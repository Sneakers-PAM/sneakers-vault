// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"fmt"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// rootMove re-wraps one working key from one root to another. It applies only
// while the row is still on FromRoot, so two replicas starting together cannot
// undo each other.
type rootMove struct {
	Ref        string
	WrappedKey []byte
	FromRoot   string
	ToRoot     string
}

// rewrapStore is the storage seam RewrapKeyring needs: every row, and an atomic
// batch of moves (all applied, or none).
type rewrapStore interface {
	Load(ctx context.Context) ([]keyringRow, error)
	MoveRoot(ctx context.Context, moves []rootMove) error
}

// RewrapKeyring moves every working key that is still on the previous root
// under the current root, then reads every working key back under the current
// root alone. It reports progress through report (state and the number of
// working keys not yet on the current root; never a key or a key name) and
// returns the final state and count.
//
//   - no previous root: none, nothing is touched.
//   - every new wrapping is checked to open under the current root before
//     anything is written, and the batch is written in one transaction, so a
//     failure leaves the stored ring exactly as it was and the vault still
//     opens it with both roots.
//   - it is idempotent: keys already on the current root are left alone, so a
//     restart, or a start with nothing left to move, changes nothing.
//   - it never deletes a working key and never touches the previous root.
func RewrapKeyring(ctx context.Context, ks rewrapStore, rk *crypto.RootKEKs, report func(crypto.RotationState, int)) (crypto.RotationState, int) {
	finish := func(st crypto.RotationState, pending int) (crypto.RotationState, int) {
		report(st, pending)
		return st, pending
	}
	if rk.Previous() == nil {
		return finish(crypto.RotationNone, 0)
	}
	rows, err := ks.Load(ctx)
	if err != nil {
		return finish(crypto.RotationFailed, 0)
	}
	var todo []keyringRow
	for _, r := range rows {
		if !rk.OnCurrent(r.RootRef) {
			todo = append(todo, r)
		}
	}
	report(crypto.RotationInProgress, len(todo))

	if len(todo) > 0 {
		moves, err := planMoves(todo, rk)
		if err == nil {
			err = ks.MoveRoot(ctx, moves)
		}
		if err != nil {
			return finish(crypto.RotationFailed, len(todo))
		}
	}

	pending, err := unreadable(ctx, ks, rk)
	if err != nil || pending > 0 {
		return finish(crypto.RotationFailed, max(pending, 1))
	}
	return finish(crypto.RotationVerified, 0)
}

// planMoves re-wraps each row under the current root and checks the result
// opens under the current root alone and yields the same key.
func planMoves(todo []keyringRow, rk *crypto.RootKEKs) ([]rootMove, error) {
	moves := make([]rootMove, 0, len(todo))
	for _, r := range todo {
		raw, err := rk.UnwrapDEK(r.WrappedKey, r.RootRef)
		if err != nil {
			return nil, fmt.Errorf("open working key %s: %w", r.Ref, err)
		}
		wrapped, ref, err := rk.WrapDEK(raw)
		if err != nil {
			clear(raw)
			return nil, fmt.Errorf("wrap working key %s: %w", r.Ref, err)
		}
		back, err := rk.Current().UnwrapDEK(wrapped, ref)
		same := err == nil && bytes.Equal(back, raw)
		clear(raw)
		clear(back)
		if !same {
			return nil, fmt.Errorf("working key %s does not read back under the current root", r.Ref)
		}
		moves = append(moves, rootMove{Ref: r.Ref, WrappedKey: wrapped, FromRoot: r.RootRef, ToRoot: ref})
	}
	return moves, nil
}

// unreadable counts the working keys that are not on the current root or do
// not open under the current root alone.
func unreadable(ctx context.Context, ks rewrapStore, rk *crypto.RootKEKs) (int, error) {
	rows, err := ks.Load(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		if !rk.OnCurrent(r.RootRef) {
			n++
			continue
		}
		raw, err := rk.Current().UnwrapDEK(r.WrappedKey, r.RootRef)
		if err != nil {
			n++
			continue
		}
		clear(raw)
	}
	return n, nil
}
