// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// reconcileKeyring refreshes this replica's in-memory KEK keyring from the
// durable kek_keyring table. reload's hydrate already swaps in
// the latest s.records — including any rewrapped by a peer's RotateKek, now
// referencing a working-KEK generation this replica's keyring never learned
// about — but hydrate never touches s.keyring itself. Without this, every
// reveal on this replica fails ("no working KEK for ref ...") until it
// restarts and rebuilds its keyring via BuildKeyring. reconcileKeyring closes
// that gap: for every persisted generation this keyring doesn't already have,
// unwrap it under the shared root (fail-closed — mirrors BuildKeyring's
// boot-time rule that the root must be able to open every working key it
// wrapped) and add it, then point the active ref at whatever the DB reports
// active.
//
// No-op (nil error) when the keyring isn't wired at all — the no-Postgres/
// demo path and any Server that never called SetKeyring.
func (s *Server) reconcileKeyring(ctx context.Context) error {
	if s.keyring == nil || s.keyringStore == nil || s.root == nil {
		return nil
	}

	rows, err := s.keyringStore.Load(ctx)
	if err != nil {
		return fmt.Errorf("reconcile keyring: load: %w", err)
	}

	var activeRow keyringRow
	var haveActive bool
	for _, row := range rows {
		if row.Active {
			activeRow, haveActive = row, true
		}
		if s.keyring.Has(row.Ref) {
			continue
		}
		raw, err := s.root.UnwrapDEK(row.WrappedKey, row.RootRef)
		if err != nil {
			return fmt.Errorf("reconcile keyring: unwrap %s: %w", row.Ref, err)
		}
		s.keyring.Add(crypto.WorkingKey{Ref: row.Ref, Key: raw}, false)
	}

	if haveActive && activeRow.Ref != s.keyring.ActiveRef() {
		if err := s.keyring.SetActive(activeRow.Ref); err != nil {
			return fmt.Errorf("reconcile keyring: set active %s: %w", activeRow.Ref, err)
		}
	}
	return nil
}
