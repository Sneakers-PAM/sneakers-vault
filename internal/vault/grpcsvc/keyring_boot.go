// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// keyringPersist is the durable-storage seam BuildKeyring depends on. It is
// deliberately small so it can be faked in tests without a live DB;
// *keyringStore satisfies it.
type keyringPersist interface {
	Load(ctx context.Context) ([]keyringRow, error)
	Active(ctx context.Context) (keyringRow, bool, error)
	InsertActive(ctx context.Context, ref string, wrapped []byte, rootRef string) error
}

// seedKeyRef is the ref assigned to the working KEK generation seeded on
// first boot, when the keyring has no active row yet.
const seedKeyRef = "kek-v1"

// BuildKeyring assembles the KeyringKEK used at boot. It loads every
// persisted working-KEK generation and unwraps each under root — fail
// closed on any unwrap error, since the root KEK must be able to open every
// working key it wrapped. On first boot (no active row yet) it generates a
// fresh 32-byte working key, wraps it under root, and persists it as the new
// active generation via InsertActive. Each legacy key is appended as a
// recognized (but never active) working key so secrets sealed before the
// keyring existed keep unwrapping; pass none once they are retired
// (VAULT_DISABLE_DEV_STATIC_KEK).
func BuildKeyring(ctx context.Context, ks keyringPersist, root crypto.KEKProvider, rootRef string, legacy ...crypto.WorkingKey) (*crypto.KeyringKEK, error) {
	rows, err := ks.Load(ctx)
	if err != nil {
		return nil, err
	}

	working := make([]crypto.WorkingKey, 0, len(rows)+2)
	for _, row := range rows {
		raw, err := root.UnwrapDEK(row.WrappedKey, row.RootRef)
		if err != nil {
			return nil, err
		}
		working = append(working, crypto.WorkingKey{Ref: row.Ref, Key: raw})
	}

	activeRow, ok, err := ks.Active(ctx)
	if err != nil {
		return nil, err
	}

	activeRef := activeRow.Ref
	if !ok {
		seed, err := crypto.RandKey()
		if err != nil {
			return nil, err
		}
		wrapped, _, err := root.WrapDEK(seed)
		if err != nil {
			return nil, err
		}
		if err := ks.InsertActive(ctx, seedKeyRef, wrapped, rootRef); err != nil {
			return nil, err
		}
		working = append(working, crypto.WorkingKey{Ref: seedKeyRef, Key: seed})
		activeRef = seedKeyRef
	}

	working = append(working, legacy...)

	return crypto.NewKeyringKEK(root, working, activeRef)
}
