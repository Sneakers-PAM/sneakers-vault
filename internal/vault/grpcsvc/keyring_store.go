// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// keyringRow is a single KEK-keyring entry: the wrapped (root-key-encrypted)
// data-encryption key material for one KEK generation. CreatedAt lets the
// auto-rotation scheduler compute the active generation's age
// without a separate query.
type keyringRow struct {
	Ref        string
	WrappedKey []byte
	RootRef    string
	Active     bool
	CreatedAt  time.Time
}

// KeyringAdmin is the durable KEK-keyring storage seam RotateKek and
// sweepRewrap depend on, beyond BuildKeyring's boot-time keyringPersist:
// enumerating every generation (to derive the next ref and find retirement
// candidates) and retiring one once no record references it any more.
// Exported (unlike the package-private keyringPersist) so cmd/vault can name
// it as buildEnvelope's return type and Server.SetKeyring's parameter type.
// *keyringStore satisfies it; kek_rotate_test.go fakes it for DB-free tests.
type KeyringAdmin interface {
	keyringPersist
	Retire(ctx context.Context, ref string) error
}

// keyringStore is the durable store over kek_keyring: exactly one row may be
// active at a time (enforced by the partial unique index on active=true),
// giving readers a single unambiguous current KEK while retired generations
// stay around for decrypt-only use.
type keyringStore struct{ db *postgres.DB }

func newKeyringStore(db *postgres.DB) *keyringStore { return &keyringStore{db: db} }

// NewKeyringStore is the exported constructor used by cmd/vault to build the
// keyringPersist passed to BuildKeyring at boot.
func NewKeyringStore(db *postgres.DB) *keyringStore { return newKeyringStore(db) }

// Load returns every keyring row (active and retired), for enumeration/audit.
func (k *keyringStore) Load(ctx context.Context) ([]keyringRow, error) {
	rows, err := k.db.Querier().Query(ctx, `SELECT ref, wrapped_key, root_ref, active, created_at FROM kek_keyring`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyringRow
	for rows.Next() {
		var r keyringRow
		if err := rows.Scan(&r.Ref, &r.WrappedKey, &r.RootRef, &r.Active, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Active returns the single currently-active keyring row, if any. CreatedAt is
// read alongside the rest of the row so the auto-rotation scheduler can
// compute the active generation's age without a second query.
func (k *keyringStore) Active(ctx context.Context) (keyringRow, bool, error) {
	var r keyringRow
	err := k.db.Querier().QueryRow(ctx,
		`SELECT ref, wrapped_key, root_ref, active, created_at FROM kek_keyring WHERE active`,
	).Scan(&r.Ref, &r.WrappedKey, &r.RootRef, &r.Active, &r.CreatedAt)
	if errors.Is(err, postgres.ErrNoRows) {
		return keyringRow{}, false, nil
	}
	if err != nil {
		return keyringRow{}, false, err
	}
	return r, true, nil
}

// InsertActive inserts a new active keyring generation, demoting whatever was
// previously active, in one transaction so a reader never sees zero or two
// active rows (mirrors versionStore.append's single-active invariant).
func (k *keyringStore) InsertActive(ctx context.Context, ref string, wrapped []byte, rootRef string) error {
	return k.db.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		if _, err := tx.Exec(ctx, `UPDATE kek_keyring SET active=false WHERE active`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO kek_keyring (ref, wrapped_key, root_ref, active) VALUES ($1,$2,$3,true)`,
			ref, wrapped, rootRef)
		return err
	})
}

// Retire stamps retired_at on the given generation without otherwise changing
// it (it may already be inactive; retirement is just a record of when a KEK
// generation was taken fully out of use).
func (k *keyringStore) Retire(ctx context.Context, ref string) error {
	_, err := k.db.Querier().Exec(ctx, `UPDATE kek_keyring SET retired_at = now() WHERE ref = $1`, ref)
	return err
}
