// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
)

// kekKeyringDDL mirrors the kek_keyring table in migrations/vault/0001_baseline.up.sql (idempotent).
const kekKeyringDDL = `
CREATE TABLE IF NOT EXISTS kek_keyring (
    ref         TEXT PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    root_ref    TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS kek_keyring_one_active ON kek_keyring (active) WHERE active;
`

func keyringTestPool(t *testing.T) *postgres.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	p, err := postgres.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err := p.Querier().Exec(context.Background(), kekKeyringDDL); err != nil {
		t.Fatalf("bootstrap kek_keyring: %v", err)
	}
	_, _ = p.Querier().Exec(context.Background(), "TRUNCATE kek_keyring")
	return p
}

func TestKeyringStoreInsertActiveLoadRetire(t *testing.T) {
	ctx := context.Background()
	k := newKeyringStore(keyringTestPool(t))

	// Seed kek-v1 as active directly (simulating an existing generation).
	if _, err := k.db.Querier().Exec(ctx,
		`INSERT INTO kek_keyring (ref, wrapped_key, root_ref, active) VALUES ($1,$2,$3,true)`,
		"kek-v1", []byte("wrapped-v1"), "root-1"); err != nil {
		t.Fatalf("seed kek-v1: %v", err)
	}

	// InsertActive for kek-v2 must demote kek-v1 and become the sole active row.
	if err := k.InsertActive(ctx, "kek-v2", []byte("wrapped-v2"), "root-1"); err != nil {
		t.Fatalf("InsertActive: %v", err)
	}

	active, ok, err := k.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if !ok {
		t.Fatal("Active: expected ok=true")
	}
	if active.Ref != "kek-v2" {
		t.Fatalf("Active.Ref = %q, want kek-v2", active.Ref)
	}
	if string(active.WrappedKey) != "wrapped-v2" {
		t.Fatalf("Active.WrappedKey = %q, want wrapped-v2", active.WrappedKey)
	}
	if active.RootRef != "root-1" {
		t.Fatalf("Active.RootRef = %q, want root-1", active.RootRef)
	}
	if !active.Active {
		t.Fatal("Active.Active = false, want true")
	}
	if active.CreatedAt.IsZero() {
		t.Fatal("Active.CreatedAt = zero, want the row's created_at")
	}

	rows, err := k.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("Load: got %d rows, want 2", len(rows))
	}
	var activeCount int
	byRef := map[string]keyringRow{}
	for _, r := range rows {
		byRef[r.Ref] = r
		if r.Active {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("Load: %d active rows, want exactly 1", activeCount)
	}
	if _, ok := byRef["kek-v1"]; !ok {
		t.Fatal("Load: missing kek-v1")
	}
	if _, ok := byRef["kek-v2"]; !ok {
		t.Fatal("Load: missing kek-v2")
	}
	if byRef["kek-v1"].Active {
		t.Fatal("kek-v1 should have been demoted by InsertActive")
	}
	if !byRef["kek-v2"].Active {
		t.Fatal("kek-v2 should be active")
	}

	// Retire kek-v1: sets retired_at, leaves active untouched (already false).
	if err := k.Retire(ctx, "kek-v1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	var retiredAtSet, stillInactive bool
	if err := k.db.Querier().QueryRow(ctx,
		`SELECT retired_at IS NOT NULL, NOT active FROM kek_keyring WHERE ref='kek-v1'`,
	).Scan(&retiredAtSet, &stillInactive); err != nil {
		t.Fatal(err)
	}
	if !retiredAtSet {
		t.Fatal("Retire: retired_at not set")
	}
	if !stillInactive {
		t.Fatal("Retire: kek-v1 unexpectedly became active")
	}

	// kek-v2 remains the active row after kek-v1 was retired.
	active2, ok, err := k.Active(ctx)
	if err != nil || !ok || active2.Ref != "kek-v2" {
		t.Fatalf("Active after Retire: %v %v %v", active2, ok, err)
	}
}

func TestKeyringStoreActiveNoRows(t *testing.T) {
	ctx := context.Background()
	k := newKeyringStore(keyringTestPool(t))
	_, ok, err := k.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if ok {
		t.Fatal("Active: expected ok=false with no rows")
	}
}
