// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/jackc/pgx/v5/pgxpool"
)

// secretVersionsDDL mirrors the secret_versions table in
// migrations/vault/0001_baseline.up.sql (idempotent), applied directly so
// this test runs standalone against any Postgres at TEST_DATABASE_DSN.
const secretVersionsDDL = `
CREATE TABLE IF NOT EXISTS secret_versions (
  secret_id   TEXT        NOT NULL,
  version_no  INT         NOT NULL,
  record      JSONB       NOT NULL,
  active      BOOLEAN     NOT NULL DEFAULT false,
  staged      BOOLEAN     NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by  TEXT        NOT NULL DEFAULT '',
  PRIMARY KEY (secret_id, version_no)
);
CREATE INDEX IF NOT EXISTS secret_versions_active ON secret_versions (secret_id) WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS secret_versions_one_staged ON secret_versions (secret_id) WHERE staged;
`

func verTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err := p.Exec(context.Background(), secretVersionsDDL); err != nil {
		t.Fatalf("bootstrap secret_versions: %v", err)
	}
	_, _ = p.Exec(context.Background(), "TRUNCATE secret_versions")
	return p
}

func sealTest(t *testing.T, fields map[string]string) (crypto.Record, *crypto.Envelope) {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	env := crypto.New(kek)
	rec, err := env.Seal(fields)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return rec, env
}

func rowState(t *testing.T, p *pgxpool.Pool, secretID string, versionNo int) (active, staged bool) {
	t.Helper()
	err := p.QueryRow(context.Background(),
		`SELECT active, staged FROM secret_versions WHERE secret_id=$1 AND version_no=$2`,
		secretID, versionNo).Scan(&active, &staged)
	if err != nil {
		t.Fatalf("rowState v%d: %v", versionNo, err)
	}
	return active, staged
}

func TestVersionStoreAppendActiveDemotesPrior(t *testing.T) {
	ctx := context.Background()
	v := newVersionStore(verTestPool(t))
	rec1, _ := sealTest(t, map[string]string{"password": "one"})
	rec2, _ := sealTest(t, map[string]string{"password": "two"})

	n1, err := v.AppendActive(ctx, "sec-1", rec1, "u")
	if err != nil || n1 != 1 {
		t.Fatalf("AppendActive#1: n=%d err=%v", n1, err)
	}
	n2, err := v.AppendActive(ctx, "sec-1", rec2, "u")
	if err != nil || n2 != 2 {
		t.Fatalf("AppendActive#2: n=%d err=%v", n2, err)
	}
	if a, _ := rowState(t, v.db, "sec-1", 1); a {
		t.Fatal("v1 should be demoted (active=false)")
	}
	if a, _ := rowState(t, v.db, "sec-1", 2); !a {
		t.Fatal("v2 should be active")
	}
}

func TestVersionStoreStageCommit(t *testing.T) {
	ctx := context.Background()
	v := newVersionStore(verTestPool(t))
	rec1, env := sealTest(t, map[string]string{"password": "old"})
	if _, err := v.AppendActive(ctx, "sec-1", rec1, "u"); err != nil {
		t.Fatal(err)
	}
	// Stage v2 from the same envelope so the round-tripped record still opens.
	rec2, err := env.Seal(map[string]string{"password": "new"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := v.Stage(ctx, "sec-1", rec2, "connector:w1")
	if err != nil || n != 2 {
		t.Fatalf("Stage: n=%d err=%v", n, err)
	}
	if a, st := rowState(t, v.db, "sec-1", 2); a || !st {
		t.Fatalf("v2 should be staged not active, got active=%v staged=%v", a, st)
	}
	if a, _ := rowState(t, v.db, "sec-1", 1); !a {
		t.Fatal("v1 should still be active while v2 staged")
	}

	if err := v.Commit(ctx, "sec-1", 2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if a, st := rowState(t, v.db, "sec-1", 2); !a || st {
		t.Fatalf("after commit v2 active not staged, got active=%v staged=%v", a, st)
	}
	if a, _ := rowState(t, v.db, "sec-1", 1); a {
		t.Fatal("v1 should be inactive after commit")
	}

	// ActiveRecord returns v2 and its password decrypts to "new".
	got, ok, err := v.ActiveRecord(ctx, "sec-1")
	if err != nil || !ok {
		t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
	}
	pw, err := env.Open(got, "password")
	if err != nil {
		t.Fatalf("decrypt active record: %v", err)
	}
	if pw != "new" {
		t.Fatalf("active password = %q, want new", pw)
	}
}

func TestVersionStoreCommitIdempotent(t *testing.T) {
	ctx := context.Background()
	v := newVersionStore(verTestPool(t))
	rec1, env := sealTest(t, map[string]string{"password": "old"})
	if _, err := v.AppendActive(ctx, "sec-1", rec1, "u"); err != nil {
		t.Fatal(err)
	}
	rec2, _ := env.Seal(map[string]string{"password": "new"})
	if _, err := v.Stage(ctx, "sec-1", rec2, "u"); err != nil {
		t.Fatal(err)
	}
	if err := v.Commit(ctx, "sec-1", 2); err != nil {
		t.Fatal(err)
	}
	if err := v.Commit(ctx, "sec-1", 2); err != nil {
		t.Fatalf("second Commit should be idempotent: %v", err)
	}
	if a, _ := rowState(t, v.db, "sec-1", 2); !a {
		t.Fatal("v2 still active after idempotent re-commit")
	}
}

func TestVersionStoreDiscardStaged(t *testing.T) {
	ctx := context.Background()
	v := newVersionStore(verTestPool(t))
	rec1, env := sealTest(t, map[string]string{"password": "old"})
	if _, err := v.AppendActive(ctx, "sec-1", rec1, "u"); err != nil {
		t.Fatal(err)
	}
	rec2, _ := env.Seal(map[string]string{"password": "new"})
	if _, err := v.Stage(ctx, "sec-1", rec2, "u"); err != nil {
		t.Fatal(err)
	}
	if err := v.DiscardStaged(ctx, "sec-1"); err != nil {
		t.Fatalf("DiscardStaged: %v", err)
	}
	var staged int
	if err := v.db.QueryRow(ctx, `SELECT count(*) FROM secret_versions WHERE secret_id='sec-1' AND staged`).Scan(&staged); err != nil {
		t.Fatal(err)
	}
	if staged != 0 {
		t.Fatalf("staged rows remain: %d", staged)
	}
	if a, _ := rowState(t, v.db, "sec-1", 1); !a {
		t.Fatal("v1 should still be active after discarding staged")
	}
}

// TestChangedFieldKeysDiff proves the per-version change detection without a DB:
// versions are diffed by hashing decrypted values, so identical values report no
// change, a changed value reports only that key, and added/removed keys count as
// changed — all while never exposing a value.
func TestChangedFieldKeysDiff(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	env := crypto.New(kek)
	seal := func(fields map[string]string) map[string]string {
		rec, err := env.Seal(fields)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		fp, err := fieldFingerprints(env, rec)
		if err != nil {
			t.Fatalf("fingerprints: %v", err)
		}
		return fp
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	v1 := seal(map[string]string{"username": "svc", "password": "old"})
	v2 := seal(map[string]string{"username": "svc", "password": "new"}) // only password changed
	v3 := seal(map[string]string{"username": "svc", "password": "new"}) // identical re-save
	v4 := seal(map[string]string{"username": "svc"})                    // password removed
	v5 := seal(map[string]string{"username": "svc", "note": "hi"})      // note added

	// Oldest version: no prior => all keys.
	if got := changedFieldKeys(v1, nil); !eq(got, []string{"password", "username"}) {
		t.Fatalf("v1 changed = %v, want [password username]", got)
	}
	if got := changedFieldKeys(v2, v1); !eq(got, []string{"password"}) {
		t.Fatalf("v2 changed = %v, want [password]", got)
	}
	if got := changedFieldKeys(v3, v2); len(got) != 0 {
		t.Fatalf("v3 (identical re-save) changed = %v, want none", got)
	}
	if got := changedFieldKeys(v4, v3); !eq(got, []string{"password"}) {
		t.Fatalf("v4 (removed password) changed = %v, want [password]", got)
	}
	if got := changedFieldKeys(v5, v4); !eq(got, []string{"note"}) {
		t.Fatalf("v5 (added note) changed = %v, want [note]", got)
	}
}

func TestVersionStoreActiveRecordAbsent(t *testing.T) {
	ctx := context.Background()
	v := newVersionStore(verTestPool(t))
	_, ok, err := v.ActiveRecord(ctx, "nope")
	if err != nil {
		t.Fatalf("ActiveRecord(absent): %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a secret with no versions")
	}
}
