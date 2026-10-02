// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const repoMigrations = "../../migrations/vault"

// freshDB creates an isolated, empty database on the TEST_DATABASE_DSN server
// and returns its DSN (dropped on cleanup). Skips when TEST_DATABASE_DSN is
// unset, like the grpcsvc Postgres-backed tests.
func freshDB(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_DSN")
	if base == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "boot_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// migrateTo applies the repo migrations whose version is <= upto to the
// database at dsn.
// headMigration is the highest migration number in the repo.
func headMigration(t *testing.T) int64 {
	t.Helper()
	entries, err := os.ReadDir(repoMigrations)
	if err != nil {
		t.Fatal(err)
	}
	head := int64(0)
	for _, e := range entries {
		if n, err := strconv.ParseInt(e.Name()[:4], 10, 64); err == nil && n > head {
			head = n
		}
	}
	return head
}

func migrateTo(t *testing.T, dsn, upto string) {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(repoMigrations)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name()[:4] > upto {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(repoMigrations, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := postgres.Migrate(dsn, dir); err != nil {
		t.Fatalf("migrate to %s: %v", upto, err)
	}
}

func schemaVersion(t *testing.T, dsn string) (int64, bool) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	var v int64
	var dirty bool
	if err := c.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&v, &dirty); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	return v, dirty
}

func randKEK(t *testing.T) string {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// With a correct KEK, preflight migrates to head and the keyring then builds
// (seeding kek-v1); a second boot with the same KEK passes the unwrap check.
func TestMigrateAfterPreflight_CorrectKEK_MigratesAndBoots(t *testing.T) {
	dsn := freshDB(t)
	migrateTo(t, dsn, "0002")
	t.Setenv("VAULT_ROOT_KEK", randKEK(t))
	ctx := context.Background()

	root, rootRef, err := migrateAfterPreflight(ctx, dsn, repoMigrations, "qa")
	if err != nil {
		t.Fatalf("migrateAfterPreflight: %v", err)
	}
	if rootRef != "root-v1" {
		t.Fatalf("rootRef = %q, want root-v1", rootRef)
	}
	if v, dirty := schemaVersion(t, dsn); v != headMigration(t) || dirty {
		t.Fatalf("schema version = %d dirty=%v, want %d clean", v, dirty, headMigration(t))
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, kr, _, err := buildEnvelope(ctx, pool, root, rootRef, true)
	if err != nil {
		t.Fatalf("buildEnvelope: %v", err)
	}
	if kr.ActiveRef() != "kek-v1" {
		t.Fatalf("active ref = %q, want kek-v1", kr.ActiveRef())
	}

	// Re-boot with the same KEK: preflight now unwrap-checks kek-v1 and passes.
	if _, _, err := migrateAfterPreflight(ctx, dsn, repoMigrations, "qa"); err != nil {
		t.Fatalf("second boot with same KEK: %v", err)
	}
}

// Dev keeps its zero-setup path: no VAULT_ROOT_KEK on a fresh database boots.
func TestMigrateAfterPreflight_DevFallback_FreshDB(t *testing.T) {
	dsn := freshDB(t)
	t.Setenv("VAULT_ROOT_KEK", "")
	_, rootRef, err := migrateAfterPreflight(context.Background(), dsn, repoMigrations, "dev")
	if err != nil {
		t.Fatalf("dev boot: %v", err)
	}
	if rootRef != "dev-root-v1" {
		t.Fatalf("rootRef = %q, want dev-root-v1", rootRef)
	}
}

// devStaticRecord seals fields with the static dev key: under
// sha256("sneakers-pam-dev-kek-seed-v1"), stamped KeyRef dev-static-v1.
func devStaticRecord(t *testing.T, fields map[string]string) (crypto.Record, []byte) {
	t.Helper()
	k := sha256.Sum256([]byte("sneakers-pam-dev-kek-seed-v1"))
	kek, err := crypto.NewStaticKEK(k[:])
	if err != nil {
		t.Fatal(err)
	}
	rec, err := crypto.New(kek).Seal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyRef != grpcsvc.DevStaticKeyRef {
		t.Fatalf("seed KeyRef = %q, want %s", rec.KeyRef, grpcsvc.DevStaticKeyRef)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, raw
}

type storedRow struct {
	table, id string
	version   int
	password  string
}

// readAll opens the password field of every secret_records / secret_versions
// row straight from Postgres with env, failing on any unreadable row.
func readAll(t *testing.T, pool *pgxpool.Pool, env *crypto.Envelope, want []storedRow) {
	t.Helper()
	ctx := context.Background()
	for _, w := range want {
		var raw []byte
		var err error
		if w.table == "secret_records" {
			err = pool.QueryRow(ctx, `SELECT record FROM secret_records WHERE secret_id=$1`, w.id).Scan(&raw)
		} else {
			err = pool.QueryRow(ctx, `SELECT record FROM secret_versions WHERE secret_id=$1 AND version_no=$2`, w.id, w.version).Scan(&raw)
		}
		if err != nil {
			t.Fatalf("load %s %s/%d: %v", w.table, w.id, w.version, err)
		}
		var rec crypto.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		got, err := env.Open(rec, "password")
		if err != nil {
			t.Fatalf("open %s %s/%d (ref %s): %v", w.table, w.id, w.version, rec.KeyRef, err)
		}
		if got != w.password {
			t.Fatalf("%s %s/%d password = %q, want %q", w.table, w.id, w.version, got, w.password)
		}
	}
}

// End-to-end retirement of dev-static-v1 on real Postgres: rows sealed with the static dev key
// (records + versions under dev-static) -> boot (report shows them) ->
// disable-flag boot refused -> RotateKek -> no dev-static rows left ->
// disable-flag boot passes and every row still reads -> one leftover row ->
// disable-flag boot refused again.
func TestDevStaticRetirement_EndToEnd(t *testing.T) {
	dsn := freshDB(t)
	ctx := context.Background()
	t.Setenv("VAULT_ROOT_KEK", randKEK(t))
	root, rootRef, err := migrateAfterPreflight(ctx, dsn, repoMigrations, "qa")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// A non-empty store (pgStore treats no types/folders/settings as a fresh
	// install and persists an empty snapshot over it).
	if _, err := pool.Exec(ctx, `INSERT INTO security_settings (id, data) VALUES (1, '{}')`); err != nil {
		t.Fatal(err)
	}
	var want []storedRow
	var leftover []byte
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("secret-%d", i)
		cur := fmt.Sprintf("pw-%d-v2", i)
		_, rawCur := devStaticRecord(t, map[string]string{"username": "svc", "password": cur})
		if _, err := pool.Exec(ctx, `INSERT INTO secret_records (secret_id, record) VALUES ($1,$2)`, id, rawCur); err != nil {
			t.Fatal(err)
		}
		want = append(want, storedRow{"secret_records", id, 0, cur})
		for v := 1; v <= 2; v++ {
			pw := fmt.Sprintf("pw-%d-v%d", i, v)
			_, raw := devStaticRecord(t, map[string]string{"username": "svc", "password": pw})
			if i == 0 && v == 1 {
				leftover = raw
			}
			if _, err := pool.Exec(ctx,
				`INSERT INTO secret_versions (secret_id, version_no, record, active) VALUES ($1,$2,$3,$4)`,
				id, v, raw, v == 2); err != nil {
				t.Fatal(err)
			}
			want = append(want, storedRow{"secret_versions", id, v, pw})
		}
	}

	// Normal boot: dev-static still loaded, report counts every row, reads work.
	kb, err := bootKeyring(ctx, pool, root, rootRef, false)
	if err != nil {
		t.Fatalf("bootKeyring: %v", err)
	}
	if got := kb.report.Count(grpcsvc.DevStaticKeyRef); got != 9 {
		t.Fatalf("dev-static rows = %d (%s), want 9", got, kb.report)
	}
	if len(kb.unreadable) != 0 {
		t.Fatalf("unreadable refs = %v", kb.unreadable)
	}
	readAll(t, pool, kb.envelope, want)

	// Disable flag before the sweep: refused, nothing changes.
	if _, err := bootKeyring(ctx, pool, root, rootRef, true); err == nil ||
		!strings.Contains(err.Error(), "9 stored rows still reference dev-static-v1") {
		t.Fatalf("disable-flag boot before sweep: err = %v, want refusal naming 9 rows", err)
	}

	// Rotate (human site-admin) — re-wraps records AND versions.
	srv, err := grpcsvc.NewWithStore(ctx, grpcsvc.NewPGStore(pool), kb.envelope, nil, "qa")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetKeyring(kb.keyring, kb.store, root, rootRef)
	srv.SetRotation(pool, nil)
	machine := &vaultv1.ActorContext{UserId: "svc-bot", IsSiteAdmin: true, PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT}
	if _, err := srv.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: machine}); err == nil {
		t.Fatal("machine principal with IsSiteAdmin must not rotate the KEK")
	}
	resp, err := srv.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}})
	if err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	if resp.GetRewrapped() != 9 || resp.GetActiveRef() != "kek-v2" {
		t.Fatalf("RotateKek = %v, want 9 rewrapped onto kek-v2", resp)
	}
	readAll(t, pool, kb.envelope, want) // reads work mid-procedure

	report, err := grpcsvc.KeyRefCounts(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if report.Count(grpcsvc.DevStaticKeyRef) != 0 || report.Count("kek-v2") != 9 {
		t.Fatalf("after rotate: %s, want all 9 on kek-v2", report)
	}

	// Disable-flag boot passes; the keyring no longer holds dev-static-v1 and
	// every row still reads under it.
	kb2, err := bootKeyring(ctx, pool, root, rootRef, true)
	if err != nil {
		t.Fatalf("disable-flag boot after sweep: %v", err)
	}
	if kb2.keyring.Has(grpcsvc.DevStaticKeyRef) {
		t.Fatal("dev-static-v1 still loaded with VAULT_DISABLE_DEV_STATIC_KEK=true")
	}
	readAll(t, pool, kb2.envelope, want)

	// One leftover row (e.g. restored from an old backup) -> refused.
	if _, err := pool.Exec(ctx, `UPDATE secret_versions SET record=$1 WHERE secret_id='secret-0' AND version_no=1`, leftover); err != nil {
		t.Fatal(err)
	}
	_, err = bootKeyring(ctx, pool, root, rootRef, true)
	if err == nil || !strings.Contains(err.Error(), "1 stored rows still reference dev-static-v1 (secret_versions=1)") {
		t.Fatalf("disable-flag boot with one leftover: err = %v, want refusal naming secret_versions=1", err)
	}
	// Without the flag it still boots and the leftover still reads.
	kb3, err := bootKeyring(ctx, pool, root, rootRef, false)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, pool, kb3.envelope, want)
}

func TestDevStaticDisabled_Parse(t *testing.T) {
	for v, want := range map[string]bool{"": false, "true": true, "1": true, "false": false} {
		t.Setenv("VAULT_DISABLE_DEV_STATIC_KEK", v)
		got, err := devStaticDisabled()
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v; want %v", v, got, err, want)
		}
	}
	t.Setenv("VAULT_DISABLE_DEV_STATIC_KEK", "yes please")
	if _, err := devStaticDisabled(); err == nil {
		t.Fatal("unparseable value must be an error")
	}
}

func TestKekRotationPrincipals_Boot(t *testing.T) {
	t.Setenv(grpcsvc.KekRotationPrincipalsEnv, "")
	if ids, err := kekRotationPrincipals(); err != nil || len(ids) != 0 {
		t.Fatalf("unset: got %v, %v; want disabled", ids, err)
	}
	t.Setenv(grpcsvc.KekRotationPrincipalsEnv, "system:kek-rotation")
	if ids, err := kekRotationPrincipals(); err != nil || len(ids) != 1 || ids[0] != "system:kek-rotation" {
		t.Fatalf("valid: got %v, %v", ids, err)
	}
	for _, bad := range []string{"user-carol", "system:kek-rotation,sa-1", "system:"} {
		t.Setenv(grpcsvc.KekRotationPrincipalsEnv, bad)
		if _, err := kekRotationPrincipals(); err == nil {
			t.Fatalf("%q: bad entry must be a boot error", bad)
		}
	}
}
