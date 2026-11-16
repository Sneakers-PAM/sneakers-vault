// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
)

// keyringRoots reads root_ref per working key, and the wrapped bytes, from the database.
func keyringRoots(t *testing.T, pool *postgres.DB) (map[string]string, map[string][]byte) {
	t.Helper()
	rows, err := pool.Querier().Query(context.Background(), `SELECT ref, root_ref, wrapped_key FROM kek_keyring`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	roots, wrapped := map[string]string{}, map[string][]byte{}
	for rows.Next() {
		var ref, root string
		var w []byte
		if err := rows.Scan(&ref, &root, &w); err != nil {
			t.Fatal(err)
		}
		roots[ref], wrapped[ref] = root, w
	}
	return roots, wrapped
}

func bootWith(t *testing.T, dsn, current, previous string) (*crypto.RootKEKs, string, error) {
	t.Helper()
	t.Setenv("VAULT_ROOT_KEK", current)
	t.Setenv("VAULT_ROOT_KEK_PREVIOUS", previous)
	return migrateAfterPreflight(context.Background(), dsn, repoMigrations, "qa")
}

func TestRootKeyReplacement_EndToEnd(t *testing.T) {
	dsn := freshDB(t)
	ctx := context.Background()
	oldKey, newKey := randKEK(t), randKEK(t)

	// A first start under the old root seeds the keyring on root-v1.
	root, rootRef, err := bootWith(t, dsn, oldKey, "")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	env, kr, _, err := buildEnvelope(ctx, pool, root, rootRef, true)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := env.Seal(map[string]string{"password": "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := keyringRoots(t, pool)
	if before["kek-v1"] != "root-v1" {
		t.Fatalf("seeded on %q, want root-v1", before["kek-v1"])
	}
	_ = kr

	// A wrong previous key stops the start before anything is re-wrapped.
	if _, _, err := bootWith(t, dsn, randKEK(t), randKEK(t)); err == nil {
		t.Fatal("a wrong previous key started")
	} else if !strings.Contains(err.Error(), "VAULT_ROOT_KEK_PREVIOUS") {
		t.Fatalf("the error should name VAULT_ROOT_KEK_PREVIOUS, not the current key: %v", err)
	} else if strings.Contains(err.Error(), oldKey) || strings.Contains(err.Error(), newKey) {
		t.Fatalf("the error shows a key: %v", err)
	}
	if after, _ := keyringRoots(t, pool); after["kek-v1"] != "root-v1" {
		t.Fatal("the ring changed although the start was refused")
	}

	// The new root with the old one as previous: re-wrapped and verified.
	root2, ref2, err := bootWith(t, dsn, newKey, oldKey)
	if err != nil {
		t.Fatalf("start with both roots: %v", err)
	}
	var states []crypto.RotationState
	st, pending := grpcsvc.RewrapKeyring(ctx, grpcsvc.NewKeyringStore(pool), root2, func(s crypto.RotationState, _ int) { states = append(states, s) })
	if st != crypto.RotationVerified || pending != 0 {
		t.Fatalf("state=%s pending=%d, want verified, 0", st, pending)
	}
	roots, wrapped := keyringRoots(t, pool)
	if roots["kek-v1"] != ref2 || ref2 == "root-v1" {
		t.Fatalf("kek-v1 on %q, want the new root's own ref %q", roots["kek-v1"], ref2)
	}
	// Secret data was not re-encrypted: the stored record still opens.
	env2, _, _, err := buildEnvelope(ctx, pool, root2, ref2, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := env2.Open(rec, "password"); err != nil || got != "hunter2" {
		t.Fatalf("a stored secret no longer opens after the root changed: %v", err)
	}

	// A restart with both keys changes nothing a second time.
	root3, _, err := bootWith(t, dsn, newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := grpcsvc.RewrapKeyring(ctx, grpcsvc.NewKeyringStore(pool), root3, func(crypto.RotationState, int) {}); st != crypto.RotationVerified {
		t.Fatalf("restart: %s, want verified", st)
	}
	if _, w2 := keyringRoots(t, pool); !bytes.Equal(w2["kek-v1"], wrapped["kek-v1"]) {
		t.Fatal("a restart with every key already on the current root wrote again")
	}

	// The operator drops the previous key: the new root alone opens everything.
	root4, ref4, err := bootWith(t, dsn, newKey, "")
	if err != nil {
		t.Fatalf("start with the new root alone: %v", err)
	}
	env4, _, _, err := buildEnvelope(ctx, pool, root4, ref4, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := env4.Open(rec, "password"); err != nil || got != "hunter2" {
		t.Fatalf("after dropping the previous key: %v", err)
	}
	// And the old root alone no longer opens the ring.
	if _, _, err := bootWith(t, dsn, oldKey, ""); err == nil {
		t.Fatal("the old root alone still starts after the move")
	}
}

func TestInitialRootKeyStatus_InProgressWhileAPreviousKeyIsSet(t *testing.T) {
	st, n := initialRootKeyStatus(envMap(map[string]string{"VAULT_ROOT_KEK_PREVIOUS": b64Key(1)})).Get()
	if st != crypto.RotationInProgress || n != 0 {
		t.Fatalf("%s %d: with a previous key set the status must read in-progress from the first moment, not none", st, n)
	}
	st, n = initialRootKeyStatus(envMap(nil)).Get()
	if st != crypto.RotationNone || n != 0 {
		t.Fatalf("%s %d, want none", st, n)
	}
}
