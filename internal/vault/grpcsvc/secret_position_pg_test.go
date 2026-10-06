// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"reflect"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// Real Postgres 17: the 0003 migration backfills positions by name for
// secrets stored before positions existed, and ReorderSecrets survives a
// restart.
func TestSecretPositions_BackfillAndPersist_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	store := NewPGStore(pool)
	s, err := NewWithStore(ctx, store, env, nil, "dev")
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	f := callPersisted(t, s, "CreateFolder", &vaultv1.CreateFolderRequest{Actor: posCarol, Name: "Ops"}, s.CreateFolder).GetFolder().GetId()
	ids := map[string]string{}
	for _, name := range []string{"charlie", "Alpha", "bravo", "retired"} {
		ids[name] = callPersisted(t, s, "CreateSecret", &vaultv1.CreateSecretRequest{
			Actor: posCarol, Name: name, FolderId: f, TypeId: "type-password",
			Fields: map[string]string{"username": "u", "password": "Str0ng!Passw0rd-1"},
		}, s.CreateSecret).GetSecret().GetId()
	}
	callPersisted(t, s, "RetireSecret", &vaultv1.RetireSecretRequest{Actor: posCarol, Id: ids["retired"]}, s.RetireSecret)

	// Put the rows back to how a release before positions stored them, then
	// run the migration's SQL.
	if _, err := pool.Querier().Exec(ctx, `UPDATE secrets SET data = data - 'position'`); err != nil {
		t.Fatal(err)
	}
	up, err := os.ReadFile("../../../migrations/vault/0003_secret_positions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Querier().Exec(ctx, string(up)); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	s2, err := NewWithStore(ctx, store, env, nil, "dev")
	if err != nil {
		t.Fatalf("boot after backfill: %v", err)
	}
	wantOrder(t, s2, f, "Alpha", "bravo", "charlie")
	if p := s2.findSecret(ids["retired"]).GetPosition(); p != 0 {
		t.Fatalf("retired secret backfilled to %d, want 0", p)
	}

	callPersisted(t, s2, "ReorderSecrets", &vaultv1.ReorderSecretsRequest{
		Actor: posCarol, FolderId: f, OrderedIds: []string{ids["charlie"], ids["Alpha"], ids["bravo"]},
	}, s2.ReorderSecrets)
	s3, err := NewWithStore(ctx, store, env, nil, "dev")
	if err != nil {
		t.Fatalf("boot after reorder: %v", err)
	}
	if got := listOrder(t, s3, f); !reflect.DeepEqual(got, []string{"charlie", "Alpha", "bravo"}) {
		t.Fatalf("order after restart = %v", got)
	}
}
