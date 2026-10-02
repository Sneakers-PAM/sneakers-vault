// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

func TestPGUseStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	ctx := context.Background()
	pool, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, q := range []string{`TRUNCATE secret_uses`, `TRUNCATE secret_use_grants`} {
		if _, err := pool.Querier().Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	st := &pgUseStore{db: pool.Querier()}
	use := &vaultv1.SecretUse{Id: "use-1", UserId: "u-ada", TokenId: "utok-1", Argv: []string{"ssh", "h"},
		State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, ExpiresAtUnix: 4102444800}
	if err := st.PutUse(ctx, use); err != nil {
		t.Fatal(err)
	}
	pending, err := st.PendingUses(ctx, "u-ada")
	if err != nil || len(pending) != 1 || pending[0].GetTokenId() != "utok-1" {
		t.Fatalf("PendingUses = %v, %v", pending, err)
	}
	use.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
	if err := st.PutUse(ctx, use); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetUse(ctx, "use-1"); err != nil || got.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("GetUse = %v, %v", got, err)
	}
	if p, _ := st.PendingUses(ctx, "u-ada"); len(p) != 0 {
		t.Fatalf("an approved use is still pending: %v", p)
	}
	g := &vaultv1.UseGrant{Id: "g-1", UserId: "u-ada", TokenId: "utok-1", Uses: 1}
	if err := st.PutGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	if grants, err := st.GrantsFor(ctx, "u-ada"); err != nil || len(grants) != 1 || grants[0].GetUses() != 1 {
		t.Fatalf("GrantsFor = %v, %v", grants, err)
	}
	if _, err := st.GetUse(ctx, "missing"); err != errUseNotFound {
		t.Fatalf("missing use: want errUseNotFound, got %v", err)
	}
}
