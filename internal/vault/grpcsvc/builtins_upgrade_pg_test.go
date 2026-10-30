// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/protobuf/proto"
)

// bootProd starts a production vault on pool, the way cmd/vault does.
func bootProd(t *testing.T, pool *postgres.DB, env *crypto.Envelope) *Server {
	t.Helper()
	s, err := NewWithStore(context.Background(), NewPGStore(pool), env, nil, "production")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	return s
}

func execSQL(t *testing.T, pool *postgres.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := pool.Querier().Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func builtinType(t *testing.T, id string) *vaultv1.SecretType {
	t.Helper()
	for _, ty := range BuiltinTypes() {
		if ty.GetId() == id {
			return ty
		}
	}
	t.Fatalf("no built-in type %s", id)
	return nil
}

// An install set up on v0.1.0-rc.3 and upgraded: its store has no GitHub App
// type, is missing an extension pack the new release ships, and holds
// built-ins the admin changed or deleted. Starting the new release adds what
// is missing and leaves every existing record exactly as it was.
func TestUpgradeBootAddsNewBuiltinsAndKeepsExistingRecords_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)

	// First-run /setup on the old release.
	setup := bootProd(t, pool, env)
	admin := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true, IsSiteAdmin: true}
	callPersisted(t, setup, "SeedBuiltins", &vaultv1.SeedBuiltinsRequest{Actor: admin}, setup.SeedBuiltins)

	// Shape the store as rc.3 left it, after the admin's own changes.
	execSQL(t, pool,
		`DELETE FROM secret_types WHERE id='type-github-app'`,
		`DELETE FROM extension_catalog WHERE id='ext-aws-iam-key'`,
		`UPDATE secret_types SET data = jsonb_set(data, '{name}', '"Password (older catalogue)"') WHERE id='type-password'`,
		`UPDATE connections SET data = jsonb_set(jsonb_set(data, '{port}', '2222'), '{name}', '"Jump host SSH"') WHERE id='conn-ssh-default'`,
		`DELETE FROM connections WHERE id='conn-ldaps'`,
		`UPDATE password_policies SET data = jsonb_set(data, '{minLength}', '16') WHERE id='pwpolicy-default'`,
		`DELETE FROM password_policies WHERE id='pwpolicy-privileged'`,
		`DELETE FROM builtin_ledger`,
	)
	before, _, err := NewPGStore(pool).Load(ctx)
	if err != nil {
		t.Fatalf("load rc.3 store: %v", err)
	}

	// Start the new release on that store.
	up := bootProd(t, pool, env)

	got, _, err := NewPGStore(pool).Load(ctx)
	if err != nil {
		t.Fatalf("load after boot: %v", err)
	}
	if ty := findByID(got.types, "type-github-app"); ty == nil {
		t.Fatal("type-github-app was not added on start-up")
	} else if !proto.Equal(ty, builtinType(t, "type-github-app")) {
		t.Fatalf("type-github-app = %v, want the shipped built-in", ty)
	}
	if findByID(got.extCatalog, "ext-aws-iam-key") == nil {
		t.Fatal("extension pack ext-aws-iam-key was not added on start-up")
	}
	if up.findType("type-github-app") == nil {
		t.Fatal("the running vault does not serve type-github-app")
	}
	if added, want := up.BootAddedBuiltins(), []string{"type:type-github-app", "extension:ext-aws-iam-key"}; !slices.Equal(added, want) {
		t.Errorf("BootAddedBuiltins = %v, want %v", added, want)
	}

	// Everything that was already there is untouched.
	for _, old := range before.types {
		if now := findByID(got.types, old.GetId()); !proto.Equal(old, now) {
			t.Errorf("type %s changed: %v -> %v", old.GetId(), old, now)
		}
	}
	for _, old := range before.connections {
		if now := findByID(got.connections, old.GetId()); !proto.Equal(old, now) {
			t.Errorf("connection %s changed: %v -> %v", old.GetId(), old, now)
		}
	}
	for _, old := range before.policies {
		if now := findByID(got.policies, old.GetId()); !proto.Equal(old, now) {
			t.Errorf("policy %s changed: %v -> %v", old.GetId(), old, now)
		}
	}
	for _, old := range before.folders {
		if now := findByID(got.folders, old.GetId()); !proto.Equal(old, now) {
			t.Errorf("folder %s changed: %v -> %v", old.GetId(), old, now)
		}
	}
	if len(got.folders) != len(before.folders) {
		t.Errorf("folders = %d, want %d: start-up must not create folders", len(got.folders), len(before.folders))
	}
	if !proto.Equal(before.settings, got.settings) {
		t.Errorf("settings changed: %v -> %v", before.settings, got.settings)
	}
	if findByID(got.connections, "conn-ldaps") != nil {
		t.Error("conn-ldaps, deleted by the admin, was put back")
	}
	if findByID(got.policies, "pwpolicy-privileged") != nil {
		t.Error("pwpolicy-privileged, deleted by the admin, was put back")
	}

	// A built-in the admin deletes after the upgrade stays deleted on the
	// next start too.
	callPersisted(t, up, "DeleteConnection", &vaultv1.DeleteConnectionRequest{Actor: admin, Id: "conn-winrm-default"}, up.DeleteConnection)
	again := bootProd(t, pool, env)
	if findByID(again.connections, "conn-winrm-default") != nil {
		t.Error("conn-winrm-default, deleted after the upgrade, was put back on the next start")
	}
	if again.findType("type-github-app") == nil {
		t.Error("type-github-app is gone after a second start")
	}
	if added := again.BootAddedBuiltins(); len(added) != 0 {
		t.Errorf("a second start added %v, want nothing", added)
	}
}

// A production store that has not been through /setup stays empty on start:
// /setup's SeedBuiltins installs the baseline, never the boot.
func TestBootBeforeSetupLeavesProductionStoreEmpty_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	bootProd(t, pool, env)
	s := bootProd(t, pool, env)
	if len(s.types) != 0 || len(s.connections) != 0 || len(s.extCatalog) != 0 || len(s.policies) != 0 || len(s.folders) != 0 {
		t.Fatalf("pre-setup store grew: %d types, %d connections, %d packs, %d policies, %d folders",
			len(s.types), len(s.connections), len(s.extCatalog), len(s.policies), len(s.folders))
	}
	st, empty, err := NewPGStore(pool).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !empty || len(st.types) != 0 {
		t.Fatalf("pre-setup store persisted built-ins (empty=%v, types=%d)", empty, len(st.types))
	}
}
