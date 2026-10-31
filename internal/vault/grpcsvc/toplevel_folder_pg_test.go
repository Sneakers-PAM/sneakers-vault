// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// Real Postgres 17: a settings row saved by a build that had the retired
// "Agents may create top-level folders" field loads with that value dropped,
// so an old "on" can't read as restricted. The new setting is off, and once a
// site admin turns it on it survives a restart.
func TestRestrictTopLevelFolders_UpgradedStoreAndRestart_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	if _, err := pool.Querier().Exec(ctx, `INSERT INTO security_settings (id, data) VALUES (1, $1)`,
		[]byte(`{"defaultPasswordPolicyId":"pwpolicy-default","requireMfaForSensitiveCheckout":true,"kekRotationDays":90,"agentsMayCreateTopLevelFolders":true}`)); err != nil {
		t.Fatalf("seed old settings row: %v", err)
	}
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	s, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "qa")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	got, err := s.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSettings().GetRestrictTopLevelFolders() || !got.GetSettings().GetRequireMfaForSensitiveCheckout() {
		t.Fatalf("upgraded settings = %v, want the new field off and the others kept", got.GetSettings())
	}
	bob := tokenActor("user-bob", false)
	id := callPersisted(t, s, "CreateFolderForPrincipal", &vaultv1.CreateFolderForPrincipalRequest{Actor: bob, Name: "Agents"}, s.CreateFolderForPrincipal).GetFolder().GetId()

	on := true
	callPersisted(t, s, "UpdateSecuritySettings", &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, RestrictTopLevelFolders: &on}, s.UpdateSecuritySettings)

	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "qa")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !s2.settings.GetRestrictTopLevelFolders() {
		t.Fatal("the setting must survive a restart")
	}
	if _, err := createTopLevel(s2, bob, "More"); err == nil {
		t.Fatal("the restriction must hold after a restart")
	}
	f := s2.findFolder(id)
	if f == nil || f.GetParentId() != "" || len(f.GetOwners()) != 1 || f.GetOwners()[0] != "user-bob" {
		t.Fatalf("top-level folder after restart = %+v", f)
	}
}
