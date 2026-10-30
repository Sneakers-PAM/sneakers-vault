// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// Real Postgres 17: a store saved before the setting existed reads it as off,
// and once a site admin turns it on, the setting and a token's top-level
// folder both survive a restart.
func TestTopLevelFolderSetting_UpgradedStoreAndRestart_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	// The settings row as an older vault wrote it: no top-level field at all.
	if _, err := pool.Querier().Exec(ctx, `INSERT INTO security_settings (id, data) VALUES (1, $1)`,
		[]byte(`{"defaultPasswordPolicyId":"pwpolicy-default","requireMfaForSensitiveCheckout":true,"kekRotationDays":90}`)); err != nil {
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
	if got.GetSettings().GetAgentsMayCreateTopLevelFolders() || !got.GetSettings().GetRequireMfaForSensitiveCheckout() {
		t.Fatalf("upgraded settings = %v, want the new field off and the old ones kept", got.GetSettings())
	}
	if _, err := createTopLevel(s, adminTokenActor("user-ada"), "Agents"); err == nil {
		t.Fatal("an upgraded store must refuse a top-level create until the setting is turned on")
	}

	on := true
	callPersisted(t, s, "UpdateSecuritySettings", &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, AgentsMayCreateTopLevelFolders: &on}, s.UpdateSecuritySettings)
	id := callPersisted(t, s, "CreateFolderForPrincipal", &vaultv1.CreateFolderForPrincipalRequest{Actor: adminTokenActor("user-ada"), Name: "Agents"}, s.CreateFolderForPrincipal).GetFolder().GetId()

	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "qa")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !s2.settings.GetAgentsMayCreateTopLevelFolders() {
		t.Fatal("the setting must survive a restart")
	}
	f := s2.findFolder(id)
	if f == nil || f.GetParentId() != "" || len(f.GetOwners()) != 1 || f.GetOwners()[0] != "user-ada" {
		t.Fatalf("top-level folder after restart = %+v", f)
	}
}
