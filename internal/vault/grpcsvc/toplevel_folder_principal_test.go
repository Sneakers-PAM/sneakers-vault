// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// "Agents may create top-level folders": off by default; when on, a personal
// token whose owner is a site admin may create a folder with no parent, owned
// by that admin. Every other machine caller is refused, personal trees stay
// closed, and both the create and every change to the setting are audited.

// adminTokenActor is a personal token whose owner the gateway resolved as a
// site admin.
func adminTokenActor(userID string) *vaultv1.ActorContext {
	a := tokenActor(userID, false)
	a.TokenOwnerIsSiteAdmin = true
	return a
}

func setTopLevelFolders(t *testing.T, s *Server, on bool) {
	t.Helper()
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{
		Actor: siteAdmin, AgentsMayCreateTopLevelFolders: &on,
	}); err != nil {
		t.Fatalf("UpdateSecuritySettings: %v", err)
	}
}

func createTopLevel(s *Server, actor *vaultv1.ActorContext, name string) (*vaultv1.CreateFolderForPrincipalResponse, error) {
	return s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{Actor: actor, Name: name})
}

func TestTopLevelFolderSettingIsOffByDefault(t *testing.T) {
	for name, s := range map[string]*Server{"dev seed": newServer(t), "fresh production store": freshProdServer(t)} {
		resp, err := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
		if err != nil {
			t.Fatalf("%s: GetSecuritySettings: %v", name, err)
		}
		if resp.GetSettings().GetAgentsMayCreateTopLevelFolders() {
			t.Fatalf("%s: agents_may_create_top_level_folders must default to off", name)
		}
	}
}

func TestTopLevelFolderFromTokenRefusedWhileSettingOff(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	n := len(s.folders)
	for name, a := range map[string]*vaultv1.ActorContext{
		"admin's token":     adminTokenActor("user-ada"),
		"non-admin's token": tokenActor("user-bob", false),
	} {
		_, err := createTopLevel(s, a, "Agents")
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonTopLevelFoldersDisabled {
			t.Fatalf("%s: reason %q, want %s", name, got, ReasonTopLevelFoldersDisabled)
		}
		if msg := status.Convert(err).Message(); !containsAll(msg, "Agents may create top-level folders") {
			t.Fatalf("%s: message %q doesn't name the setting", name, msg)
		}
	}
	if len(s.folders) != n || ca.find("folder.create.principal") != nil {
		t.Fatal("a refused create must not add or audit a folder")
	}
}

func TestTopLevelFolderFromAdminTokenWhileSettingOn(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	setTopLevelFolders(t, s, true)
	ada := adminTokenActor("user-ada")

	resp, err := createTopLevel(s, ada, " Agents ")
	if err != nil {
		t.Fatalf("CreateFolderForPrincipal: %v", err)
	}
	f := s.findFolder(resp.GetFolder().GetId())
	if f == nil || f.GetName() != "Agents" || f.GetParentId() != "" {
		t.Fatalf("created folder = %+v", f)
	}
	if f.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_GROUP || f.GetGroupId() == "" ||
		len(f.GetOwners()) != 1 || f.GetOwners()[0] != "user-ada" || f.GetOwnerUserId() != "" {
		t.Fatalf("a top-level folder must be shared and owned by the token's user, as in the web: %+v", f)
	}
	if !resp.GetFolder().GetCanManage() || len(resp.GetFolder().GetOwners()) != 0 {
		t.Fatalf("response must be metadata only, with can_manage: %+v", resp.GetFolder())
	}
	// The owner's token keeps working in its new folder.
	if _, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: ada, ParentId: f.GetId(), Name: "Databases",
	}); err != nil {
		t.Fatalf("subfolder under the new top-level folder: %v", err)
	}
	ev := ca.find("folder.create.principal")
	if ev == nil || ev.ActorUserID != "user-ada" || ev.Subject != f.GetId() ||
		ev.Attributes["token_id"] != "utok-1" || ev.Attributes["path"] != "/Agents" ||
		ev.Attributes["top_level"] != "true" || ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_USER_TOKEN" {
		t.Fatalf("create audit = %+v", ev)
	}
	for _, x := range s.folders {
		if x.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && x.GetOwnerUserId() == "user-ada" {
			t.Fatal("a token's create must not provision a personal folder")
		}
	}
}

func TestTopLevelFolderRefusalsWhileSettingOn(t *testing.T) {
	cases := map[string]struct {
		actor  *vaultv1.ActorContext
		name   string
		code   codes.Code
		reason string
	}{
		"non-admin's token": {tokenActor("user-bob", false), "Agents", codes.PermissionDenied, ReasonNotSiteAdmin},
		// Admin flags on a token are never honoured; only the gateway's
		// resolution of the owner counts.
		"token with spoofed admin flags": {tokenActor("user-bob", true), "Agents", codes.PermissionDenied, ReasonNotSiteAdmin},
		"service account":                {agentGroupActor("sa-1"), "Agents", codes.InvalidArgument, ""},
		"service account with the flag": {&vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-1", TokenOwnerIsSiteAdmin: true,
		}, "Agents", codes.InvalidArgument, ""},
		"workload": {&vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-1", TokenOwnerIsSiteAdmin: true,
		}, "Agents", codes.InvalidArgument, ""},
		"human caller":           {humanAdmin, "Agents", codes.PermissionDenied, ""},
		"empty name":             {adminTokenActor("user-ada"), "  ", codes.InvalidArgument, ""},
		"duplicate top-level":    {adminTokenActor("user-ada"), "platform", codes.AlreadyExists, ""},
		"token with no owner id": {&vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, TokenId: "utok-2", TokenOwnerIsSiteAdmin: true}, "Agents", codes.PermissionDenied, ReasonNotSiteAdmin},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			setTopLevelFolders(t, s, true)
			mutFolder(t, s, "Platform")
			n := len(s.folders)
			_, err := createTopLevel(s, c.actor, c.name)
			if c.reason != "" {
				if got := reasonOf(t, err, c.code); got != c.reason {
					t.Fatalf("reason %q, want %q", got, c.reason)
				}
			} else {
				wantCode(t, err, c.code)
			}
			if len(s.folders) != n || ca.find("folder.create.principal") != nil {
				t.Fatal("a refused create must not add or audit a folder")
			}
		})
	}
}

func TestTopLevelFolderSettingNeverOpensPersonalTrees(t *testing.T) {
	for _, on := range []bool{false, true} {
		parents := map[string]func(s *Server) string{
			"another user's personal folder": func(s *Server) string {
				seedPersonalFolder(s, "user-bob")
				return "folder-personal-bob"
			},
			"master personal root": func(s *Server) string {
				s.ensureMasterPersonalFolder()
				return "folder-personal-root"
			},
		}
		for name, setup := range parents {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			setTopLevelFolders(t, s, on)
			parent := setup(s)
			injectEveryoneRule(s, parent, map[string]string{"R": "allow"})
			n := len(s.folders)
			_, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
				Actor: adminTokenActor("user-ada"), ParentId: parent, Name: "Agents",
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("setting %v, %s: err %v, want PermissionDenied", on, name, err)
			}
			if len(s.folders) != n || ca.find("folder.create.principal") != nil {
				t.Fatalf("setting %v, %s: a refused create must not add or audit a folder", on, name)
			}
		}
	}
}

func TestTopLevelFolderSettingIsSiteAdminOnlyAndAudited(t *testing.T) {
	on := true
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		"admin's token":   adminTokenActor("user-ada"),
		"service account": agentGroupActor("sa-1"),
	} {
		s := newServer(t)
		_, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: a, AgentsMayCreateTopLevelFolders: &on})
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonNotSiteAdmin {
			t.Fatalf("%s: reason %q", name, got)
		}
		if s.settings.GetAgentsMayCreateTopLevelFolders() {
			t.Fatalf("%s: a refused update must not change the setting", name)
		}
	}

	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, AgentsMayCreateTopLevelFolders: &on})
	if err != nil || !resp.GetSettings().GetAgentsMayCreateTopLevelFolders() {
		t.Fatalf("UpdateSecuritySettings: %v %v", resp, err)
	}
	got, _ := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if !got.GetSettings().GetAgentsMayCreateTopLevelFolders() {
		t.Fatal("GetSecuritySettings must read the new value back")
	}
	ev := ca.find("settings.update")
	if ev == nil || ev.ActorUserID != "user-admin" ||
		ev.Attributes["agents_may_create_top_level_folders.from"] != "false" ||
		ev.Attributes["agents_may_create_top_level_folders.to"] != "true" {
		t.Fatalf("settings audit = %+v", ev)
	}

	// A partial update of another field leaves it alone and doesn't report it.
	ca2 := &capAudit{}
	s.audit = ca2
	ttl := int32(1200)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if !s.settings.GetAgentsMayCreateTopLevelFolders() {
		t.Fatal("an update without the field must keep it")
	}
	if ev := ca2.find("settings.update"); ev == nil || ev.Attributes["agents_may_create_top_level_folders.to"] != "" {
		t.Fatalf("settings audit = %+v", ev)
	}
}
