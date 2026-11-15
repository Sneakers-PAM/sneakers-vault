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

// "Restrict top-level folders to admins": off by default, so any signed-in
// person or personal token may create a top-level folder and owns it. On, only
// site admins and root may, in the web or through a token whose owner is one.
// Service accounts and workloads are refused either way, personal trees stay
// closed, and both the create and every change to the setting are audited.

// adminTokenActor is a personal token whose owner the gateway resolved as a
// site admin.
func adminTokenActor(userID string) *vaultv1.ActorContext {
	a := tokenActor(userID, false)
	a.TokenOwnerIsSiteAdmin = true
	return a
}

func setRestrictTopLevel(t *testing.T, s *Server, on bool) {
	t.Helper()
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{
		Actor: siteAdmin, RestrictTopLevelFolders: &on,
	}); err != nil {
		t.Fatalf("UpdateSecuritySettings: %v", err)
	}
}

func createTopLevel(s *Server, actor *vaultv1.ActorContext, name string) (*vaultv1.CreateFolderForPrincipalResponse, error) {
	return s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{Actor: actor, Name: name})
}

func createTopLevelAsPerson(s *Server, actor *vaultv1.ActorContext, name string) (*vaultv1.CreateFolderResponse, error) {
	return s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: actor, Name: name})
}

func wantSharedFolderOwnedBy(t *testing.T, s *Server, id, name, owner string) {
	t.Helper()
	f := s.findFolder(id)
	if f == nil || f.GetName() != name || f.GetParentId() != "" {
		t.Fatalf("created folder = %+v", f)
	}
	if f.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_GROUP || f.GetGroupId() == "" ||
		len(f.GetOwners()) != 1 || f.GetOwners()[0] != owner || f.GetOwnerUserId() != "" {
		t.Fatalf("a top-level folder must be shared and owned by %s: %+v", owner, f)
	}
}

func TestRestrictTopLevelFoldersIsOffByDefault(t *testing.T) {
	for name, s := range map[string]*Server{"dev seed": newServer(t), "fresh production store": freshProdServer(t)} {
		resp, err := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
		if err != nil {
			t.Fatalf("%s: GetSecuritySettings: %v", name, err)
		}
		if resp.GetSettings().GetRestrictTopLevelFolders() {
			t.Fatalf("%s: restrict_top_level_folders must default to off", name)
		}
	}
}

func TestTopLevelFolderFromAnyPersonByDefault(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		"site admin":      {UserId: "user-ada", IsSiteAdmin: true},
		"root":            {UserId: "user-ada", IsRoot: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			resp, err := createTopLevelAsPerson(s, a, "Team")
			if err != nil {
				t.Fatalf("CreateFolder: %v", err)
			}
			wantSharedFolderOwnedBy(t, s, resp.GetFolder().GetId(), "Team", a.GetUserId())
			if ev := ca.find("folder.create"); ev == nil || ev.ActorUserID != a.GetUserId() || ev.Subject != resp.GetFolder().GetId() {
				t.Fatalf("create audit = %+v", ev)
			}
		})
	}
}

func TestTopLevelFolderFromAnyTokenByDefault(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"non-admin's token": tokenActor("user-bob", false),
		"admin's token":     adminTokenActor("user-bob"),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			resp, err := createTopLevel(s, a, " Agents ")
			if err != nil {
				t.Fatalf("CreateFolderForPrincipal: %v", err)
			}
			id := resp.GetFolder().GetId()
			wantSharedFolderOwnedBy(t, s, id, "Agents", "user-bob")
			if !resp.GetFolder().GetCanManage() || len(resp.GetFolder().GetOwners()) != 0 {
				t.Fatalf("response must be metadata only, with can_manage: %+v", resp.GetFolder())
			}
			// The token keeps working in its new folder.
			if _, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
				Actor: a, ParentId: id, Name: "Databases",
			}); err != nil {
				t.Fatalf("subfolder under the new top-level folder: %v", err)
			}
			ev := ca.find("folder.create.principal")
			if ev == nil || ev.ActorUserID != "user-bob" || ev.Subject != id ||
				ev.Attributes["token_id"] != "utok-1" || ev.Attributes["path"] != "/Agents" ||
				ev.Attributes["top_level"] != "true" || ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_USER_TOKEN" {
				t.Fatalf("create audit = %+v", ev)
			}
			for _, x := range s.folders {
				if x.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && x.GetOwnerUserId() == "user-bob" {
					t.Fatal("a token's create must not provision a personal folder")
				}
			}
		})
	}
}

func TestTopLevelFolderAllowedWhileRestricted(t *testing.T) {
	people := map[string]*vaultv1.ActorContext{
		"site admin": {UserId: "user-ada", IsSiteAdmin: true},
		"root":       {UserId: "user-ada", IsRoot: true},
	}
	for name, a := range people {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			setRestrictTopLevel(t, s, true)
			resp, err := createTopLevelAsPerson(s, a, "Team")
			if err != nil {
				t.Fatalf("CreateFolder: %v", err)
			}
			wantSharedFolderOwnedBy(t, s, resp.GetFolder().GetId(), "Team", "user-ada")
		})
	}
	t.Run("admin's token", func(t *testing.T) {
		s := newServer(t)
		setRestrictTopLevel(t, s, true)
		resp, err := createTopLevel(s, adminTokenActor("user-ada"), "Agents")
		if err != nil {
			t.Fatalf("CreateFolderForPrincipal: %v", err)
		}
		wantSharedFolderOwnedBy(t, s, resp.GetFolder().GetId(), "Agents", "user-ada")
	})
}

// wantRestricted asserts a refusal with the setting's reason, a message that
// names the setting, an authz.denied audit, and nothing added: no folder, and
// no personal folder provisioned on the way.
func wantRestricted(t *testing.T, s *Server, ca *capAudit, err error, folders int) {
	t.Helper()
	if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonTopLevelFoldersRestricted {
		t.Fatalf("reason %q, want %s", got, ReasonTopLevelFoldersRestricted)
	}
	if msg := status.Convert(err).Message(); !containsAll(msg, "Restrict top-level folders to admins") {
		t.Fatalf("message %q doesn't name the setting", msg)
	}
	if ev := ca.find("authz.denied"); ev == nil || ev.Attributes["reason"] != ReasonTopLevelFoldersRestricted {
		t.Fatalf("denial audit = %+v", ev)
	}
	if len(s.folders) != folders || ca.find("folder.create") != nil || ca.find("folder.create.principal") != nil {
		t.Fatal("a refused create must not add or audit a folder")
	}
}

func TestTopLevelFolderRefusedToPeopleWhileRestricted(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		// The token flag means nothing on a human actor.
		"person carrying the token flag": {UserId: "user-bob", TokenOwnerIsSiteAdmin: true},
		// No real user behind the actor, so its admin flags don't count.
		"system actor with admin flags": {UserId: "system", IsSiteAdmin: true, IsRoot: true},
		"empty actor with admin flags":  {IsSiteAdmin: true, IsRoot: true},
		"token on the person's RPC":     tokenActor("user-bob", true),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			setRestrictTopLevel(t, s, true)
			ca := &capAudit{}
			s.audit = ca
			n := len(s.folders)
			_, err := createTopLevelAsPerson(s, a, "Team")
			wantRestricted(t, s, ca, err, n)
		})
	}
}

func TestTopLevelFolderRefusedToTokensWhileRestricted(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"non-admin's token": tokenActor("user-bob", false),
		// Admin flags on a token are never honoured; only the gateway's
		// resolution of the owner counts.
		"token with spoofed admin flags": tokenActor("user-bob", true),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			setRestrictTopLevel(t, s, true)
			ca := &capAudit{}
			s.audit = ca
			n := len(s.folders)
			_, err := createTopLevel(s, a, "Agents")
			wantRestricted(t, s, ca, err, n)
		})
	}
}

// Nothing can own a folder a machine creates, so it's refused in both states
// and on both RPCs, whatever flags it carries.
func TestTopLevelFolderRefusedToMachines(t *testing.T) {
	for _, on := range []bool{false, true} {
		for name, a := range map[string]*vaultv1.ActorContext{
			"service account": agentGroupActor("sa-1"),
			"service account with the flag": {
				PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-1", TokenOwnerIsSiteAdmin: true,
			},
			"workload": {
				PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-1", TokenOwnerIsSiteAdmin: true,
			},
			"token with no owner id": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, TokenId: "utok-2", TokenOwnerIsSiteAdmin: true},
		} {
			s := newServer(t)
			setRestrictTopLevel(t, s, on)
			n := len(s.folders)
			_, err := createTopLevel(s, a, "Agents")
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("restrict %v, %s: principal RPC err %v, want InvalidArgument", on, name, err)
			}
			_, err = createTopLevelAsPerson(s, a, "Agents")
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("restrict %v, %s: person RPC err %v, want InvalidArgument", on, name, err)
			}
			if len(s.folders) != n {
				t.Fatalf("restrict %v, %s: a refused create must not add a folder", on, name)
			}
		}
	}
}

func TestTopLevelFolderFromTokenChecksTheName(t *testing.T) {
	cases := map[string]struct {
		name string
		code codes.Code
	}{
		"empty name":          {"  ", codes.InvalidArgument},
		"duplicate top-level": {"platform", codes.AlreadyExists},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			mutFolder(t, s, "Platform")
			n := len(s.folders)
			_, err := createTopLevel(s, tokenActor("user-bob", false), c.name)
			wantCode(t, err, c.code)
			if len(s.folders) != n || ca.find("folder.create.principal") != nil {
				t.Fatal("a refused create must not add or audit a folder")
			}
		})
	}
}

func TestPrincipalTopLevelFolderRefusesAPerson(t *testing.T) {
	s := newServer(t)
	_, err := createTopLevel(s, humanAdmin, "Agents")
	wantCode(t, err, codes.PermissionDenied)
}

// The setting is about the top level only: an owner keeps working inside a
// folder they already have.
func TestRestrictingTopLevelFoldersLeavesSubfoldersAlone(t *testing.T) {
	s := newServer(t)
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	resp, err := createTopLevelAsPerson(s, bob, "Team")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	setRestrictTopLevel(t, s, true)
	if _, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: bob, ParentId: resp.GetFolder().GetId(), Name: "web"}); err != nil {
		t.Fatalf("person's subfolder: %v", err)
	}
	if _, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: tokenActor("user-bob", false), ParentId: resp.GetFolder().GetId(), Name: "db",
	}); err != nil {
		t.Fatalf("token's subfolder: %v", err)
	}
}

// A non-admin's folder, made in the web or through a token: its owner sees and
// manages it and can share it; its name is listed to every person, and its
// contents stay closed to everyone else until shared.
func TestNonAdminTopLevelFolderIsManagedAndShared(t *testing.T) {
	ctx := context.Background()
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	dave := &vaultv1.ActorContext{UserId: "user-dave"}
	makers := map[string]func(s *Server) string{
		"web": func(s *Server) string {
			resp, err := createTopLevelAsPerson(s, bob, "Team")
			if err != nil {
				t.Fatal(err)
			}
			return resp.GetFolder().GetId()
		},
		"token": func(s *Server) string {
			resp, err := createTopLevel(s, tokenActor("user-bob", false), "Team")
			if err != nil {
				t.Fatal(err)
			}
			return resp.GetFolder().GetId()
		},
	}
	for name, make := range makers {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			id := make(s)

			listed, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: bob})
			if err != nil {
				t.Fatal(err)
			}
			var mine *vaultv1.Folder
			for _, f := range listed.GetFolders() {
				if f.GetId() == id {
					mine = f
				}
			}
			if mine == nil || !mine.GetCanManage() {
				t.Fatalf("the creator must see and manage the folder: %+v", mine)
			}
			access, err := s.GetMyAccess(ctx, &vaultv1.GetMyAccessRequest{Actor: bob, FolderId: id})
			if err != nil {
				t.Fatal(err)
			}
			if a := access.GetAccess(); !a.GetRead() || !a.GetManage() || !a.GetManageRuleset() {
				t.Fatalf("creator's access = %+v", a)
			}

			// Listed to another person by name, with nothing else open.
			others, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: dave})
			if err != nil {
				t.Fatal(err)
			}
			var seen *vaultv1.Folder
			for _, f := range others.GetFolders() {
				if f.GetId() == id {
					seen = f
				}
			}
			if seen == nil || seen.GetCanManage() {
				t.Fatalf("another person's view = %+v", seen)
			}
			if s.resolve(dave, id).Read.Allowed {
				t.Fatal("another person must not read the folder before it's shared")
			}
			theirs, err := s.ListFoldersForPrincipal(ctx, &vaultv1.ListFoldersForPrincipalRequest{Actor: tokenActor("user-dave", false)})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range theirs.GetFolders() {
				if f.GetId() == id {
					t.Fatal("another user's token must not list the folder before it's shared")
				}
			}

			// A non-admin owner shares with a named user, but can't open it to everyone.
			if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
				Actor: bob, FolderId: id, Owners: []string{"user-bob"},
				Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: map[string]string{"C": "allow"}}},
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("everyone rule from a non-admin: %v, want PermissionDenied", err)
			}
			if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
				Actor: bob, FolderId: id, Owners: []string{"user-bob"},
				Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-dave", Grants: map[string]string{"C": "allow"}}},
			}); err != nil {
				t.Fatalf("SetFolderRuleset: %v", err)
			}
			if !s.resolve(dave, id).Read.Allowed {
				t.Fatal("a named share must open the folder to that person")
			}

			// A token can't edit sharing, its owner's or anyone's: that stays in the web.
			if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
				Actor: tokenActor("user-bob", false), FolderId: id, Owners: []string{"user-bob"},
			}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("SetFolderRuleset from a token: %v, want PermissionDenied", err)
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
			setRestrictTopLevel(t, s, on)
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

func TestRestrictTopLevelFoldersIsSiteAdminOnlyAndAudited(t *testing.T) {
	on := true
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		"admin's token":   adminTokenActor("user-ada"),
		"service account": agentGroupActor("sa-1"),
	} {
		s := newServer(t)
		_, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: a, RestrictTopLevelFolders: &on})
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonNotSiteAdmin {
			t.Fatalf("%s: reason %q", name, got)
		}
		if s.settings.GetRestrictTopLevelFolders() {
			t.Fatalf("%s: a refused update must not change the setting", name)
		}
	}

	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, RestrictTopLevelFolders: &on})
	if err != nil || !resp.GetSettings().GetRestrictTopLevelFolders() {
		t.Fatalf("UpdateSecuritySettings: %v %v", resp, err)
	}
	got, _ := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if !got.GetSettings().GetRestrictTopLevelFolders() {
		t.Fatal("GetSecuritySettings must read the new value back")
	}
	ev := ca.find("settings.update")
	if ev == nil || ev.ActorUserID != "user-admin" ||
		ev.Attributes["restrict_top_level_folders.from"] != "false" ||
		ev.Attributes["restrict_top_level_folders.to"] != "true" {
		t.Fatalf("settings audit = %+v", ev)
	}

	// A partial update of another field leaves it alone and doesn't report it.
	ca2 := &capAudit{}
	s.audit = ca2
	ttl := int32(1200)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if !s.settings.GetRestrictTopLevelFolders() {
		t.Fatal("an update without the field must keep it")
	}
	if ev := ca2.find("settings.update"); ev == nil || ev.Attributes["restrict_top_level_folders.to"] != "" {
		t.Fatalf("settings audit = %+v", ev)
	}
}
