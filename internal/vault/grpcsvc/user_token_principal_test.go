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

// tokenActor is a personal-token caller. Admin flags are set on purpose: vault
// must ignore them for this principal even if a caller sends them.
func tokenActor(userID string, admin bool, groups ...string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN,
		UserId:        userID, TokenId: "utok-1", GroupNames: groups,
		IsSiteAdmin: admin, IsRoot: admin,
	}
}

func secretIn(t *testing.T, s *Server, actor *vaultv1.ActorContext, folderID, name string) string {
	t.Helper()
	resp, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: actor, Name: name, FolderId: folderID, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(%s): %v", name, err)
	}
	return resp.GetSecret().GetId()
}

func listFor(t *testing.T, s *Server, actor *vaultv1.ActorContext, folderID string) map[string]bool {
	t.Helper()
	resp, err := s.ListSecretsForPrincipal(context.Background(), &vaultv1.ListSecretsForPrincipalRequest{Actor: actor, FolderId: folderID})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	return idsOf(resp.GetSecrets())
}

func TestUserTokenGrantRevokeRegrantAppliesToTheSameToken(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	folder := newSharedFolder(t, s)
	id := secretIn(t, s, carol, folder, "router-admin")
	ada := tokenActor("user-ada", false, "g-agents")

	grantGroup(t, s, carol, folder, "C")
	if !listFor(t, s, ada, folder)[id] {
		t.Fatal("granted: the token's user should see the secret")
	}
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: folder, Owners: []string{"user-carol"},
	}); err != nil {
		t.Fatal(err)
	}
	if listFor(t, s, ada, folder)[id] {
		t.Fatal("revoked: the same token must lose access on the next call")
	}
	grantGroup(t, s, carol, folder, "C")
	if !listFor(t, s, ada, folder)[id] {
		t.Fatal("re-granted: the same token should see the secret again")
	}
}

func TestUserTokenOfAnAdminCannotReachAnotherUsersPersonalFolder(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-bob")
	bobFolder := "folder-personal-bob"
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	id := secretIn(t, s, bob, bobFolder, "bob-bank")
	// Even an explicit grant to the admin's user must not open another
	// user's personal folder through a token.
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: bob, FolderId: bobFolder, Owners: []string{"user-bob"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-admin", Grants: map[string]string{"C": "allow", "R": "allow"}}},
	}); err != nil {
		t.Fatal(err)
	}
	admin := tokenActor("user-admin", true, "g-agents")

	if listFor(t, s, admin, bobFolder)[id] || listFor(t, s, admin, "")[id] {
		t.Fatal("an admin's token listed another user's personal secret")
	}
	folders, err := s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{Actor: admin})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range folders.GetFolders() {
		if f.GetId() == bobFolder {
			t.Fatal("an admin's token can see another user's personal folder")
		}
	}
	_, err = s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
		Actor: admin, FolderId: bobFolder, TypeId: "type-password", Name: "planted", Fields: map[string]string{"password": "x"},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("create in another user's personal folder: want PermissionDenied, got %v", err)
	}
}

func TestUserTokenReachesItsOwnersPersonalFolder(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-admin")
	own := "folder-personal-admin"
	admin := tokenActor("user-admin", true)

	created, err := s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
		Actor: admin, FolderId: own, TypeId: "type-password", Name: "my-login", Fields: map[string]string{"password": "x"},
	})
	if err != nil {
		t.Fatalf("create in own personal folder: %v", err)
	}
	if !listFor(t, s, admin, own)[created.GetSecret().GetId()] {
		t.Fatal("the token's user should list their own personal secret")
	}
}

func TestUserTokenRevealsWithReadAndIsAuditedAsTheUser(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	folder := newSharedFolder(t, s)
	id := secretIn(t, s, carol, folder, "router-admin")
	grantGroup(t, s, carol, folder, "C")

	resp, err := s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: tokenActor("user-ada", false, "g-agents"), Id: id, FieldKey: "password",
	})
	if err != nil || resp.GetValue() == "" {
		t.Fatalf("reveal through a personal token with read: %v", err)
	}
	ev := ca.find("secret.reveal")
	if ev == nil || ev.ActorUserID != "user-ada" || ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_USER_TOKEN" ||
		ev.Attributes["token_id"] != "utok-1" || ev.Attributes["via"] != "mcp" {
		t.Fatalf("reveal audit = %+v, want secret.reveal by user-ada via the token", ev)
	}
	for _, v := range ev.Attributes {
		if v == resp.GetValue() {
			t.Fatal("the audit carries the value")
		}
	}
}

func TestUserTokenRevealStillNeedsReadAndNeverOpensAnotherUsersFolder(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	noRead := secretIn(t, s, carol, newSharedFolder(t, s), "no-grant")
	seedPersonalFolder(s, "user-bob")
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	bobs := secretIn(t, s, bob, "folder-personal-bob", "bob-bank")
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: bob, FolderId: "folder-personal-bob", Owners: []string{"user-bob"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-admin", Grants: map[string]string{"C": "allow"}}},
	}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		actor *vaultv1.ActorContext
		id    string
	}{
		"no RACI read":                          {tokenActor("user-ada", false, "g-agents"), noRead},
		"another user's personal folder, admin": {tokenActor("user-admin", true), bobs},
	} {
		_, err := s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: c.actor, Id: c.id, FieldKey: "password"})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, err)
		}
	}
}

func TestUserTokenCannotBreakGlass(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-bob")
	id := secretIn(t, s, &vaultv1.ActorContext{UserId: "user-bob"}, "folder-personal-bob", "bob-bank")

	_, err := s.BreakGlassSecret(context.Background(), &vaultv1.BreakGlassSecretRequest{
		Actor: tokenActor("user-admin", true), SecretId: id, Reason: "emergency",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("break-glass through a personal token: want PermissionDenied, got %v", err)
	}
}

func TestUserTokenIsAuditedAsTheUserWithTheToken(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	seedPersonalFolder(s, "user-ada")
	if _, err := s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
		Actor: tokenActor("user-ada", false), FolderId: "folder-personal-ada", TypeId: "type-password", Name: "n", Fields: map[string]string{"password": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	ev := ca.find("secret.create.principal")
	if ev == nil || ev.ActorUserID != "user-ada" || ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_USER_TOKEN" || ev.Attributes["token_id"] != "utok-1" {
		t.Fatalf("audit event = %+v", ev)
	}
}
