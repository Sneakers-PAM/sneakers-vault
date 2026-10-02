// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// agentGroupActor returns a service-account principal in group g-agents, the
// shape used throughout these tests for a non-human caller whose access comes
// entirely from a group-keyed RACI grant (never an admin flag).
func agentGroupActor(id string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   id,
		GroupNames:    []string{"g-agents"},
	}
}

// grantGroup sets a folder's ruleset so group g-agents holds exactly the given
// RACI grant (e.g. "C" for read, "R" for author), with carol retained as owner.
func grantGroup(t *testing.T, s *Server, carol *vaultv1.ActorContext, folderID, action string) {
	t.Helper()
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: folderID, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents",
			Grants: map[string]string{action: "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(%s, %s): %v", folderID, action, err)
	}
}

// idsOf collects the ids of a Secret slice for membership assertions.
func idsOf(secrets []*vaultv1.Secret) map[string]bool {
	out := make(map[string]bool, len(secrets))
	for _, sec := range secrets {
		out[sec.GetId()] = true
	}
	return out
}

// --- ListSecretsForPrincipal -------------------------------------

// TestListSecretsForPrincipalRACIFiltered proves the list is filtered to
// exactly the secrets the principal may READ (RACI C via a group grant),
// never anything from a folder it has no grant on, and returns metadata only.
func TestListSecretsForPrincipalRACIFiltered(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	fOK := newSharedFolder(t, s)
	grantGroup(t, s, carol, fOK, "C")

	fNo, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "No Access"})
	if err != nil {
		t.Fatalf("CreateFolder(fNo): %v", err)
	}
	fNoID := fNo.GetFolder().GetId()

	c1, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s1", FolderId: fOK, TypeId: "type-password",
		Fields: map[string]string{"username": "u1", "password": "p1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(s1): %v", err)
	}
	s1 := c1.GetSecret().GetId()

	c2, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s2", FolderId: fNoID, TypeId: "type-password",
		Fields: map[string]string{"username": "u2", "password": "p2"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(s2): %v", err)
	}
	s2 := c2.GetSecret().GetId()

	agentActor := agentGroupActor("sa-1")
	resp, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{Actor: agentActor})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	ids := idsOf(resp.GetSecrets())
	if !ids[s1] {
		t.Fatalf("expected readable secret %s in list, got %v", s1, ids)
	}
	if ids[s2] {
		t.Fatalf("secret %s from an ungranted folder must not appear, got %v", s2, ids)
	}

	ev := ca.find("secret.list.principal")
	if ev == nil {
		t.Fatal("expected a secret.list.principal audit event")
	}
	if ev.Sensitive {
		t.Fatal("secret.list.principal must be audited sensitive=false (metadata only)")
	}
	if ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" {
		t.Fatalf("audit principal_kind = %q, want PRINCIPAL_KIND_SERVICE_ACCOUNT", ev.Attributes["principal_kind"])
	}
	if ev.Attributes["principal_id"] != "sa-1" {
		t.Fatalf("audit principal_id = %q, want sa-1", ev.Attributes["principal_id"])
	}
}

// TestListSecretsForPrincipalRejectsHuman proves a HUMAN-kind actor is
// rejected, mirroring revealForPrincipal's defense-in-depth restriction.
func TestListSecretsForPrincipalRejectsHuman(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	_, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{
		Actor: &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN, UserId: "u1"},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("ListSecretsForPrincipal(human): want PermissionDenied, got %v", err)
	}
}

// --- CreateSecretForPrincipal -------------------------------------

// TestCreateSecretForPrincipalRequiresAuthor proves create is gated on RACI
// Author (R) — the same grant human CreateSecret requires — not merely Read:
// a folder granting the principal's group only C (read) must deny create,
// while a folder granting R (author) must allow it and the created secret
// round-trips through RevealSecretFieldForPrincipal (author implies read).
func TestCreateSecretForPrincipalRequiresAuthor(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	fOK := newSharedFolder(t, s)
	grantGroup(t, s, carol, fOK, "R")

	fRO, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "Read Only"})
	if err != nil {
		t.Fatalf("CreateFolder(fRO): %v", err)
	}
	fROID := fRO.GetFolder().GetId()
	grantGroup(t, s, carol, fROID, "C")

	agentActor := agentGroupActor("sa-1")

	if _, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: agentActor, FolderId: fROID, TypeId: "type-password", Name: "svc-a",
		Fields: map[string]string{"username": "svc-a", "password": "p"},
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("read-only folder must deny create, got %v", err)
	}

	resp, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: agentActor, FolderId: fOK, TypeId: "type-password", Name: "svc-a",
		Fields: map[string]string{"username": "svc-a", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sid := resp.GetSecret().GetId()
	if sid == "" {
		t.Fatal("expected created secret id")
	}
	if resp.GetSecret().GetFolderId() != fOK {
		t.Fatalf("created secret folder = %q, want %q", resp.GetSecret().GetFolderId(), fOK)
	}

	// Stored + sealed: reveal-for-principal proves the round-trip (the same
	// Author grant implies Read per the authz package's Resolve).
	rev, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: agentActor, Id: sid, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal(created secret): %v", err)
	}
	if rev.GetValue() != "Sup3r$ecret" {
		t.Fatalf("revealed %q, want Sup3r$ecret", rev.GetValue())
	}

	ev := ca.find("secret.create.principal")
	if ev == nil {
		t.Fatal("expected a secret.create.principal audit event")
	}
	if !ev.Sensitive {
		t.Fatal("secret.create.principal must be audited sensitive=true")
	}
	if ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" {
		t.Fatalf("audit principal_kind = %q, want PRINCIPAL_KIND_SERVICE_ACCOUNT", ev.Attributes["principal_kind"])
	}
	if ev.Attributes["principal_id"] != "sa-1" {
		t.Fatalf("audit principal_id = %q, want sa-1", ev.Attributes["principal_id"])
	}
	for _, v := range ev.Attributes {
		if v == "Sup3r$ecret" {
			t.Fatal("audit attributes must never carry the secret value")
		}
	}
}

// TestCreateSecretForPrincipalRejectsHuman proves a HUMAN-kind actor is
// rejected even if it would otherwise satisfy RACI-author.
func TestCreateSecretForPrincipalRejectsHuman(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // owner of a folder it creates below => author
	fOK := newSharedFolder(t, s)
	_, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: carol, FolderId: fOK, TypeId: "type-password", Name: "svc-a",
		Fields: map[string]string{"username": "svc-a", "password": "p"},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("CreateSecretForPrincipal(human): want PermissionDenied, got %v", err)
	}
}

// --- GenerateSecretForPrincipal -----------------------------------

// TestGenerateSecretForPrincipalStoresGeneratedPassword proves generate stores
// a policy-compliant, non-empty password in the type's password field, and
// returns it once (return_value=true) — the value returned matches what was
// stored, proven via a reveal round-trip, and the extra
// secret.generate.value_returned.principal audit fires.
func TestGenerateSecretForPrincipalStoresGeneratedPassword(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fOK := newSharedFolder(t, s)
	grantGroup(t, s, carol, fOK, "R")
	agentActor := agentGroupActor("sa-1")

	resp, err := s.GenerateSecretForPrincipal(ctx, &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: agentActor, FolderId: fOK, TypeId: "type-active-directory", Name: "svc-sql",
		Fields: map[string]string{"domain": "CORP", "username": "svc-sql"}, ReturnValue: true,
	})
	if err != nil {
		t.Fatalf("GenerateSecretForPrincipal: %v", err)
	}
	if resp.GetGeneratedValue() == "" {
		t.Fatal("return_value=true should return the generated password")
	}
	sid := resp.GetSecret().GetId()
	if sid == "" {
		t.Fatal("expected created secret id")
	}

	rev, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: agentActor, Id: sid, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal(generated secret): %v", err)
	}
	if rev.GetValue() != resp.GetGeneratedValue() {
		t.Fatalf("stored password %q does not match returned generated value %q", rev.GetValue(), resp.GetGeneratedValue())
	}

	ev := ca.find("secret.generate.value_returned.principal")
	if ev == nil {
		t.Fatal("expected a secret.generate.value_returned.principal audit event")
	}
	if !ev.Sensitive {
		t.Fatal("secret.generate.value_returned.principal must be audited sensitive=true")
	}
	for _, v := range ev.Attributes {
		if v == resp.GetGeneratedValue() {
			t.Fatal("audit attributes must never carry the generated value")
		}
	}
	if ca.find("secret.create.principal") == nil {
		t.Fatal("expected the shared secret.create.principal audit event too")
	}
}

// TestGenerateSecretForPrincipalNoReturnByDefault proves return_value omitted
// (false) means the response carries no generated value, even though the
// secret is still created with a non-empty password field.
func TestGenerateSecretForPrincipalNoReturnByDefault(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fOK := newSharedFolder(t, s)
	grantGroup(t, s, carol, fOK, "R")
	agentActor := agentGroupActor("sa-1")

	resp, err := s.GenerateSecretForPrincipal(ctx, &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: agentActor, FolderId: fOK, TypeId: "type-active-directory", Name: "svc-sql",
		Fields: map[string]string{"domain": "CORP", "username": "svc-sql"},
	})
	if err != nil {
		t.Fatalf("GenerateSecretForPrincipal: %v", err)
	}
	if resp.GetGeneratedValue() != "" {
		t.Fatal("return_value omitted must not return the generated password")
	}
	sid := resp.GetSecret().GetId()

	rev, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: agentActor, Id: sid, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal(generated secret): %v", err)
	}
	if rev.GetValue() == "" {
		t.Fatal("secret must still be created with a non-empty generated password field")
	}
	if ca.find("secret.generate.value_returned.principal") != nil {
		t.Fatal("value_returned audit must NOT fire when return_value is false")
	}
}

// TestGenerateSecretForPrincipalRequiresAuthor proves generate is gated on
// RACI Author (R), same as create: a read-only (C) grant must deny.
func TestGenerateSecretForPrincipalRequiresAuthor(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fRO, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "Read Only"})
	if err != nil {
		t.Fatalf("CreateFolder(fRO): %v", err)
	}
	fROID := fRO.GetFolder().GetId()
	grantGroup(t, s, carol, fROID, "C")
	agentActor := agentGroupActor("sa-1")

	_, err = s.GenerateSecretForPrincipal(ctx, &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: agentActor, FolderId: fROID, TypeId: "type-active-directory", Name: "svc-sql",
		Fields: map[string]string{"domain": "CORP", "username": "svc-sql"},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("read-only folder must deny generate, got %v", err)
	}
}

// TestGenerateSecretForPrincipalRejectsHuman proves a HUMAN-kind actor is
// rejected even if it would otherwise satisfy RACI-author.
func TestGenerateSecretForPrincipalRejectsHuman(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fOK := newSharedFolder(t, s)
	_, err := s.GenerateSecretForPrincipal(ctx, &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: carol, FolderId: fOK, TypeId: "type-active-directory", Name: "svc-sql",
		Fields: map[string]string{"domain": "CORP", "username": "svc-sql"},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("GenerateSecretForPrincipal(human): want PermissionDenied, got %v", err)
	}
}

// --- Anti-escalation regression --------------------------------------------

// TestPrincipalHandlersIgnoreSpoofedAdminFlags proves a machine principal
// carrying spoofed admin flags (is_site_admin + is_root) with NO RACI grant
// on the target folder gains nothing from either principal handler: evalOf
// (server.go) strips those flags for any non-HUMAN principal, so canManage
// (CreateSecretForPrincipal) and canRead (ListSecretsForPrincipal) resolve
// purely off RACI/Target grants, never a spoofed flag. Mirrors
// reveal_principal_test.go's TestRevealSecretFieldForPrincipalSpoofedAdminDenied
// but anchors the principal create/list surface too.
func TestPrincipalHandlersIgnoreSpoofedAdminFlags(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s1", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "u1", "password": "p1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	spoofed := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   "sa-spoofed-admin", IsSiteAdmin: true, IsRoot: true,
	}

	if _, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: spoofed, FolderId: fid, TypeId: "type-password", Name: "svc-a",
		Fields: map[string]string{"username": "svc-a", "password": "p"},
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("spoofed admin with no grant must be denied create, got %v", err)
	}

	resp, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{Actor: spoofed})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	if ids := idsOf(resp.GetSecrets()); ids[sid] {
		t.Fatalf("spoofed admin with no read grant must not see secret %s, got %v", sid, ids)
	}
	if n := len(resp.GetSecrets()); n != 0 {
		t.Fatalf("spoofed admin with no grants anywhere must see zero secrets, got %d", n)
	}
}
