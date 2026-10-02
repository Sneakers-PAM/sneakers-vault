// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Anti-escalation regression suite for machine principals carrying spoofed
// admin flags. The invariant (see isHumanAdmin, server.go) is that
// is_site_admin/is_root are gateway-resolved from a HUMAN identity's roles and
// must never be honoured on a non-human ActorContext. It was first enforced for
// target-ruleset edits (isTargetOwner) but eleven other admin-authority checks
// — isFolderOwner among them — still read the raw flags, so a service-account
// or workload principal that presented is_site_admin=true could rewrite a
// folder's RACI ruleset, grant ITSELF read, and reveal every secret under it.
//
// These tests pin the whole class shut. They deliberately exercise the
// grant-GRANTING surfaces (folder/secret ruleset + owners) because those are
// the ones that convert a spoofed flag into secret plaintext.
package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// spoofedAdminMachine is a service-account principal presenting BOTH admin
// flags and holding no RACI grant anywhere — the exact shape a compromised or
// buggy machine caller would send.
func spoofedAdminMachine(id string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   id, IsSiteAdmin: true, IsRoot: true,
	}
}

// TestSpoofedAdminMachineCannotEscalateToPlaintext is the end-to-end proof.
// Without the human-only isFolderOwner check, every step below would succeed:
// the machine would rewrite the folder ruleset to grant itself RACI-C and then
// read the human-authored secret's password in cleartext.
func TestSpoofedAdminMachineCannotEscalateToPlaintext(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "human-only", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "u1", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	spoofed := spoofedAdminMachine("sa-spoofed")

	// Step 1 — the self-grant must be refused.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: spoofed, FolderId: fid, Owners: []string{"sa-spoofed"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-spoofed",
			Grants: map[string]string{"C": "allow"},
		}},
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("spoofed-admin machine must not edit a folder ruleset: want PermissionDenied, got %v", err)
	}

	// Step 2 — the principal discovery surface must not list it either.
	listed, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{Actor: spoofed})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	if n := len(listed.GetSecrets()); n != 0 {
		t.Fatalf("spoofed-admin machine with no grant must enumerate zero secrets, got %d", n)
	}

	// Step 3 — and the secret must remain unreadable to it.
	resp, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: spoofed, Id: sid, FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("spoofed-admin machine reveal: want PermissionDenied, got %v", err)
	}
	if v := resp.GetValue(); v != "" {
		t.Fatalf("spoofed-admin machine must never receive a field value, got %q", v)
	}
}

// TestSpoofedAdminMachineCannotEditSecretRuleset covers the per-secret
// ruleset, the other isFolderOwner-gated grant-granting surface.
func TestSpoofedAdminMachineCannotEditSecretRuleset(t *testing.T) {
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
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: spoofedAdminMachine("sa-spoofed"), SecretId: created.GetSecret().GetId(),
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-spoofed",
			Grants: map[string]string{"C": "allow"},
		}},
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("spoofed-admin machine must not edit a secret ruleset: want PermissionDenied, got %v", err)
	}
}

// TestMachineWithNoUserIDIsNeverFolderOwner pins the empty-string match: a
// machine principal carries no UserId, so before the fix it matched a folder
// whose OwnerUserId was likewise empty (or that carried an empty Owners entry)
// and was handed ownership of it.
func TestMachineWithNoUserIDIsNeverFolderOwner(t *testing.T) {
	s := newServer(t)
	s.folders = append(s.folders, &vaultv1.Folder{
		Id: "folder-ownerless", Name: "Ownerless",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL,
		// OwnerUserId deliberately empty, plus an empty Owners entry.
		Owners: []string{""},
	})
	f := s.findFolder("folder-ownerless")
	machine := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   "sa-no-flags",
	}
	if s.isFolderOwner(machine, f) {
		t.Fatal("a machine principal with an empty UserId must not own an ownerless folder")
	}
	// A human with an empty UserId (unauthenticated/zero actor) likewise.
	if s.isFolderOwner(&vaultv1.ActorContext{}, f) {
		t.Fatal("a zero-value actor must not own an ownerless folder")
	}
}

// TestHumanAdminAuthorityUnchanged is the counterweight: the fix must not cost
// real admins anything. A HUMAN admin is PrincipalKind_PRINCIPAL_KIND_HUMAN,
// which is the enum's ZERO value — so legacy callers that never set the field
// (every human path, plus internal/setup's bootstrap actor) stay admins.
func TestHumanAdminAuthorityUnchanged(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)

	humanAdmin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if !isHumanAdmin(humanAdmin) {
		t.Fatal("a human site-admin with PrincipalKind unset must still be an admin")
	}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: humanAdmin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("human site-admin must still set a folder ruleset (incl. everyone rules): %v", err)
	}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-root", IsRoot: true}, FolderId: fid,
		Owners: []string{"user-carol"},
	}); err != nil {
		t.Fatalf("human root must still set a folder ruleset: %v", err)
	}
}
