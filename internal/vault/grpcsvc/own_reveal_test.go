// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// ownGrantFolder creates a shared folder owned by carol, and grants the
// subject (named by subjectName, SUBJECT_KIND_USER — matching both a human
// user id and a non-human principal id, same as the rest of this package's
// principal fixtures) RACI Author (contribute) plus an own-only Read (C=own)
// cell: the "contribute, own reveal" grant under test.
func ownGrantFolder(t *testing.T, s *Server, subjectName string) string {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: subjectName,
			Grants: map[string]string{"R": "allow", "C": "own"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	return fid
}

// TestOwnReveal_PrincipalRevealsItsOwnSecretOnly is the core path: a
// service-account principal with a contribute/own-reveal grant creates a
// secret (buildAndStoreSecret records creator_principal_id), reveals it, and
// is refused — audited — on a secret someone else created in the SAME
// folder, under the SAME grant.
func TestOwnReveal_PrincipalRevealsItsOwnSecretOnly(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	fid := ownGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	own, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "own-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	if got := own.GetSecret().GetId(); got == "" {
		t.Fatal("expected a secret id")
	}

	// A human owner (carol, auto-read/author) creates a second secret in the
	// same folder — this is the "anyone else's" secret the SA never created.
	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "host-b admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "others-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (carol): %v", err)
	}

	// Reveal own: succeeds.
	rv, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: sa, Id: own.GetSecret().GetId(), FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("reveal own: unexpected error: %v", err)
	}
	if rv.GetValue() != "own-pw" {
		t.Fatalf("revealed %q, want own-pw", rv.GetValue())
	}

	// Reveal someone else's in the same folder, same grant: refused + audited.
	ca.events = nil
	_, err = s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: sa, Id: others.GetSecret().GetId(), FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("reveal other's secret: want PermissionDenied, got %v", err)
	}
	if ev := ca.find("secret.reveal.denied"); ev == nil {
		t.Fatalf("want an audit record for the refusal, events=%+v", ca.events)
	}
}

// TestOwnReveal_ContributeStillCreatesAndUpdatesAnywhereInFolder proves the
// restriction is reveal-only: the own-reveal grant still lets the principal
// create AND update secrets anywhere in the folder, including ones it
// doesn't own (RACI Author is unaffected by an own-only Read cell).
func TestOwnReveal_ContributeStillCreatesAndUpdatesAnywhereInFolder(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := ownGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "host-b admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "others-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (carol): %v", err)
	}
	if _, err := s.UpdateSecretFieldsForPrincipal(ctx, &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: sa, Id: others.GetSecret().GetId(), Fields: map[string]string{"password": "rotated-by-sa"},
	}); err != nil {
		t.Fatalf("UpdateSecretFieldsForPrincipal on an unowned secret should still be allowed (contribute): %v", err)
	}
	if !s.canManage(sa, fid) {
		t.Fatal("contribute grant should still allow Author/manage on the folder")
	}
}

// TestOwnReveal_ListAndGetHideSecretsTheCallerDidNotCreate covers the
// listing/metadata read paths: ListSecretsForPrincipal and
// GetSecretForPrincipal must show only secrets the principal itself created,
// never anyone else's, under an own-reveal grant.
func TestOwnReveal_ListAndGetHideSecretsTheCallerDidNotCreate(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := ownGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	own, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "own-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "host-b admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "others-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (carol): %v", err)
	}

	list, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{Actor: sa, FolderId: fid})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	if len(list.GetSecrets()) != 1 || list.GetSecrets()[0].GetId() != own.GetSecret().GetId() {
		t.Fatalf("want only the SA's own secret listed, got %+v", list.GetSecrets())
	}

	if _, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: sa, Id: own.GetSecret().GetId()}); err != nil {
		t.Fatalf("GetSecretForPrincipal(own): %v", err)
	}
	if _, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: sa, Id: others.GetSecret().GetId()}); code(err) != codes.PermissionDenied {
		t.Fatalf("GetSecretForPrincipal(other's): want PermissionDenied, got %v", err)
	}
}

// TestOwnReveal_CopySecretRefusedOnUnownedSecret covers the human copy-to-
// clipboard path (CopySecret): a human subject carrying the same own-reveal
// grant may copy a secret it created, and is refused on one it didn't,
// proving the restriction isn't limited to non-human principals.
func TestOwnReveal_CopySecretRefusedOnUnownedSecret(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := ownGrantFolder(t, s, "user-dave")
	dave := &vaultv1.ActorContext{UserId: "user-dave"}

	own, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: dave, Name: "dave's secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "dave-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (dave): %v", err)
	}
	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "carol's secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "carol-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (carol): %v", err)
	}

	if resp, err := s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: dave, Id: own.GetSecret().GetId()}); err != nil || resp.GetValue() != "dave-pw" {
		t.Fatalf("CopySecret(own): value=%q err=%v", resp.GetValue(), err)
	}
	if _, err := s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: dave, Id: others.GetSecret().GetId()}); code(err) != codes.PermissionDenied {
		t.Fatalf("CopySecret(other's): want PermissionDenied, got %v", err)
	}
}

// TestOwnReveal_VersionRevealRefusedOnUnownedSecret covers the history/
// version-reveal path (RevealSecretVersionField): own-reveal plus the
// recovery role still only reveals a version of a secret the subject itself
// created.
func TestOwnReveal_VersionRevealRefusedOnUnownedSecret(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := ownGrantFolder(t, s, "user-dave")
	dave := &vaultv1.ActorContext{UserId: "user-dave", IsRecovery: true, MfaVerifiedAtUnix: time.Now().Unix()}

	own, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-dave"}, Name: "dave's secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "dave-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (dave): %v", err)
	}
	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "carol's secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "carol-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (carol): %v", err)
	}

	if _, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: dave, SecretId: own.GetSecret().GetId(), FieldKey: "password", VersionNo: 1,
	}); err != nil {
		t.Fatalf("RevealSecretVersionField(own): %v", err)
	}
	if _, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: dave, SecretId: others.GetSecret().GetId(), FieldKey: "password", VersionNo: 1,
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("RevealSecretVersionField(other's): want PermissionDenied, got %v", err)
	}
}

// TestOwnReveal_ExistingAllowDenyGrantsUnchanged proves a plain allow/deny
// folder (no "own" cell anywhere) behaves exactly as before: full read for
// an allowed subject, nothing new leaks in or is newly restricted.
func TestOwnReveal_ExistingAllowDenyGrantsUnchanged(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-dave",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	others, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "carol's secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "carol-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if !s.canRead(&vaultv1.ActorContext{UserId: "user-dave"}, others.GetSecret()) {
		t.Fatal("a plain C=allow grant must still read a secret the subject didn't create")
	}
}

// TestOwnReveal_SaveRejectsOwnOnNonReadCell proves the server refuses to save
// a ruleset carrying "own" on any cell but C — a stray value there would
// silently do nothing (no allow, no deny, no own-handling for R/A/I in
// authz.decideAction), which is worse than refusing it up front.
func TestOwnReveal_SaveRejectsOwnOnNonReadCell(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	_, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-laps",
			Grants: map[string]string{"R": "own"},
		}},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for own on R, got %v", err)
	}
}

// TestOwnReveal_CreatorRecordedOnCreate proves creator_principal_id is set
// at creation on every creation path the own-reveal check relies on: the
// human CreateSecret and the non-human CreateSecretForPrincipal/
// GenerateSecretForPrincipal (via the shared buildAndStoreSecret).
func TestOwnReveal_CreatorRecordedOnCreate(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)

	human, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "human-made", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if got := human.GetSecret().GetCreatorPrincipalId(); got != "user-carol" {
		t.Fatalf("CreateSecret: creator_principal_id = %q, want user-carol", got)
	}

	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-laps",
			Grants: map[string]string{"R": "allow", "C": "own"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "sa-made", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "pw2"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	if got := created.GetSecret().GetCreatorPrincipalId(); got != "sa-laps" {
		t.Fatalf("CreateSecretForPrincipal: creator_principal_id = %q, want sa-laps", got)
	}

	generated, err := s.GenerateSecretForPrincipal(ctx, &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: sa, Name: "sa-generated", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc"},
	})
	if err != nil {
		t.Fatalf("GenerateSecretForPrincipal: %v", err)
	}
	if got := generated.GetSecret().GetCreatorPrincipalId(); got != "sa-laps" {
		t.Fatalf("GenerateSecretForPrincipal: creator_principal_id = %q, want sa-laps", got)
	}
}
