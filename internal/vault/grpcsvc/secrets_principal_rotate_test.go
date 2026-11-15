// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// authorGrantFolder creates a shared folder owned by carol and grants
// subjectName plain RACI-Author (R) — the "may rotate/restore what it may
// author" grant #169 relies on — never RACI-C, proving rotate/restore don't
// need read access.
func authorGrantFolder(t *testing.T, s *Server, subjectName string) string {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: subjectName,
			Grants: map[string]string{"R": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	return fid
}

// TestRotateSecretForPrincipal_AuthorGrantRotatesAndReturnsValueOnce is the
// core LAPS-broker path: a service-account principal with RACI-Author (no
// RACI-C) rotates a secret it may author, the new value comes back in the
// same response (store-first, then set-on-host), a new version is appended,
// and the rotation is audited.
func TestRotateSecretForPrincipal_AuthorGrantRotatesAndReturnsValueOnce(t *testing.T) {
	s := newServerWithVersions(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	fid := authorGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "initial-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sid := created.GetSecret().GetId()

	resp, err := s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: sa, SecretId: sid})
	if err != nil {
		t.Fatalf("RotateSecretForPrincipal: %v", err)
	}
	if resp.GetNewValue() == "" || resp.GetNewValue() == "initial-pw" {
		t.Fatalf("want a freshly generated value, got %q", resp.GetNewValue())
	}

	// The vault's own copy is now the new value: a fresh reveal (own-reveal,
	// since the SA created the secret) returns exactly what rotate returned.
	rv, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: sa, Id: sid, FieldKey: "password"})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal after rotate: %v", err)
	}
	if rv.GetValue() != resp.GetNewValue() {
		t.Fatalf("stored value %q does not match returned value %q", rv.GetValue(), resp.GetNewValue())
	}
	if ev := ca.find("secret.rotate.principal"); ev == nil {
		t.Fatalf("want secret.rotate.principal audited, events=%+v", ca.events)
	}
}

// TestRotateSecretForPrincipal_RefusedWithoutAuthorAccess proves a token
// without RACI-Author on the folder is refused, audited either way — #169's
// second Done-when line.
func TestRotateSecretForPrincipal_RefusedWithoutAuthorAccess(t *testing.T) {
	s := newServerWithVersions(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s) // no grant at all for sa-laps
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "initial-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	_, err = s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: sa, SecretId: created.GetSecret().GetId()})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if ev := ca.find("secret.rotate.principal.denied"); ev == nil {
		t.Fatalf("want secret.rotate.principal.denied audited, events=%+v", ca.events)
	}
}

// TestRotateSecretForPrincipal_RefusedWithOnlyReadNoAuthor proves RACI-C
// (read/own-reveal) alone, without Author, never lets a principal rotate —
// rotate is gated on Author, never on read.
func TestRotateSecretForPrincipal_RefusedWithOnlyReadNoAuthor(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-reader",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "initial-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-reader"}
	if _, err := s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: sa, SecretId: created.GetSecret().GetId()}); code(err) != codes.PermissionDenied {
		t.Fatalf("read-only grant should never rotate, got %v", err)
	}
}

// TestRotateSecretForPrincipal_RefusedWhileRotationQueued mirrors
// RestoreSecretVersion's ROTATION_IN_PROGRESS guard for the principal path.
func TestRotateSecretForPrincipal_RefusedWhileRotationQueued(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := authorGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "initial-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sid := created.GetSecret().GetId()
	s.rot = newRotationStore(rotTestPool(t).Querier())
	if err := s.rot.Enqueue(ctx, sid, "manual", 0); err != nil {
		t.Fatal(err)
	}
	_, err = s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: sa, SecretId: sid})
	if got := reasonOf(t, err, codes.FailedPrecondition); got != ReasonRotationInProgress {
		t.Fatalf("reason %q, want %s", got, ReasonRotationInProgress)
	}
}

// TestRestoreSecretVersionForPrincipal_AuthorGrantRestoresPriorVersion
// covers #169's restore half: a principal with RACI-Author rolls a secret
// back to an earlier version as a NEW version (never a history rewrite),
// audited, with no recovery role or MFA required (unlike the human path).
func TestRestoreSecretVersionForPrincipal_AuthorGrantRestoresPriorVersion(t *testing.T) {
	s := newServerWithVersions(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	fid := authorGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}

	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "v1-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: sa, SecretId: sid}); err != nil {
		t.Fatalf("RotateSecretForPrincipal: %v", err)
	}

	if _, err := s.RestoreSecretVersionForPrincipal(ctx, &vaultv1.RestoreSecretVersionForPrincipalRequest{
		Actor: sa, SecretId: sid, VersionNo: 1,
	}); err != nil {
		t.Fatalf("RestoreSecretVersionForPrincipal: %v", err)
	}
	rv, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: sa, Id: sid, FieldKey: "password"})
	if err != nil {
		t.Fatalf("reveal after restore: %v", err)
	}
	if rv.GetValue() != "v1-pw" {
		t.Fatalf("restored value %q, want v1-pw", rv.GetValue())
	}
	metas, err := s.vers.List(ctx, sid, s.crypt)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("want 3 versions (create, rotate, restore), got %d", len(metas))
	}
	if ev := ca.find("secret.version.restore.principal"); ev == nil {
		t.Fatalf("want secret.version.restore.principal audited, events=%+v", ca.events)
	}
}

// TestRestoreSecretVersionForPrincipal_RefusedWithoutAuthorAccess mirrors
// the rotate refusal test for restore.
func TestRestoreSecretVersionForPrincipal_RefusedWithoutAuthorAccess(t *testing.T) {
	s := newServerWithVersions(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "v1-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	_, err = s.RestoreSecretVersionForPrincipal(ctx, &vaultv1.RestoreSecretVersionForPrincipalRequest{
		Actor: sa, SecretId: created.GetSecret().GetId(), VersionNo: 1,
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if ev := ca.find("secret.version.restore.principal.denied"); ev == nil {
		t.Fatalf("want secret.version.restore.principal.denied audited, events=%+v", ca.events)
	}
}

// TestRotateAndRestoreForPrincipal_RefuseHumanActor: these two RPCs are the
// non-human path; a human actor must use RestoreSecretVersion (and has no
// direct "rotate now" RPC of its own to misuse here).
func TestRotateAndRestoreForPrincipal_RefuseHumanActor(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "v1-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if _, err := s.RotateSecretForPrincipal(ctx, &vaultv1.RotateSecretForPrincipalRequest{Actor: carol, SecretId: created.GetSecret().GetId()}); code(err) != codes.PermissionDenied {
		t.Fatalf("human rotate-for-principal: want PermissionDenied, got %v", err)
	}
	if _, err := s.RestoreSecretVersionForPrincipal(ctx, &vaultv1.RestoreSecretVersionForPrincipalRequest{Actor: carol, SecretId: created.GetSecret().GetId(), VersionNo: 1}); code(err) != codes.PermissionDenied {
		t.Fatalf("human restore-for-principal: want PermissionDenied, got %v", err)
	}
}
