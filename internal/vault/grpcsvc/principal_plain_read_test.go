// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func plainRead(s *Server, actor *vaultv1.ActorContext, id, field string) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	return s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: actor, Id: id, FieldKey: field,
	})
}

func assertNoReveal(t *testing.T, ca *capAudit) {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	for _, ev := range ca.events {
		if strings.HasPrefix(ev.Action, "secret.reveal") {
			t.Fatalf("a plain field read was audited as a reveal: %+v", ev)
		}
	}
}

func TestPrincipalReadsANonSensitiveFieldWithRead(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	folder := newSharedFolder(t, s)
	id := secretIn(t, s, carol, folder, "router-admin")
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: folder, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-ci-runner",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-ci-runner"}
	views := s.findSecret(id).GetViewCount()

	resp, err := plainRead(s, sa, id, "username")
	if err != nil {
		t.Fatalf("SA plain read: %v", err)
	}
	if resp.GetValue() != "u" {
		t.Fatalf("read %q, want u", resp.GetValue())
	}
	ev := ca.find("secret.read.principal")
	if ev == nil {
		t.Fatal("expected a secret.read.principal audit event")
	}
	if ev.ActorUserID != "sa-ci-runner" || ev.Subject != id+"#username" || ev.Sensitive {
		t.Fatalf("read audit = %+v", ev)
	}
	if ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" || ev.Attributes["principal_id"] != "sa-ci-runner" {
		t.Fatalf("read audit attributes = %+v", ev.Attributes)
	}
	for _, v := range ev.Attributes {
		if v == "u" {
			t.Fatal("audit attributes must never carry the field value")
		}
	}
	assertNoReveal(t, ca)
	if s.findSecret(id).GetViewCount() != views {
		t.Fatal("a plain field read must not count as a view")
	}
}

func TestPersonalTokenReadsANonSensitiveField(t *testing.T) {
	fx := newUseFixture(t)
	resp, err := plainRead(fx.s, fx.token, fx.secret, "username")
	if err != nil {
		t.Fatalf("token plain read: %v", err)
	}
	if resp.GetValue() != "u" {
		t.Fatalf("read %q, want u", resp.GetValue())
	}
	ev := fx.ca.find("secret.read.principal")
	if ev == nil {
		t.Fatal("expected a secret.read.principal audit event")
	}
	if ev.ActorUserID != "user-ada" || ev.Attributes["token_id"] != "utok-1" ||
		ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_USER_TOKEN" {
		t.Fatalf("token read audit = %+v", ev)
	}
	assertNoReveal(t, fx.ca)
}

func TestPrincipalPlainReadWithoutReadIsDenied(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	id := secretIn(t, s, carol, newSharedFolder(t, s), "router-admin")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-no-grant"}
	resp, err := plainRead(s, sa, id, "username")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SA without read: want PermissionDenied, got %v", err)
	}
	if resp.GetValue() != "" {
		t.Fatal("no value on denial")
	}
	if _, err := plainRead(s, tokenActor("user-ada", false, "g-agents"), id, "username"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("token without read: want PermissionDenied, got %v", err)
	}
}

func TestPersonalTokenCannotPlainReadAnotherUsersPersonalFolder(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-bob")
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	id := secretIn(t, s, bob, "folder-personal-bob", "bob-bank")
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: bob, FolderId: "folder-personal-bob", Owners: []string{"user-bob"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-admin", Grants: map[string]string{"C": "allow", "R": "allow"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := plainRead(s, tokenActor("user-admin", true), id, "username"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another user's personal folder: want PermissionDenied, got %v", err)
	}
}

func TestApprovalOnGatesOnlySensitiveFieldsForATokenRead(t *testing.T) {
	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	resp, err := plainRead(fx.s, fx.token, fx.secret, "username")
	if err != nil {
		t.Fatalf("approval ON must not gate a non-sensitive read: %v", err)
	}
	if resp.GetValue() != "u" {
		t.Fatalf("read %q, want u", resp.GetValue())
	}
	_, err = plainRead(fx.s, fx.token, fx.secret, "password")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "approval_required") {
		t.Fatalf("sensitive field on approval ON: want approval_required, got %v", err)
	}
}

func TestPrincipalReadOfAnUnknownFieldIsNotFound(t *testing.T) {
	fx := newUseFixture(t)
	if _, err := plainRead(fx.s, fx.token, fx.secret, "no-such-field"); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown field: want NotFound, got %v", err)
	}
}
