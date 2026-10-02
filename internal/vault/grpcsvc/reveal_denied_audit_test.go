// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refused reveal is audited as secret.reveal.denied with the reason, for
// people and machine principals, on reveal, copy and version reveal.

func revealDeniedFixture(t *testing.T) (*Server, *capAudit, string) {
	t.Helper()
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	fid := newSharedFolder(t, s)
	return s, ca, secretIn(t, s, &vaultv1.ActorContext{UserId: "user-carol"}, fid, "db")
}

func wantRevealDenied(t *testing.T, ca *capAudit, err error, actor, reason, action string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: not refused", action)
	}
	ev := ca.find("secret.reveal.denied")
	if ev == nil || ev.ActorUserID != actor || ev.Attributes["reason"] != reason || ev.Attributes["action"] != action {
		t.Fatalf("%s: audit = %+v", action, ev)
	}
	for _, v := range ev.Attributes {
		if v == "p" {
			t.Fatal("the value leaked into the audit")
		}
	}
	if action != "reveal" || actor != "sa-x" {
		ca.mu.Lock()
		ca.events = nil
		ca.mu.Unlock()
	}
}

func TestRefusedRevealsAreAudited(t *testing.T) {
	ctx := context.Background()
	nobody := &vaultv1.ActorContext{UserId: "user-nobody"}

	s, ca, sid := revealDeniedFixture(t)
	_, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: nobody, Id: sid, FieldKey: "password"})
	wantRevealDenied(t, ca, err, "user-nobody", ReasonNoAccess, "reveal")

	_, err = s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: nobody, Id: sid})
	wantRevealDenied(t, ca, err, "user-nobody", ReasonNoAccess, "copy")

	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x"}
	_, err = s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: sa, Id: sid, FieldKey: "password"})
	wantRevealDenied(t, ca, err, "sa-x", ReasonNoAccess, "reveal")
	if ev := ca.find("secret.reveal.denied"); ev == nil || ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" {
		t.Fatalf("principal_kind = %q", ev.Attributes["principal_kind"])
	}
}

func TestRefusedVersionRevealIsAudited(t *testing.T) {
	s := newServerWithVersions(t)
	ca := &capAudit{}
	s.audit = ca
	fid := newSharedFolder(t, s)
	sid := secretIn(t, s, &vaultv1.ActorContext{UserId: "user-carol"}, fid, "db")
	nobody := &vaultv1.ActorContext{UserId: "user-nobody", IsRecovery: true, MfaVerifiedAtUnix: time.Now().Unix()}
	_, err := s.RevealSecretVersionField(context.Background(), &vaultv1.RevealSecretVersionFieldRequest{Actor: nobody, SecretId: sid, VersionNo: 1, FieldKey: "password"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err %v", err)
	}
	wantRevealDenied(t, ca, err, "user-nobody", ReasonNoAccess, "version.reveal")
}

func TestRevealOfARetiredSecretIsAudited(t *testing.T) {
	s, ca, sid := revealDeniedFixture(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatal(err)
	}
	_, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: carol, Id: sid, FieldKey: "password"})
	wantRevealDenied(t, ca, err, "user-carol", ReasonRetired, "reveal")
}
