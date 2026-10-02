// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// TestRevealSecretFieldForPrincipalSAWithGrant proves an SA principal with a
// RACI-C grant on the secret's chain reveals the plaintext and emits an
// audited secret.reveal.principal event attributed to the principal, with
// principal_kind/principal_id attributes and NEVER the revealed value.
func TestRevealSecretFieldForPrincipalSAWithGrant(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator => owner
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	// Grant the SA principal C (read) via the folder ruleset — SA principals are
	// RACI subjects keyed by principal id, matched like a SUBJECT_KIND_USER rule.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-ci-runner",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}

	saActor := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-ci-runner",
	}
	resp, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: saActor, Id: sid, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal(SA with grant): %v", err)
	}
	if resp.GetValue() != "Sup3r$ecret" {
		t.Fatalf("revealed %q, want Sup3r$ecret", resp.GetValue())
	}

	ev := ca.find("secret.reveal.principal")
	if ev == nil {
		t.Fatal("expected a secret.reveal.principal audit event")
	}
	if ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" {
		t.Fatalf("audit principal_kind = %q, want PRINCIPAL_KIND_SERVICE_ACCOUNT", ev.Attributes["principal_kind"])
	}
	if ev.Attributes["principal_id"] != "sa-ci-runner" {
		t.Fatalf("audit principal_id = %q, want sa-ci-runner", ev.Attributes["principal_id"])
	}
	for _, v := range ev.Attributes {
		if v == "Sup3r$ecret" {
			t.Fatal("audit attributes must never carry the revealed value")
		}
	}
}

// TestRevealSecretFieldForPrincipalSAWithoutGrantDenied proves an SA
// principal without a Read grant is denied and never receives plaintext.
func TestRevealSecretFieldForPrincipalSAWithoutGrantDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	saActor := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-no-grant",
	}
	resp, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: saActor, Id: sid, FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("SA without grant: want PermissionDenied, got %v", err)
	}
	if resp != nil && resp.GetValue() != "" {
		t.Fatal("no plaintext must be returned on denial")
	}
}

// TestRevealSecretFieldForPrincipalHumanDenied proves a HUMAN-kind actor
// (PRINCIPAL_KIND_HUMAN, the default/zero value) is rejected by
// RevealSecretFieldForPrincipal even though it would otherwise satisfy
// RACI-read (it owns the secret's folder). This is a deliberate
// defense-in-depth restriction: the no-MFA principal-reveal path must be
// reachable ONLY by non-human principals, so the security property doesn't
// rest solely on the gateway routing humans through RevealSecretField's
// MFA/checkout step-up instead. A human must use RevealSecretField.
func TestRevealSecretFieldForPrincipalHumanDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator => owner
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	resp, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: carol, Id: sid, FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("RevealSecretFieldForPrincipal(human): want PermissionDenied, got %v", err)
	}
	if resp != nil && resp.GetValue() != "" {
		t.Fatal("no plaintext must be returned to a human caller on this path")
	}
}

// TestRevealSecretFieldForPrincipalSpoofedAdminDenied proves an SA principal
// carrying is_site_admin=true, but with NO RACI grant, is still denied.
// evalOf never treats is_site_admin/is_root as meaningful for a non-human
// principal, so this anchors the anti-spoof branch: access comes entirely
// from RACI/Target grants, never from a spoofed admin flag.
func TestRevealSecretFieldForPrincipalSpoofedAdminDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	saActor := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   "sa-spoofed-admin", IsSiteAdmin: true,
	}
	resp, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: saActor, Id: sid, FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("SA with spoofed is_site_admin, no grant: want PermissionDenied, got %v", err)
	}
	if resp != nil && resp.GetValue() != "" {
		t.Fatal("no plaintext must be returned on denial")
	}
}

// TestRevealSecretFieldForPrincipalNoMFAGate proves the principal reveal path
// never consults an MFA/checkout gate: a machine principal that never
// performs interactive MFA/checkout still reveals purely on RACI-C, same as
// the SA-with-grant case above (this test documents the absence of any
// checkout-state precondition on the call).
func TestRevealSecretFieldForPrincipalNoMFAGate(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc secret", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-no-checkout",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	saActor := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-no-checkout",
	}
	// No checkout/MFA state exists anywhere for this principal — the call must
	// still succeed on RACI-C alone.
	if _, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: saActor, Id: sid, FieldKey: "password",
	}); err != nil {
		t.Fatalf("reveal without any MFA/checkout state: %v", err)
	}
}
