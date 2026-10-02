// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
)

// TestRevealForWorkloadWithGrant proves a verified workload principal (fake
// wid.Verify -> Principal{WorkerID:"wl-1"}) with RACI-C on the secret's chain
// reveals via the same generalized path as RevealSecretFieldForPrincipal,
// and the audit event attributes the workload principal.
func TestRevealForWorkloadWithGrant(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "wl-1"}}
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

	// Grant the workload principal C (read) on the folder — matched the same
	// way an SA principal is (RACI subject keyed by principal id).
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "wl-1",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}

	resp, err := s.RevealForWorkload(ctx, &vaultv1.WorkerIdentity{Token: "whatever"}, sid, "password")
	if err != nil {
		t.Fatalf("RevealForWorkload(with grant): %v", err)
	}
	if resp.GetValue() != "Sup3r$ecret" {
		t.Fatalf("revealed %q, want Sup3r$ecret", resp.GetValue())
	}

	ev := ca.find("secret.reveal.principal")
	if ev == nil {
		t.Fatal("expected a secret.reveal.principal audit event")
	}
	if ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_WORKLOAD" {
		t.Fatalf("audit principal_kind = %q, want PRINCIPAL_KIND_WORKLOAD", ev.Attributes["principal_kind"])
	}
	if ev.Attributes["principal_id"] != "wl-1" {
		t.Fatalf("audit principal_id = %q, want wl-1", ev.Attributes["principal_id"])
	}
	if ev.ActorUserID != "wl-1" {
		t.Fatalf("audit actor = %q, want wl-1 (the workload principal)", ev.ActorUserID)
	}
}

// TestRevealForWorkloadWithoutGrantDenied proves a verified workload
// principal WITHOUT a Read grant is denied.
func TestRevealForWorkloadWithoutGrantDenied(t *testing.T) {
	s := newServer(t)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "wl-2"}}
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

	_, err = s.RevealForWorkload(ctx, &vaultv1.WorkerIdentity{Token: "whatever"}, sid, "password")
	if code(err) != codes.PermissionDenied {
		t.Fatalf("workload without grant: want PermissionDenied, got %v", err)
	}
}

// TestRevealForWorkloadRejectsBadIdentity proves an unverifiable workload
// token is rejected before any RACI/secret lookup happens.
func TestRevealForWorkloadRejectsBadIdentity(t *testing.T) {
	s := newServer(t)
	s.wid = rejectVerifier{}
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

	_, err = s.RevealForWorkload(ctx, &vaultv1.WorkerIdentity{Token: "bad"}, sid, "password")
	if code(err) != codes.PermissionDenied {
		t.Fatalf("bad workload identity: want PermissionDenied, got %v", err)
	}
}
