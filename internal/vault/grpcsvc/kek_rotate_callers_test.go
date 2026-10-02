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

// RotateKek runs as a human site admin, or in-process as the KEK scheduler.
// No other caller, and no workload actor, may rotate the key.

func wantDenied(t *testing.T, err error, what string) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%s: err = %v, want PermissionDenied", what, err)
	}
}

func TestRotateKek_RefusesEveryoneButAHumanAdmin(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	for name, a := range map[string]*vaultv1.ActorContext{
		"workload with admin flags": {UserId: "system:kek-rotation", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, IsSiteAdmin: true, IsRoot: true},
		"service account":           {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "system:kek-rotation", IsSiteAdmin: true},
		"human non-admin":           {UserId: "user-carol"},
		"human with a system id":    {UserId: "system:kek-rotation"},
	} {
		_, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: a})
		wantDenied(t, err, name)
	}
}

func TestRotateKek_HumanAdminPasses(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("human site-admin must rotate: %v", err)
	}
	ev := auditor.find("kek.rotate")
	if ev == nil || ev.ActorUserID != "user-admin" {
		t.Fatalf("kek.rotate event = %+v, want actor user-admin", ev)
	}
	if ev.Attributes["principal_kind"] != "human" || ev.Attributes["rotated_by"] != "human" {
		t.Fatalf("human rotation attrs = %v, want principal_kind=human rotated_by=human", ev.Attributes)
	}
}

func TestKekSchedulerTick_EmitsAuditEvent(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s := fx.s
	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()
	fx.ks.mu.Lock()
	fx.ks.rows[0].CreatedAt = time.Now().Add(-40 * 24 * time.Hour)
	fx.ks.mu.Unlock()

	if err := s.kekSchedulerTick(context.Background()); err != nil {
		t.Fatalf("kekSchedulerTick: %v", err)
	}
	ev := auditor.find("kek.rotate")
	if ev == nil {
		t.Fatal("scheduler rotation emitted no kek.rotate audit event")
	}
	if ev.ActorUserID != "system:kek-scheduler" {
		t.Fatalf("ActorUserID = %q, want system:kek-scheduler", ev.ActorUserID)
	}
	for k, want := range map[string]string{
		"principal_kind": "workload",
		"rotated_by":     "system",
		"trigger":        "scheduler",
		"outcome":        "ok",
		"active_ref":     "kek-v2",
	} {
		if got := ev.Attributes[k]; got != want {
			t.Fatalf("attr %s = %q, want %q (all: %v)", k, got, want, ev.Attributes)
		}
	}
}

func TestKekSchedulerTick_NotDue_NoAuditEvent(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s := fx.s
	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()
	fx.ks.mu.Lock()
	fx.ks.rows[0].CreatedAt = time.Now()
	fx.ks.mu.Unlock()
	if err := s.kekSchedulerTick(context.Background()); err != nil {
		t.Fatalf("kekSchedulerTick: %v", err)
	}
	if ev := auditor.find("kek.rotate"); ev != nil {
		t.Fatalf("not-due tick emitted %+v", ev)
	}
}
