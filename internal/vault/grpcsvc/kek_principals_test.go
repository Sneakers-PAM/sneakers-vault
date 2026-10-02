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

// systemRotator is the allowlisted SYSTEM principal the operator presents to
// RotateKek. Admin flags are set on purpose: they must be ignored, never
// turned into admin authority anywhere else.
func systemRotator() *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		UserId:        "system:kek-rotation",
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
		IsSiteAdmin:   true,
		IsRoot:        true,
	}
}

func newSystemRotatorServer(t *testing.T, auditor Auditor) rotateFixture {
	t.Helper()
	fx := newRotateTestServer(t, auditor)
	ids, err := ParseKekRotationPrincipals("system:kek-rotation")
	if err != nil {
		t.Fatalf("ParseKekRotationPrincipals: %v", err)
	}
	fx.s.SetKekRotationPrincipals(ids)
	return fx
}

func wantDenied(t *testing.T, err error, what string) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%s: err = %v, want PermissionDenied", what, err)
	}
}

func TestParseKekRotationPrincipals(t *testing.T) {
	for _, v := range []string{"", "   "} {
		ids, err := ParseKekRotationPrincipals(v)
		if err != nil || len(ids) != 0 {
			t.Fatalf("%q: got %v, %v; want disabled (empty, nil)", v, ids, err)
		}
	}
	ids, err := ParseKekRotationPrincipals(" system:kek-rotation , system:dr-rotation ")
	if err != nil {
		t.Fatalf("valid list: %v", err)
	}
	if len(ids) != 2 || ids[0] != "system:kek-rotation" || ids[1] != "system:dr-rotation" {
		t.Fatalf("ids = %q, want trimmed [system:kek-rotation system:dr-rotation]", ids)
	}
	for _, bad := range []string{
		"kek-rotation",                   // no system: prefix
		"system:",                        // empty name
		"system:kek-rotation,user-carol", // one bad entry poisons the list
		"system:kek-rotation,,system:x",  // empty entry
		"System:kek-rotation",            // prefix is case-sensitive
		"system:kek rotation",            // whitespace inside the id
		"system:kek-scheduler",           // reserved for the internal scheduler
		"system",                         // the legacy seed/non-user actor
		"sa-deadbeef",                    // a service-account id
	} {
		if _, err := ParseKekRotationPrincipals(bad); err == nil {
			t.Fatalf("%q: want a config error", bad)
		}
	}
}

func TestRotateKek_AllowlistedWorkload_Passes(t *testing.T) {
	fx := newSystemRotatorServer(t, nil)
	resp, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: systemRotator()})
	if err != nil {
		t.Fatalf("allowlisted SYSTEM workload must rotate: %v", err)
	}
	if resp.GetActiveRef() != "kek-v2" {
		t.Fatalf("ActiveRef = %q, want kek-v2", resp.GetActiveRef())
	}
}

func TestRotateKek_AllowlistIsExactMatch(t *testing.T) {
	fx := newSystemRotatorServer(t, nil)
	for _, id := range []string{"system:kek-rotation2", "system:kek-rotatio", " system:kek-rotation", "SYSTEM:kek-rotation", "system:other", ""} {
		a := systemRotator()
		a.UserId = id
		_, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: a})
		wantDenied(t, err, "non-allowlisted workload "+id)
	}
	if got := fx.s.keyring.ActiveRef(); got != "kek-v1" {
		t.Fatalf("a denied call must not rotate: ActiveRef = %q", got)
	}
}

func TestRotateKek_DisabledByDefault(t *testing.T) {
	fx := newRotateTestServer(t, nil) // no SetKekRotationPrincipals: env unset
	_, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: systemRotator()})
	wantDenied(t, err, "workload with the allowlist unset")
}

func TestRotateKek_ServiceAccountWithAllowlistedID_Denied(t *testing.T) {
	fx := newSystemRotatorServer(t, nil)
	a := systemRotator()
	a.PrincipalKind = vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT
	a.PrincipalId = "system:kek-rotation"
	_, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: a})
	wantDenied(t, err, "SERVICE_ACCOUNT carrying an allowlisted id")
}

func TestRotateKek_HumanWithAllowlistedID_NonAdmin_Denied(t *testing.T) {
	fx := newSystemRotatorServer(t, nil)
	for _, a := range []*vaultv1.ActorContext{
		{UserId: "user-carol"},
		// HUMAN kind never gets the SYSTEM grant, even with the exact id.
		{UserId: "system:kek-rotation", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN},
	} {
		_, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: a})
		wantDenied(t, err, "human non-admin "+a.GetUserId())
	}
}

func TestRotateKek_HumanAdminStillPasses(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newSystemRotatorServer(t, auditor)
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("human site-admin must still rotate: %v", err)
	}
	ev := auditor.find("kek.rotate")
	if ev == nil || ev.ActorUserID != "user-admin" {
		t.Fatalf("kek.rotate event = %+v, want actor user-admin", ev)
	}
	if ev.Attributes["principal_kind"] != "human" || ev.Attributes["rotated_by"] != "human" {
		t.Fatalf("human rotation attrs = %v, want principal_kind=human rotated_by=human", ev.Attributes)
	}
}

func TestRotateKek_SystemPrincipal_AuditCarriesSystemID(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newSystemRotatorServer(t, auditor)
	if _, err := fx.s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: systemRotator()}); err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	ev := auditor.find("kek.rotate")
	if ev == nil {
		t.Fatal("no kek.rotate audit event")
	}
	if ev.ActorUserID != "system:kek-rotation" {
		t.Fatalf("ActorUserID = %q, want system:kek-rotation", ev.ActorUserID)
	}
	for k, want := range map[string]string{
		"principal_kind": "workload",
		"rotated_by":     "system",
		"trigger":        "rpc",
		"outcome":        "ok",
		"active_ref":     "kek-v2",
	} {
		if got := ev.Attributes[k]; got != want {
			t.Fatalf("attr %s = %q, want %q (all: %v)", k, got, want, ev.Attributes)
		}
	}
}

// TestSystemRotator_GetsNoOtherAdminAuthority: the SYSTEM grant is RotateKek
// only. The same actor (admin flags set) must stay a non-admin on every other
// isHumanAdmin gate.
func TestSystemRotator_GetsNoOtherAdminAuthority(t *testing.T) {
	fx := newSystemRotatorServer(t, nil)
	s := fx.s
	ctx := context.Background()
	a := systemRotator()

	if isHumanAdmin(a) {
		t.Fatal("isHumanAdmin must stay false for the SYSTEM rotator")
	}
	fid := newSharedFolder(t, s)
	// Make the rotator a folder owner first, so the call below gets past the
	// owner gate and is decided by the admin-only everyone-rule gate itself.
	humanAdmin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: humanAdmin, FolderId: fid, Owners: []string{"user-carol", "system:kek-rotation"},
	}); err != nil {
		t.Fatalf("admin SetFolderRuleset: %v", err)
	}
	_, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: a, FolderId: fid, Owners: []string{"system:kek-rotation"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	})
	wantDenied(t, err, "SYSTEM rotator on SetFolderRuleset")

	// Prod hard-delete is admin-only.
	ids, _ := seedRecordsOnV1(t, s, 1)
	s.env = "prod"
	_, err = s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: a, Id: ids[0]})
	wantDenied(t, err, "SYSTEM rotator on prod DeleteSecret")
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
