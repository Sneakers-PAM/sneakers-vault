// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
)

// The domain's built-in Administrator (objectSid RID 500) is never rotated.
// The connector reports it on heartbeat and on a refused rotation; vault
// records it on the secret and keeps it out of every rotation path, while
// heartbeat keeps running.

type builtinAdminFixture struct {
	s  *Server
	ca *capAudit
	id string
}

// newBuiltinAdminFixture is a mem-backed server with real Postgres schedule
// and version stores, holding one rotating AD secret with a reachable target.
func newBuiltinAdminFixture(t *testing.T) *builtinAdminFixture {
	t.Helper()
	_, pool := organizeFreshDB(t)
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.SetHeartbeat(pool, nil)
	s.SetRotation(pool, nil)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	fx := &builtinAdminFixture{s: s, ca: ca}
	tgt, _ := reachableTarget(t, s)
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "domain admin", FolderId: authorFolder(t, s), TypeId: "type-windows-domain", TargetId: tgt,
		Fields: map[string]string{"domain": "EXAMPLE", "username": "renamed-admin", "password": "Init1alP@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	fx.id = c.GetSecret().GetId()
	if !fx.hasRotationRow(t) || !fx.hasHeartbeatRow(t) {
		t.Fatal("setup: the secret should be scheduled for rotation and heartbeat")
	}
	return fx
}

func heartbeatReport(id string, builtin, adminCount *bool) *vaultv1.ReportHeartbeatRequest {
	return &vaultv1.ReportHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: id,
		Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, BuiltinAdministrator: builtin, AdminCount: adminCount,
	}
}

func (fx *builtinAdminFixture) heartbeat(t *testing.T, builtin, adminCount *bool) {
	t.Helper()
	if _, err := fx.s.ReportHeartbeat(context.Background(), heartbeatReport(fx.id, builtin, adminCount)); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
}

func (fx *builtinAdminFixture) secret() *vaultv1.Secret {
	fx.s.mu.RLock()
	defer fx.s.mu.RUnlock()
	return fx.s.findSecret(fx.id)
}

func (fx *builtinAdminFixture) hasRotationRow(t *testing.T) bool {
	t.Helper()
	ok, err := fx.s.rot.Exists(context.Background(), fx.id)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (fx *builtinAdminFixture) hasHeartbeatRow(t *testing.T) bool {
	t.Helper()
	ok, err := fx.s.hb.Exists(context.Background(), fx.id)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (fx *builtinAdminFixture) claimed(t *testing.T) bool {
	t.Helper()
	resp, err := fx.s.ClaimDueRotations(context.Background(), &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
	if err != nil {
		t.Fatalf("ClaimDueRotations: %v", err)
	}
	for _, j := range resp.GetJobs() {
		if j.GetSecretId() == fx.id {
			return true
		}
	}
	return false
}

func ptr(b bool) *bool { return &b }

// Real Postgres 17 snapshot store: the flags survive a restart.
func TestReportHeartbeat_RecordsAccountFlagsAcrossRestart(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	s, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	ca := &capAudit{}
	s.audit = ca
	s.SetHeartbeat(pool, nil)
	s.SetRotation(pool, nil)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	folder := callPersisted(t, s, "CreateFolder", &vaultv1.CreateFolderRequest{Actor: orgCarol, Name: "Domain"}, s.CreateFolder).GetFolder().GetId()
	conn := callPersisted(t, s, "SaveConnection", &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "Directory LDAPS", Protocol: "ldap", Port: 636, UseTls: true},
	}, s.SaveConnection).GetConnection().GetId()
	tgt := callPersisted(t, s, "SaveTarget", &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn, Kind: "windows", Domain: "EXAMPLE"},
	}, s.SaveTarget).GetTarget().GetId()
	id := callPersisted(t, s, "CreateSecret", &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "domain admin", FolderId: folder, TypeId: "type-windows-domain", TargetId: tgt,
		Fields: map[string]string{"domain": "EXAMPLE", "username": "renamed-admin", "password": "Init1alP@ss"},
	}, s.CreateSecret).GetSecret().GetId()

	callPersisted(t, s, "ReportHeartbeat", heartbeatReport(id, ptr(true), ptr(true)), s.ReportHeartbeat)

	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sec := s2.findSecret(id)
	if !sec.GetBuiltinAdministrator() || !sec.GetAdminCount() {
		t.Fatalf("flags after restart: builtin=%v adminCount=%v, want both true", sec.GetBuiltinAdministrator(), sec.GetAdminCount())
	}
	ev := ca.find("secret.account_flags")
	if ev == nil || ev.Attributes["builtin_administrator"] != "true" || ev.Attributes["admin_count"] != "true" {
		t.Fatalf("flag change must be audited with both flags: %+v", ev)
	}
}

func TestReportHeartbeat_BuiltinAdministratorStopsRotationNotHeartbeat(t *testing.T) {
	fx := newBuiltinAdminFixture(t)

	fx.heartbeat(t, ptr(true), ptr(false))

	if fx.hasRotationRow(t) {
		t.Fatal("the built-in Administrator must have no rotation schedule")
	}
	if !fx.hasHeartbeatRow(t) {
		t.Fatal("heartbeat must stay scheduled for the built-in Administrator")
	}
	if got := fx.secret().GetLastHeartbeatResult(); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
		t.Fatalf("heartbeat result = %v, want OK recorded as usual", got)
	}
}

func TestReportHeartbeat_UnsetFlagsKeepWhatWasRecorded(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	fx.heartbeat(t, ptr(true), ptr(true))

	fx.heartbeat(t, nil, nil)

	if sec := fx.secret(); !sec.GetBuiltinAdministrator() || !sec.GetAdminCount() {
		t.Fatal("a heartbeat that could not read the flags must not clear them")
	}
}

func TestReportHeartbeat_ClearedBuiltinAdministratorSchedulesRotationAgain(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	fx.heartbeat(t, ptr(true), ptr(false))

	fx.heartbeat(t, ptr(false), ptr(false))

	if fx.secret().GetBuiltinAdministrator() {
		t.Fatal("flag should clear when the connector reports the account is not RID 500")
	}
	if !fx.hasRotationRow(t) {
		t.Fatal("rotation should be scheduled again once the flag clears")
	}
}

func TestAdminCountAloneStillRotates(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	fx.heartbeat(t, ptr(false), ptr(true))

	if !fx.secret().GetAdminCount() {
		t.Fatal("admin_count should be recorded")
	}
	if _, err := fx.s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: fx.id, Reason: "manual"}); err != nil {
		t.Fatalf("EnqueueRotation: %v", err)
	}
	if !fx.claimed(t) {
		t.Fatal("an adminCount=1 account that is not RID 500 must still be rotated")
	}
}

func TestClaimDueRotations_NeverHandsOutBuiltinAdministrator(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	fx.heartbeat(t, ptr(true), ptr(true))
	// A row left over from before the flag was known.
	if err := fx.s.rot.Enqueue(context.Background(), fx.id, "manual", 30); err != nil {
		t.Fatal(err)
	}

	if fx.claimed(t) {
		t.Fatal("the built-in Administrator must never be handed to the connector")
	}
	if fx.hasRotationRow(t) {
		t.Fatal("the claimed row must be removed so it is not retried")
	}
}

func TestEnqueueRotation_BuiltinAdministrator(t *testing.T) {
	t.Run("manual is refused", func(t *testing.T) {
		fx := newBuiltinAdminFixture(t)
		fx.heartbeat(t, ptr(true), ptr(false))

		_, err := fx.s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: fx.id, Reason: "manual"})

		if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), builtinAdministratorReason) {
			t.Fatalf("want FailedPrecondition %q, got %v", builtinAdministratorReason, err)
		}
		if fx.hasRotationRow(t) {
			t.Fatal("a refused enqueue must not schedule anything")
		}
		if ev := fx.ca.find("rotate.refused"); ev == nil || ev.Attributes["reason"] != builtinAdministratorReason {
			t.Fatalf("the refusal must be audited with the reason: %+v", ev)
		}
	})
	for _, trigger := range []string{"checkin", "break-glass"} {
		t.Run(trigger+" is skipped", func(t *testing.T) {
			fx := newBuiltinAdminFixture(t)
			fx.heartbeat(t, ptr(true), ptr(false))

			resp, err := fx.s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{
				Actor: &vaultv1.ActorContext{IsRoot: true, UserId: "system-rotation"}, SecretId: fx.id, Reason: trigger,
			})

			if err != nil || !resp.GetOk() {
				t.Fatalf("a %s rotation must skip without failing the saga (the lease still closes): %v", trigger, err)
			}
			if fx.hasRotationRow(t) {
				t.Fatal("a skipped rotation must not schedule anything")
			}
			ev := fx.ca.find("rotate.skip")
			if ev == nil || ev.Attributes["reason"] != builtinAdministratorReason || ev.Attributes["trigger"] != trigger {
				t.Fatalf("the skip must be audited with the reason and trigger: %+v", ev)
			}
			if fx.ca.find("rotate.enqueue") != nil {
				t.Fatal("a skipped rotation must not be audited as enqueued")
			}
		})
	}
}

func TestReportRotation_BuiltinAdministratorDiscardsStagingAndStops(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	ctx := context.Background()
	// Claimed and staged before vault knows the account is RID 500.
	_, version := revealNewVer(t, fx.s, fx.id)

	callPersisted(t, fx.s, "ReportRotation", &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: fx.id,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, Validate: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED,
		Detail: builtinAdministratorReason, Version: version, BuiltinAdministrator: ptr(true),
	}, fx.s.ReportRotation)

	if !fx.secret().GetBuiltinAdministrator() {
		t.Fatal("the refused rotation must record the flag")
	}
	if fx.hasRotationRow(t) {
		t.Fatal("no retry: the rotation schedule must be removed")
	}
	if _, staged, _, err := fx.s.vers.VersionStatus(ctx, fx.id, int(version)); err != nil || staged {
		t.Fatalf("the staged credential must be discarded (staged=%v err=%v)", staged, err)
	}
	if got := activePassword(t, fx.s, fx.id); got != "Init1alP@ss" {
		t.Fatal("the active credential must stay the original one")
	}
	if ev := fx.ca.find("rotate.refused"); ev == nil || ev.Attributes["reason"] != builtinAdministratorReason {
		t.Fatalf("the refusal must be audited with the reason: %+v", ev)
	}
	if fx.ca.find("secret.rotation.failed") != nil {
		t.Fatal("a refusal is not a failure")
	}
	if !fx.hasHeartbeatRow(t) {
		t.Fatal("heartbeat must stay scheduled")
	}
}

func TestSetSecretAutomation_RefusesTurningRotationOnForBuiltinAdministrator(t *testing.T) {
	setters := map[string]func(fx *builtinAdminFixture, disableRotation, disableHeartbeat bool) error{
		"SetSecretAutomation": func(fx *builtinAdminFixture, r, h bool) error {
			_, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
				Actor: orgCarol, SecretId: fx.id, DisableRotation: r, DisableHeartbeat: h,
			})
			return err
		},
		"SetSecretAutomationForPrincipal": func(fx *builtinAdminFixture, r, h bool) error {
			_, err := fx.s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), SecretId: fx.id, DisableRotation: r, DisableHeartbeat: h,
			})
			return err
		},
	}
	for name, set := range setters {
		t.Run(name, func(t *testing.T) {
			fx := newBuiltinAdminFixture(t)
			fx.heartbeat(t, ptr(true), ptr(false))

			if err := set(fx, false, true); err != nil {
				t.Fatalf("a heartbeat change that leaves rotation as it is must be allowed: %v", err)
			}
			if err := set(fx, true, false); err != nil {
				t.Fatalf("opting out of rotation must be allowed: %v", err)
			}
			err := set(fx, false, false)
			if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), builtinAdministratorReason) {
				t.Fatalf("want FailedPrecondition %q, got %v", builtinAdministratorReason, err)
			}
			if !fx.secret().GetRotationOptOut() {
				t.Fatal("a refused request must change nothing")
			}
			if fx.hasRotationRow(t) {
				t.Fatal("a refused request must not schedule rotation")
			}
		})
	}
}

func TestBreakGlass_NoPostRotationForBuiltinAdministrator(t *testing.T) {
	fx := newBuiltinAdminFixture(t)
	fx.heartbeat(t, ptr(true), ptr(false))

	if _, err := fx.s.BreakGlassSecret(context.Background(), &vaultv1.BreakGlassSecretRequest{
		Actor: orgCarol, SecretId: fx.id, Reason: "outage",
	}); err != nil {
		t.Fatalf("BreakGlassSecret: %v", err)
	}
	if fx.hasRotationRow(t) {
		t.Fatal("break-glass must not queue a rotation for the built-in Administrator")
	}
}
