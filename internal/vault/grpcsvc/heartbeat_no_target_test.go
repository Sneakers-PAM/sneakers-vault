// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A heartbeat-capable secret only gets a heartbeat_schedule row once it has a
// target whose connection exists: without one the connector can only report
// UNREACHABLE, and three of those in a row raise a false alert.

func (fx *noTargetFixture) hasHBRow(t *testing.T, id string) bool {
	t.Helper()
	ok, err := fx.s.hb.Exists(context.Background(), id)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	return ok
}

func TestHeartbeatSchedule_NotCreatedWithoutTargetOrConnection(t *testing.T) {
	cases := map[string]func(fx *noTargetFixture) string{
		"no target":         func(*noTargetFixture) string { return "" },
		"unknown target":    func(*noTargetFixture) string { return "target-does-not-exist" },
		"target no connect": func(fx *noTargetFixture) string { fx.dropConnection(); return fx.target },
	}
	creators := map[string]func(t *testing.T, fx *noTargetFixture, targetID string) string{
		"CreateSecret": func(t *testing.T, fx *noTargetFixture, targetID string) string {
			return fx.createHuman(t, targetID)
		},
		"CreateSecretForPrincipal": func(t *testing.T, fx *noTargetFixture, targetID string) string {
			r, err := fx.s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Name: "svc", FolderId: fx.folder, TypeId: "type-windows-domain", TargetId: targetID,
				Fields: map[string]string{"domain": "EXAMPLE", "username": "svc", "password": "Init1alP@ss"},
			})
			if err != nil {
				t.Fatalf("CreateSecretForPrincipal: %v", err)
			}
			return r.GetSecret().GetId()
		},
	}
	for cname, target := range cases {
		for crname, create := range creators {
			if cname == "unknown target" && crname != "CreateSecret" {
				// A principal may only name a target it can see.
				continue
			}
			t.Run(cname+"/"+crname, func(t *testing.T) {
				fx := newNoTargetFixture(t)
				id := create(t, fx, target(fx))
				if fx.hasHBRow(t, id) {
					t.Fatal("a heartbeat secret without a reachable target must not get a heartbeat_schedule row")
				}
			})
		}
	}
}

func TestHeartbeatSchedule_CreatedWithTargetAndConnection(t *testing.T) {
	fx := newNoTargetFixture(t)
	if id := fx.createHuman(t, fx.target); !fx.hasHBRow(t, id) {
		t.Fatal("a heartbeat secret with a reachable target should be scheduled at create")
	}
}

func TestHeartbeatSchedule_NotCreatedByUpdateWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Name: "svc-renamed",
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if fx.hasHBRow(t, id) {
		t.Fatal("an update that leaves the secret without a target must not create the heartbeat_schedule row")
	}
}

func TestHeartbeatSchedule_CreatedWhenTargetAttachedByUpdate(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, TargetId: fx.target,
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if !fx.hasHBRow(t, id) {
		t.Fatal("attaching a reachable target should create the heartbeat_schedule row")
	}
}

func TestHeartbeatSchedule_CreatedWhenTargetAttachedByPrincipal(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.SetSecretTargetForPrincipal(context.Background(), &vaultv1.SetSecretTargetForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id, TargetId: fx.target,
	}); err != nil {
		t.Fatalf("SetSecretTargetForPrincipal: %v", err)
	}
	if !fx.hasHBRow(t, id) {
		t.Fatal("attaching a reachable target should create the heartbeat_schedule row")
	}
}

func TestHeartbeatSchedule_NotCreatedOnOptBackInWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	ctx := context.Background()
	for _, off := range []bool{true, false} {
		if _, err := fx.s.SetSecretAutomation(ctx, &vaultv1.SetSecretAutomationRequest{
			Actor: orgCarol, SecretId: id, DisableHeartbeat: off,
		}); err != nil {
			t.Fatalf("SetSecretAutomation(%v): %v", off, err)
		}
	}
	if fx.hasHBRow(t, id) {
		t.Fatal("opting back in without a reachable target must not create the heartbeat_schedule row")
	}
}

func TestHeartbeatSchedule_NotCreatedOnRestoreWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	ctx := context.Background()
	id := fx.createHuman(t, "")
	if _, err := fx.s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: orgCarol, Id: id}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	if _, err := fx.s.RestoreSecret(ctx, &vaultv1.RestoreSecretRequest{Actor: orgCarol, Id: id}); err != nil {
		t.Fatalf("RestoreSecret: %v", err)
	}
	if fx.hasHBRow(t, id) {
		t.Fatal("restoring a secret without a reachable target must not create the heartbeat_schedule row")
	}
}

// A schedule row whose secret has no target, or whose target has no
// connection, must never reach the connector, or it reports UNREACHABLE and
// alerts on a secret it was never meant to check.
func TestClaimDueHeartbeats_RemovesExistingRowWithoutTargetOrConnection(t *testing.T) {
	cases := map[string]func(t *testing.T, fx *noTargetFixture) string{
		"no target": func(t *testing.T, fx *noTargetFixture) string { return fx.createHuman(t, "") },
		"target detached": func(t *testing.T, fx *noTargetFixture) string {
			id := fx.createHuman(t, fx.target)
			fx.s.mu.Lock()
			fx.s.findSecret(id).TargetId = ""
			fx.s.mu.Unlock()
			return id
		},
		"connection gone": func(t *testing.T, fx *noTargetFixture) string {
			id := fx.createHuman(t, fx.target)
			fx.dropConnection()
			return id
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newNoTargetFixture(t)
			ctx := context.Background()
			id := mk(t, fx)
			if err := fx.s.hb.Ensure(ctx, id, 300); err != nil {
				t.Fatal(err)
			}

			resp, err := fx.s.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
			if err != nil {
				t.Fatalf("ClaimDueHeartbeats: %v", err)
			}
			for _, j := range resp.GetJobs() {
				if j.GetSecretId() == id {
					t.Fatal("a secret without a reachable target must not be handed to the connector")
				}
			}
			if fx.hasHBRow(t, id) {
				t.Fatal("the claimed row of an unreachable secret must be removed, not re-claimed every TTL")
			}
			for i := 0; i < hbAlertAfterN; i++ {
				_, err := fx.s.ReportHeartbeat(ctx, &vaultv1.ReportHeartbeatRequest{
					Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: id,
					Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE,
				})
				if code(err) != codes.PermissionDenied {
					t.Fatalf("report %d for a dropped row: want PermissionDenied, got %v", i+1, err)
				}
			}
			if fx.ca.find("heartbeat.report") != nil {
				t.Fatal("no heartbeat report may be recorded for a secret without a reachable target")
			}
		})
	}
}

func TestClaimDueHeartbeats_KeepsRowWithTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	ctx := context.Background()
	id := fx.createHuman(t, fx.target)
	resp, err := fx.s.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
	if err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	if len(resp.GetJobs()) != 1 || resp.GetJobs()[0].GetSecretId() != id {
		t.Fatalf("jobs = %v, want the reachable secret", resp.GetJobs())
	}
	if !fx.hasHBRow(t, id) {
		t.Fatal("a reachable secret's row must stay after the claim")
	}
}

func TestRequestHeartbeat_FailsWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	ctx := context.Background()
	id := fx.createHuman(t, "")
	if err := fx.s.hb.Ensure(ctx, id, 300); err != nil {
		t.Fatal(err)
	}
	err := requestHB(fx.s, agentGroupActor("sa-1"), id)
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "target") {
		t.Fatalf("want FailedPrecondition naming the target, got %v", err)
	}
	if fx.ca.find("heartbeat.request.principal") != nil {
		t.Fatal("a refused request must not be audited as a request")
	}
}
