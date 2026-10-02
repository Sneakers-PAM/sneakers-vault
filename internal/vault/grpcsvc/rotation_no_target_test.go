// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A rotating-type secret only gets a rotation_schedule row once it has a
// target whose connection exists: without one the connector has nothing to
// rotate against, and a row would be claimed forever and never complete.

type noTargetFixture struct {
	s      *Server
	ca     *capAudit
	folder string
	target string
	conn   string
}

// reachableTarget saves a connection and a shared target bound to it,
// returning both ids.
func reachableTarget(t *testing.T, s *Server) (targetID, connID string) {
	t.Helper()
	ctx := context.Background()
	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "Directory LDAPS", Protocol: "ldap", Port: 636, UseTls: true},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	tgt, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn.GetConnection().GetId(),
			Kind: "windows", Domain: "EXAMPLE", Realm: "EXAMPLE.ORG",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	return tgt.GetTarget().GetId(), conn.GetConnection().GetId()
}

func newNoTargetFixture(t *testing.T) *noTargetFixture {
	t.Helper()
	_, pool := organizeFreshDB(t)
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.SetHeartbeat(pool, nil)
	s.SetRotation(pool, nil)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	f := authorFolder(t, s)
	tgt, conn := reachableTarget(t, s)
	return &noTargetFixture{s: s, ca: ca, folder: f, target: tgt, conn: conn}
}

// dropConnection makes the fixture's target dangle: its connection is gone.
func (fx *noTargetFixture) dropConnection() {
	fx.s.mu.Lock()
	defer fx.s.mu.Unlock()
	fx.s.connections = removeByID(fx.s.connections, fx.conn)
}

func (fx *noTargetFixture) createHuman(t *testing.T, targetID string) string {
	t.Helper()
	c, err := fx.s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "svc", FolderId: fx.folder, TypeId: "type-windows-domain", TargetId: targetID,
		Fields: map[string]string{"domain": "EXAMPLE", "username": "svc", "password": "Init1alP@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return c.GetSecret().GetId()
}

func (fx *noTargetFixture) hasRow(t *testing.T, id string) bool {
	t.Helper()
	ok, err := fx.s.rot.Exists(context.Background(), id)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	return ok
}

func TestRotationSchedule_NotCreatedWithoutTargetOrConnection(t *testing.T) {
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
		"GenerateSecretForPrincipal": func(t *testing.T, fx *noTargetFixture, targetID string) string {
			r, err := fx.s.GenerateSecretForPrincipal(context.Background(), &vaultv1.GenerateSecretForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Name: "svc", FolderId: fx.folder, TypeId: "type-windows-domain", TargetId: targetID,
				Fields: map[string]string{"domain": "EXAMPLE", "username": "svc"},
			})
			if err != nil {
				t.Fatalf("GenerateSecretForPrincipal: %v", err)
			}
			return r.GetSecret().GetId()
		},
	}
	for cname, target := range cases {
		for crname, create := range creators {
			t.Run(cname+"/"+crname, func(t *testing.T) {
				fx := newNoTargetFixture(t)
				if cname == "unknown target" && crname != "CreateSecret" {
					// A principal may only name a target it can see, so an unknown
					// one is refused before any schedule row could exist.
					principalCreateRefusesUnknownTarget(t, fx, crname)
					return
				}
				id := create(t, fx, target(fx))
				if fx.hasRow(t, id) {
					t.Fatal("a rotating secret without a reachable target must not get a rotation_schedule row")
				}
			})
		}
	}
}

func TestRotationSchedule_CreatedWithTargetAndConnection(t *testing.T) {
	fx := newNoTargetFixture(t)
	if id := fx.createHuman(t, fx.target); !fx.hasRow(t, id) {
		t.Fatal("a rotating secret with a reachable target should be scheduled at create")
	}
}

func TestRotationSchedule_CreatedWhenTargetAttachedByUpdate(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, TargetId: fx.target,
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if !fx.hasRow(t, id) {
		t.Fatal("attaching a reachable target should create the rotation_schedule row")
	}
}

func TestRotationSchedule_CreatedWhenTargetAttachedByPrincipal(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.SetSecretTargetForPrincipal(context.Background(), &vaultv1.SetSecretTargetForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id, TargetId: fx.target,
	}); err != nil {
		t.Fatalf("SetSecretTargetForPrincipal: %v", err)
	}
	if !fx.hasRow(t, id) {
		t.Fatal("attaching a reachable target should create the rotation_schedule row")
	}
}

func TestRotationSchedule_NotCreatedWhenAttachedTargetHasNoConnection(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	fx.dropConnection()
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, TargetId: fx.target,
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if fx.hasRow(t, id) {
		t.Fatal("a target without a connection must not create the rotation_schedule row")
	}
}

func TestRotationSchedule_NotCreatedOnOptBackInWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	ctx := context.Background()
	for _, off := range []bool{true, false} {
		if _, err := fx.s.SetSecretAutomation(ctx, &vaultv1.SetSecretAutomationRequest{
			Actor: orgCarol, SecretId: id, DisableRotation: off,
		}); err != nil {
			t.Fatalf("SetSecretAutomation(%v): %v", off, err)
		}
	}
	if fx.hasRow(t, id) {
		t.Fatal("opting back in without a reachable target must not create the rotation_schedule row")
	}
}

func TestRotationSchedule_NotCreatedOnRetypeWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := mutSecret(t, fx.s, fx.folder)
	if _, err := fx.s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-active-directory",
		Fields: map[string]string{"domain": "example.org"},
	}); err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	if fx.hasRow(t, id) {
		t.Fatal("a retype into a rotating type without a reachable target must not create the rotation_schedule row")
	}
}

func TestClaimDueRotations_RemovesRowWithoutTargetOrConnection(t *testing.T) {
	cases := map[string]func(t *testing.T, fx *noTargetFixture, id string){
		"target detached": func(t *testing.T, fx *noTargetFixture, id string) {
			fx.s.mu.Lock()
			fx.s.findSecret(id).TargetId = ""
			fx.s.mu.Unlock()
		},
		"connection gone": func(_ *testing.T, fx *noTargetFixture, _ string) { fx.dropConnection() },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newNoTargetFixture(t)
			ctx := context.Background()
			id := fx.createHuman(t, fx.target)
			if _, err := fx.s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: id, Reason: "manual"}); err != nil {
				t.Fatalf("EnqueueRotation: %v", err)
			}
			breakIt(t, fx, id)

			resp, err := fx.s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
			if err != nil {
				t.Fatalf("ClaimDueRotations: %v", err)
			}
			for _, j := range resp.GetJobs() {
				if j.GetSecretId() == id {
					t.Fatal("an unreachable secret must not be handed to the connector")
				}
			}
			if fx.hasRow(t, id) {
				t.Fatal("the claimed row of an unreachable secret must be removed, not left rotating")
			}
		})
	}
}

func TestEnqueueRotation_FailsWithoutTargetOrConnection(t *testing.T) {
	cases := map[string]func(t *testing.T, fx *noTargetFixture) string{
		"no target": func(t *testing.T, fx *noTargetFixture) string { return fx.createHuman(t, "") },
		"target no connection": func(t *testing.T, fx *noTargetFixture) string {
			id := fx.createHuman(t, fx.target)
			if err := fx.s.rot.Remove(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			fx.dropConnection()
			return id
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newNoTargetFixture(t)
			id := mk(t, fx)
			_, err := fx.s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: id, Reason: "manual"})
			if code(err) != codes.FailedPrecondition {
				t.Fatalf("want FailedPrecondition, got %v", err)
			}
			if !strings.Contains(err.Error(), "target") {
				t.Fatalf("error should say the secret needs a target: %v", err)
			}
			if fx.hasRow(t, id) {
				t.Fatal("a refused enqueue must not create a rotation_schedule row")
			}
			if fx.ca.find("rotate.enqueue") != nil {
				t.Fatal("a refused enqueue must not be audited as rotate.enqueue")
			}
		})
	}
}

func TestBreakGlass_NoPostRotationWithoutTarget(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, "")
	if _, err := fx.s.BreakGlassSecret(context.Background(), &vaultv1.BreakGlassSecretRequest{
		Actor: orgCarol, SecretId: id, Reason: "outage",
	}); err != nil {
		t.Fatalf("BreakGlassSecret: %v", err)
	}
	if fx.hasRow(t, id) {
		t.Fatal("break-glass must not enqueue a rotation for a secret without a reachable target")
	}
}

func TestClaimDueRotations_RemovesRowOfDeletedRetiredOrNonRotatingSecret(t *testing.T) {
	cases := map[string]func(t *testing.T, fx *noTargetFixture, id string){
		"deleted": func(t *testing.T, fx *noTargetFixture, id string) {
			if _, err := fx.s.DeleteSecret(context.Background(), &vaultv1.DeleteSecretRequest{Actor: orgCarol, Id: id}); err != nil {
				t.Fatalf("DeleteSecret: %v", err)
			}
		},
		"retired": func(t *testing.T, fx *noTargetFixture, id string) {
			if _, err := fx.s.RetireSecret(context.Background(), &vaultv1.RetireSecretRequest{Actor: orgCarol, Id: id}); err != nil {
				t.Fatalf("RetireSecret: %v", err)
			}
		},
		"no longer rotation-capable": func(_ *testing.T, fx *noTargetFixture, _ string) {
			fx.s.mu.Lock()
			defer fx.s.mu.Unlock()
			fx.s.findType("type-windows-domain").Rotation = false
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newNoTargetFixture(t)
			ctx := context.Background()
			id := fx.createHuman(t, fx.target)
			if _, err := fx.s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: id, Reason: "manual"}); err != nil {
				t.Fatalf("EnqueueRotation: %v", err)
			}
			change(t, fx, id)
			resp, err := fx.s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
			if err != nil {
				t.Fatalf("ClaimDueRotations: %v", err)
			}
			for _, j := range resp.GetJobs() {
				if j.GetSecretId() == id {
					t.Fatal("the secret must not be handed to the connector")
				}
			}
			if fx.hasRow(t, id) {
				t.Fatal("the claimed row must be removed, not left rotating")
			}
		})
	}
}

func TestRestoreSecret_ReschedulesRotation(t *testing.T) {
	fx := newNoTargetFixture(t)
	ctx := context.Background()
	id := fx.createHuman(t, fx.target)
	if _, err := fx.s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: orgCarol, Id: id}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	if err := fx.s.rot.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.s.RestoreSecret(ctx, &vaultv1.RestoreSecretRequest{Actor: orgCarol, Id: id}); err != nil {
		t.Fatalf("RestoreSecret: %v", err)
	}
	if !fx.hasRow(t, id) {
		t.Fatal("restoring a rotating secret with a reachable target must schedule it again")
	}
}

func principalCreateRefusesUnknownTarget(t *testing.T, fx *noTargetFixture, creator string) {
	t.Helper()
	var err error
	if creator == "CreateSecretForPrincipal" {
		_, err = fx.s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
			Actor: agentGroupActor("sa-1"), Name: "svc", FolderId: fx.folder, TypeId: "type-windows-domain", TargetId: "target-does-not-exist",
			Fields: map[string]string{"domain": "EXAMPLE", "username": "svc", "password": "Init1alP@ss"},
		})
	} else {
		_, err = fx.s.GenerateSecretForPrincipal(context.Background(), &vaultv1.GenerateSecretForPrincipalRequest{
			Actor: agentGroupActor("sa-1"), Name: "svc", FolderId: fx.folder, TypeId: "type-windows-domain", TargetId: "target-does-not-exist",
			Fields: map[string]string{"domain": "EXAMPLE", "username": "svc"},
		})
	}
	if status.Code(err) != codes.NotFound {
		t.Fatalf("%s with an unknown target: want NotFound, got %v", creator, err)
	}
}
