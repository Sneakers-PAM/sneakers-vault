// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// automationTarget saves an LDAPS connection and a target bound to it, so a
// rotation-capable secret pointed at it is a real rotation candidate.
func automationTarget(t *testing.T, s *Server) string {
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
	return tgt.GetTarget().GetId()
}

func TestSetSecretAutomationForPrincipal_AllowedTogglesAndAudits(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := mutFolder(t, s, "Ops")
	grantGroup(t, s, carol, fid, "R")
	id := mutSecret(t, s, fid)
	actor := agentGroupActor("sa-1")
	actor.TokenId = "tok-1"

	resp, err := s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: actor, SecretId: id, DisableRotation: true, DisableHeartbeat: true,
	})
	if err != nil {
		t.Fatalf("SetSecretAutomationForPrincipal: %v", err)
	}
	if !resp.GetSecret().GetRotationOptOut() || !resp.GetSecret().GetHeartbeatOptOut() {
		t.Fatalf("opt-outs not set: %+v", resp.GetSecret())
	}
	for _, action := range []string{"secret.rotation.disable.principal", "secret.heartbeat.disable.principal"} {
		ev := ca.find(action)
		if ev == nil {
			t.Fatalf("expected a %s audit event", action)
		}
		if ev.ActorUserID != "sa-1" || ev.Subject != id || ev.Attributes["principal_id"] != "sa-1" || ev.Attributes["token_id"] != "tok-1" {
			t.Fatalf("%s audit not attributed to the principal: %+v", action, ev)
		}
	}

	if _, err := s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: actor, SecretId: id,
	}); err != nil {
		t.Fatalf("opt back in: %v", err)
	}
	sec := s.findSecret(id)
	if sec.GetRotationOptOut() || sec.GetHeartbeatOptOut() {
		t.Fatalf("opt-outs not cleared: %+v", sec)
	}
	if ca.find("secret.rotation.enable.principal") == nil || ca.find("secret.heartbeat.enable.principal") == nil {
		t.Fatal("expected enable audit events on opt back in")
	}
}

func TestSetSecretAutomationForPrincipal_NoChangeNoAudit(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := mutFolder(t, s, "Ops")
	grantGroup(t, s, carol, fid, "R")
	id := mutSecret(t, s, fid)

	if _, err := s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id,
	}); err != nil {
		t.Fatalf("SetSecretAutomationForPrincipal: %v", err)
	}
	for _, action := range []string{"secret.rotation.enable.principal", "secret.heartbeat.enable.principal"} {
		if ca.find(action) != nil {
			t.Fatalf("an unchanged flag must not be audited as %s", action)
		}
	}
}

func TestSetSecretAutomationForPrincipal_Denials(t *testing.T) {
	cases := []struct {
		name  string
		grant string
		actor *vaultv1.ActorContext
		want  codes.Code
	}{
		{name: "no author right (read only)", grant: "C", actor: agentGroupActor("sa-1"), want: codes.PermissionDenied},
		{name: "no grant at all", actor: agentGroupActor("sa-1"), want: codes.PermissionDenied},
		{name: "human caller", grant: "R", actor: &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true}, want: codes.PermissionDenied},
		{name: "service account with spoofed admin flags", actor: &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-evil",
			UserId: "user-carol", IsSiteAdmin: true, IsRoot: true,
		}, want: codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			carol := &vaultv1.ActorContext{UserId: "user-carol"}
			fid := mutFolder(t, s, "Ops")
			if tc.grant != "" {
				grantGroup(t, s, carol, fid, tc.grant)
			}
			id := mutSecret(t, s, fid)
			_, err := s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
				Actor: tc.actor, SecretId: id, DisableRotation: true,
			})
			if code(err) != tc.want {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if s.findSecret(id).GetRotationOptOut() {
				t.Fatal("a denied call must not change the secret")
			}
			if ca.find("secret.rotation.disable.principal") != nil {
				t.Fatal("a denied call must not audit a change")
			}
		})
	}
}

func TestSetSecretAutomationForPrincipal_UnknownSecret(t *testing.T) {
	s := newServer(t)
	_, err := s.SetSecretAutomationForPrincipal(context.Background(), &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: "secret-does-not-exist", DisableRotation: true,
	})
	if code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestSetSecretAutomationIsPersisted(t *testing.T) {
	if !mutatingMethods["SetSecretAutomationForPrincipal"] {
		t.Fatal("SetSecretAutomationForPrincipal changes state and must be in mutatingMethods")
	}
}

// automationPGServer is a mem-backed server with pg rotation + heartbeat stores
// and a shared folder where g-agents holds Author.
func automationPGServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	pool := rotTestPool(t)
	hbPool := hbTestPool(t)
	s := newServer(t)
	s.rot = newRotationStore(pool.Querier())
	s.hb = newHeartbeatStore(hbPool.Querier())
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := mutFolder(t, s, "Ops")
	grantGroup(t, s, carol, fid, "R")
	return s, fid, automationTarget(t, s)
}

func scheduleRows(t *testing.T, s *Server, id string) (rot, hb bool) {
	t.Helper()
	ctx := context.Background()
	rot, err := s.rot.Exists(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	hb, err = s.hb.Exists(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return rot, hb
}

func TestCreateSecretForPrincipal_OptOutCreatesNoScheduleRows(t *testing.T) {
	s, fid, tgt := automationPGServer(t)
	resp, err := s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Name: "recovery-admin", FolderId: fid, TypeId: "type-windows-domain", TargetId: tgt,
		Fields:          map[string]string{"domain": "EXAMPLE", "username": "recovery-admin", "password": "Init1alP@ss"},
		DisableRotation: true, DisableHeartbeat: true,
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sec := resp.GetSecret()
	if !sec.GetRotationOptOut() || !sec.GetHeartbeatOptOut() {
		t.Fatalf("opt-outs not set on create: %+v", sec)
	}
	if rot, hb := scheduleRows(t, s, sec.GetId()); rot || hb {
		t.Fatalf("opted-out secret has schedule rows: rotation=%v heartbeat=%v", rot, hb)
	}
}

func TestGenerateSecretForPrincipal_OptOutCreatesNoScheduleRows(t *testing.T) {
	s, fid, tgt := automationPGServer(t)
	resp, err := s.GenerateSecretForPrincipal(context.Background(), &vaultv1.GenerateSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Name: "recovery-admin", FolderId: fid, TypeId: "type-windows-domain", TargetId: tgt,
		Fields:          map[string]string{"domain": "EXAMPLE", "username": "recovery-admin"},
		DisableRotation: true, DisableHeartbeat: true,
	})
	if err != nil {
		t.Fatalf("GenerateSecretForPrincipal: %v", err)
	}
	sec := resp.GetSecret()
	if !sec.GetRotationOptOut() || !sec.GetHeartbeatOptOut() {
		t.Fatalf("opt-outs not set on generate: %+v", sec)
	}
	if rot, hb := scheduleRows(t, s, sec.GetId()); rot || hb {
		t.Fatalf("opted-out secret has schedule rows: rotation=%v heartbeat=%v", rot, hb)
	}
}

func TestSetSecretAutomationForPrincipal_OptOutAndBackInManagesScheduleRows(t *testing.T) {
	s, fid, tgt := automationPGServer(t)
	ctx := context.Background()
	actor := agentGroupActor("sa-1")
	resp, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: actor, Name: "svc", FolderId: fid, TypeId: "type-windows-domain", TargetId: tgt,
		Fields: map[string]string{"domain": "EXAMPLE", "username": "svc", "password": "Init1alP@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	id := resp.GetSecret().GetId()
	if rot, hb := scheduleRows(t, s, id); !rot || !hb {
		t.Fatalf("setup: expected both schedule rows, rotation=%v heartbeat=%v", rot, hb)
	}

	if _, err := s.SetSecretAutomationForPrincipal(ctx, &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: actor, SecretId: id, DisableRotation: true, DisableHeartbeat: true,
	}); err != nil {
		t.Fatalf("opt out: %v", err)
	}
	if rot, hb := scheduleRows(t, s, id); rot || hb {
		t.Fatalf("opt-out left schedule rows: rotation=%v heartbeat=%v", rot, hb)
	}

	if _, err := s.SetSecretAutomationForPrincipal(ctx, &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: actor, SecretId: id,
	}); err != nil {
		t.Fatalf("opt back in: %v", err)
	}
	if rot, hb := scheduleRows(t, s, id); !rot || !hb {
		t.Fatalf("opt back in did not restore schedule rows: rotation=%v heartbeat=%v", rot, hb)
	}
}
