// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

func linkedConnection(t *testing.T, s *Server) *vaultv1.Connection {
	t.Helper()
	resp, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{
			Name: "AD LDAPS", Protocol: "ldap", Port: 636, UseTls: true,
			TargetId: "tgt-dc1", PrivilegedSecretId: "sec-priv", Bootstrap: true,
		},
	})
	if err != nil {
		t.Fatalf("create SaveConnection: %v", err)
	}
	return resp.GetConnection()
}

func listedConnection(t *testing.T, s *Server, id string) *vaultv1.Connection {
	t.Helper()
	resp, err := s.ListConnections(context.Background(), &vaultv1.ListConnectionsRequest{})
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	for _, c := range resp.GetConnections() {
		if c.GetId() == id {
			return c
		}
	}
	t.Fatalf("connection %s not listed", id)
	return nil
}

// The gateway's ConnectionInput carries only name, protocol, port, TLS and
// description, so an edit from the admin app arrives with the linkage empty.
func TestSaveConnectionUpdateKeepsLinkageTheCallerOmits(t *testing.T) {
	s := newServer(t)
	conn := linkedConnection(t, s)

	if _, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{
			Id: conn.GetId(), Name: "AD LDAPS", Protocol: "ldap", Port: 3269, UseTls: true,
		},
	}); err != nil {
		t.Fatalf("update SaveConnection: %v", err)
	}

	got := listedConnection(t, s, conn.GetId())
	if got.GetPort() != 3269 {
		t.Errorf("port = %d, want 3269", got.GetPort())
	}
	if got.GetPrivilegedSecretId() != "sec-priv" {
		t.Errorf("privileged_secret_id = %q, want sec-priv", got.GetPrivilegedSecretId())
	}
	if got.GetTargetId() != "tgt-dc1" {
		t.Errorf("target_id = %q, want tgt-dc1", got.GetTargetId())
	}
	if !got.GetBootstrap() {
		t.Error("bootstrap was cleared by the update")
	}
}

func TestSaveConnectionUpdateAppliesNewLinkage(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	conn := linkedConnection(t, s)

	if _, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{
			Id: conn.GetId(), Name: "AD LDAPS", Protocol: "ldap", Port: 636, UseTls: true,
			TargetId: "tgt-dc2", PrivilegedSecretId: "sec-gmsa",
		},
	}); err != nil {
		t.Fatalf("update SaveConnection: %v", err)
	}

	got := listedConnection(t, s, conn.GetId())
	if got.GetPrivilegedSecretId() != "sec-gmsa" {
		t.Errorf("privileged_secret_id = %q, want sec-gmsa", got.GetPrivilegedSecretId())
	}
	if got.GetTargetId() != "tgt-dc2" {
		t.Errorf("target_id = %q, want tgt-dc2", got.GetTargetId())
	}

	ev := ca.find("connection.privileged_secret.change")
	if ev == nil {
		t.Fatal("changing privileged_secret_id was not audited")
	}
	if ev.Subject != conn.GetId() || ev.Sensitive {
		t.Errorf("audit subject=%q sensitive=%v, want %q and false", ev.Subject, ev.Sensitive, conn.GetId())
	}
	if ev.Attributes["from"] != "sec-priv" || ev.Attributes["to"] != "sec-gmsa" {
		t.Errorf("audit attrs = %v, want from=sec-priv to=sec-gmsa", ev.Attributes)
	}
}

func TestSaveConnectionUpdateWithoutPrivilegedChangeIsNotAuditedAsOne(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	conn := linkedConnection(t, s)

	for _, priv := range []string{"", "sec-priv"} {
		if _, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
			Actor: siteAdmin, Connection: &vaultv1.Connection{
				Id: conn.GetId(), Name: "AD LDAPS", Protocol: "ldap", Port: 636, PrivilegedSecretId: priv,
			},
		}); err != nil {
			t.Fatalf("update SaveConnection: %v", err)
		}
	}
	if ca.find("connection.privileged_secret.change") != nil {
		t.Error("an update that keeps privileged_secret_id was audited as a change")
	}
}

// The rotate-the-rotator guard reads privileged_secret_id from the stored
// connection, so a privileged secret linked by an update must be held while a
// managed peer rotates, and stay held after a later edit that omits it.
func TestRotationGuardHoldsPrivilegedSecretLinkedByUpdate(t *testing.T) {
	s, _, privID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	priv := findByID(s.secrets, privID)
	tgt := findByID(s.targets, priv.GetTargetId())
	connID := tgt.GetConnectionId()
	peer, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc-peer", FolderId: priv.GetFolderId(), TypeId: "type-windows-domain",
		TargetId: tgt.GetId(),
		Fields:   map[string]string{"domain": "SNEAKERS", "username": "svc-peer", "password": "OldP@ss2"},
	})
	if err != nil {
		t.Fatalf("CreateSecret peer: %v", err)
	}
	peerID := peer.GetSecret().GetId()

	save := func(c *vaultv1.Connection) {
		t.Helper()
		c.Id, c.Name, c.Protocol, c.UseTls = connID, "AD LDAPS", "ldap", true
		if _, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{Actor: siteAdmin, Connection: c}); err != nil {
			t.Fatalf("update SaveConnection: %v", err)
		}
	}
	save(&vaultv1.Connection{Port: 636, PrivilegedSecretId: privID})
	save(&vaultv1.Connection{Port: 3269})

	if err := s.rot.Enqueue(ctx, peerID, "manual", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rot.ClaimDue(ctx, 10, rotClaimTTL); err != nil {
		t.Fatal(err)
	}
	if inflight, err := s.rot.InFlightOnConnection(ctx, []string{peerID}); err != nil || !inflight {
		t.Fatalf("peer not in flight: %v, %v", inflight, err)
	}
	unclaimed := rotState(vaultv1.RotationState_ROTATION_STATE_UNSPECIFIED)
	if err := s.rot.Reschedule(ctx, privID, time.Now().Add(-time.Second), unclaimed); err != nil {
		t.Fatal(err)
	}

	claimJobs := func() map[string]bool {
		t.Helper()
		resp, err := s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
		if err != nil {
			t.Fatalf("ClaimDueRotations: %v", err)
		}
		out := map[string]bool{}
		for _, j := range resp.GetJobs() {
			out[j.GetSecretId()] = true
		}
		return out
	}
	if claimJobs()[privID] {
		t.Fatal("privileged secret was handed out while a managed peer is mid-rotation")
	}

	if err := s.rot.Reschedule(ctx, peerID, time.Now().Add(time.Hour), unclaimed); err != nil {
		t.Fatal(err)
	}
	if err := s.rot.Reschedule(ctx, privID, time.Now().Add(-time.Second), unclaimed); err != nil {
		t.Fatal(err)
	}
	if !claimJobs()[privID] {
		t.Fatal("privileged secret was not handed out once its peers settled")
	}
}
