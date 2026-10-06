// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newConnection(t *testing.T, s *Server, protocol string, port int32) string {
	t.Helper()
	resp, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: protocol, Protocol: protocol, Port: port},
	})
	if err != nil {
		t.Fatalf("SaveConnection %s: %v", protocol, err)
	}
	return resp.GetConnection().GetId()
}

// A target saved with only the legacy connection_id (no connections list) is
// read back as a one-item default list, with no data lost.
func TestTargetWithLegacyConnectionIDMigratesToOneItemList(t *testing.T) {
	s := newServer(t)
	conn := newConnection(t, s, "ssh", 22)
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	tgt := listedTarget(t, s, siteAdmin, resp.GetTarget().GetId())
	if got := tgt.GetConnections(); len(got) != 1 || got[0].GetConnectionId() != conn || !got[0].GetIsDefault() {
		t.Fatalf("connections = %v, want one default entry for %s", got, conn)
	}
	if tgt.GetConnectionId() != conn {
		t.Fatalf("connection_id = %q, want %q", tgt.GetConnectionId(), conn)
	}
}

// A target can carry more than one connection, each a different protocol,
// with exactly one default; connection_id stays in sync with the default.
func TestTargetSavesAnOrderedConnectionList(t *testing.T) {
	s := newServer(t)
	ssh := newConnection(t, s, "ssh", 22)
	winrm := newConnection(t, s, "winrm", 5985)
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org",
			Connections: []*vaultv1.TargetConnection{
				{ConnectionId: ssh, IsDefault: false},
				{ConnectionId: winrm, IsDefault: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	tgt := listedTarget(t, s, siteAdmin, resp.GetTarget().GetId())
	got := tgt.GetConnections()
	if len(got) != 2 || got[0].GetConnectionId() != ssh || got[1].GetConnectionId() != winrm {
		t.Fatalf("connections = %v, want [%s, %s] in order", got, ssh, winrm)
	}
	if got[0].GetIsDefault() || !got[1].GetIsDefault() {
		t.Fatalf("connections = %v, want only %s default", got, winrm)
	}
	if tgt.GetConnectionId() != winrm {
		t.Fatalf("connection_id = %q, want the default %q", tgt.GetConnectionId(), winrm)
	}
}

// Two connections of the same protocol on one target are refused.
func TestTargetSaveRejectsDuplicateConnectorProtocol(t *testing.T) {
	s := newServer(t)
	sshA := newConnection(t, s, "ssh", 22)
	sshB := newConnection(t, s, "ssh", 2222)
	_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org",
			Connections: []*vaultv1.TargetConnection{{ConnectionId: sshA, IsDefault: true}, {ConnectionId: sshB}},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a duplicate protocol, got %v", err)
	}
}

// Marking more than one connection default, or none, is refused.
func TestTargetSaveRejectsBadDefaultCount(t *testing.T) {
	s := newServer(t)
	ssh := newConnection(t, s, "ssh", 22)
	winrm := newConnection(t, s, "winrm", 5985)
	for name, conns := range map[string][]*vaultv1.TargetConnection{
		"two defaults": {{ConnectionId: ssh, IsDefault: true}, {ConnectionId: winrm, IsDefault: true}},
		"no default":   {{ConnectionId: ssh}, {ConnectionId: winrm}},
	} {
		_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
			Actor: siteAdmin, Target: &vaultv1.Target{Name: "dc1", Hostname: "dc1.example.org", Connections: conns},
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", name, err)
		}
	}
}

// An edit sent with only the legacy connection_id, naming a connection the
// target already carries, moves the default without dropping the rest of
// the list.
func TestLegacyConnectionIDEditPreservesOtherConnections(t *testing.T) {
	s := newServer(t)
	ssh := newConnection(t, s, "ssh", 22)
	winrm := newConnection(t, s, "winrm", 5985)
	created, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org",
			Connections: []*vaultv1.TargetConnection{{ConnectionId: ssh, IsDefault: true}, {ConnectionId: winrm}},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Id: created.GetTarget().GetId(), Name: "dc1", Hostname: "dc1.example.org", ConnectionId: winrm,
		},
	})
	if err != nil {
		t.Fatalf("legacy edit: %v", err)
	}
	tgt := listedTarget(t, s, siteAdmin, created.GetTarget().GetId())
	got := tgt.GetConnections()
	if len(got) != 2 {
		t.Fatalf("connections = %v, want both to survive the legacy edit", got)
	}
	if tgt.GetConnectionId() != winrm {
		t.Fatalf("connection_id = %q, want the new default %q", tgt.GetConnectionId(), winrm)
	}
}

// A connection still named by any of a target's entries — default or not —
// can't be deleted.
func TestDeleteConnectionRefusedWhileAnyEntryBindsIt(t *testing.T) {
	s := newServer(t)
	ssh := newConnection(t, s, "ssh", 22)
	winrm := newConnection(t, s, "winrm", 5985)
	_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org",
			Connections: []*vaultv1.TargetConnection{{ConnectionId: ssh, IsDefault: true}, {ConnectionId: winrm}},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	resp, err := s.DeleteConnection(context.Background(), &vaultv1.DeleteConnectionRequest{Actor: siteAdmin, Id: winrm})
	if err != nil {
		t.Fatalf("DeleteConnection: %v", err)
	}
	if resp.GetRemoved() {
		t.Fatalf("a non-default connection still bound to a target was removed")
	}
}
