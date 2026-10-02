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

var siteAdmin = &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}

func adminConnection(t *testing.T, s *Server) string {
	t.Helper()
	resp, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "AD LDAPS", Protocol: "ldap", Port: 636, UseTls: true},
	})
	if err != nil {
		t.Fatalf("admin SaveConnection: %v", err)
	}
	return resp.GetConnection().GetId()
}

func sharedTarget(t *testing.T, s *Server, conn string) string {
	t.Helper()
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn, Kind: "windows"},
	})
	if err != nil {
		t.Fatalf("admin SaveTarget: %v", err)
	}
	return resp.GetTarget().GetId()
}

func TestConnectionsAreManagedByAdminsOnly(t *testing.T) {
	s := newServer(t)
	conn := adminConnection(t, s)
	for name, actor := range map[string]*vaultv1.ActorContext{
		"a user":           {UserId: "user-carol"},
		"an admin's token": tokenActor("user-admin", true),
		"service account":  agentGroupActor("sa-1"),
	} {
		_, err := s.SaveConnection(context.Background(), &vaultv1.SaveConnectionRequest{Actor: actor, Connection: &vaultv1.Connection{Name: "x"}})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s save: want PermissionDenied, got %v", name, err)
		}
		_, err = s.DeleteConnection(context.Background(), &vaultv1.DeleteConnectionRequest{Actor: actor, Id: conn})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s delete: want PermissionDenied, got %v", name, err)
		}
	}
}

func TestSharedTargetsAreEditedAndDeletedByAdminsOnly(t *testing.T) {
	s := newServer(t)
	conn := adminConnection(t, s)
	tgt := sharedTarget(t, s, conn)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: carol, Target: &vaultv1.Target{Id: tgt, Name: "hijack", Hostname: "evil.example.org", ConnectionId: conn},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin edit of a shared target: want PermissionDenied, got %v", err)
	}
	_, err = s.DeleteTarget(context.Background(), &vaultv1.DeleteTargetRequest{Actor: carol, Id: tgt})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin delete of a shared target: want PermissionDenied, got %v", err)
	}
}

func TestATokenCreatesAPersonalTargetAndAServiceAccountNone(t *testing.T) {
	s := newServer(t)
	conn := adminConnection(t, s)
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: tokenActor("user-admin", true), Target: &vaultv1.Target{Name: "dc2", Hostname: "dc2.example.org", ConnectionId: conn},
	})
	if err != nil || resp.GetTarget().GetOwnerUserId() != "user-admin" {
		t.Fatalf("token target = %+v, %v; want personal to user-admin even for an admin's token", resp.GetTarget(), err)
	}
	_, err = s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: agentGroupActor("sa-1"), Target: &vaultv1.Target{Name: "dc3", Hostname: "dc3.example.org", ConnectionId: conn},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service-account target create: want PermissionDenied (it would become shared), got %v", err)
	}
}

func TestSaveTargetNeedsAnExistingConnection(t *testing.T) {
	s := newServer(t)
	_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: tokenActor("user-ada", false), Target: &vaultv1.Target{Name: "x", Hostname: "x.example.org", ConnectionId: "no-such-conn"},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing connection: want NotFound, got %v", err)
	}
}
