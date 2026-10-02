// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// newTestTarget creates a connection + target owned (created) by carol and
// returns the target id.
func newTestTarget(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true}
	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "RDP", Protocol: "rdp", Port: 3389},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	tgt, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: carol, Target: &vaultv1.Target{
			Name: "jump-1", Hostname: "jump-1.example.org", ConnectionId: conn.GetConnection().GetId(),
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	return tgt.GetTarget().GetId()
}

// TestTargetRulesetRoundTrip proves SetTargetRuleset then GetTargetRuleset
// round-trips the ordered rule set, mirroring folder rulesets.
func TestTargetRulesetRoundTrip(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	tid := newTestTarget(t, s)

	if _, err := s.SetTargetRuleset(ctx, &vaultv1.SetTargetRulesetRequest{
		Actor: admin, TargetId: tid,
		Ruleset: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetTargetRuleset: %v", err)
	}

	got, err := s.GetTargetRuleset(ctx, &vaultv1.GetTargetRulesetRequest{Actor: admin, TargetId: tid})
	if err != nil {
		t.Fatalf("GetTargetRuleset: %v", err)
	}
	if len(got.GetRuleset()) != 1 || got.GetRuleset()[0].GetSubjectName() != "user-turing" {
		t.Fatalf("GetTargetRuleset did not return the persisted rule: %+v", got.GetRuleset())
	}
	if got.GetRuleset()[0].GetGrants()["C"] != "allow" {
		t.Fatalf("persisted rule grants = %+v, want C:allow", got.GetRuleset()[0].GetGrants())
	}
}

// TestCanConnectTargetGrantedByC proves canConnectTarget is true for a
// subject with a C-grant on the target's own ruleset, false without.
func TestCanConnectTargetGrantedByC(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	tid := newTestTarget(t, s)

	if _, err := s.SetTargetRuleset(ctx, &vaultv1.SetTargetRulesetRequest{
		Actor: admin, TargetId: tid,
		Ruleset: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetTargetRuleset: %v", err)
	}

	s.mu.RLock()
	tgt := findByID(s.targets, tid)
	s.mu.RUnlock()
	if tgt == nil {
		t.Fatal("target not found")
	}

	if !s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-turing"}, tgt) {
		t.Fatal("user-turing has C on the target ruleset: canConnectTarget should be true")
	}
	if s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-nobody"}, tgt) {
		t.Fatal("user-nobody has no grant: canConnectTarget should be false")
	}
}

// TestCanConnectTargetAdminShortCircuit proves a site-admin/root can always
// connect, even with no explicit ruleset entry (mirrors other admin checks).
func TestCanConnectTargetAdminShortCircuit(t *testing.T) {
	s := newServer(t)
	tid := newTestTarget(t, s)
	s.mu.RLock()
	tgt := findByID(s.targets, tid)
	s.mu.RUnlock()
	if tgt == nil {
		t.Fatal("target not found")
	}
	if !s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}, tgt) {
		t.Fatal("site-admin should always be able to connect")
	}
	if !s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-root", IsRoot: true}, tgt) {
		t.Fatal("root should always be able to connect")
	}
}

// TestSetTargetRulesetNonAdminDenied proves a plain user cannot edit a
// shared target's ruleset (mirrors SetFolderRuleset's owner gate).
func TestSetTargetRulesetNonAdminDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	tid := newTestTarget(t, s)
	_, err := s.SetTargetRuleset(ctx, &vaultv1.SetTargetRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-nobody"}, TargetId: tid,
		Ruleset: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"C": "allow"},
		}},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin SetTargetRuleset: want PermissionDenied, got %v", err)
	}
}

// TestSetTargetRulesetSpoofedMachineAdminDenied proves a non-human principal
// (SERVICE_ACCOUNT) carrying is_site_admin=true — which a gateway should never
// set for a machine, but the vault must not trust blindly — is still denied
// when it has no ownership of the target. isTargetOwner (and by extension
// SetTargetRuleset's owner gate) must treat is_site_admin/is_root as valid
// ONLY for a PRINCIPAL_KIND_HUMAN actor (mirrors evalOf's anti-spoof guard).
func TestSetTargetRulesetSpoofedMachineAdminDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	tid := newTestTarget(t, s)
	spoofed := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   "sa-spoofed-admin",
		IsSiteAdmin:   true,
	}
	_, err := s.SetTargetRuleset(ctx, &vaultv1.SetTargetRulesetRequest{
		Actor: spoofed, TargetId: tid,
		Ruleset: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"C": "allow"},
		}},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("spoofed machine admin SetTargetRuleset: want PermissionDenied, got %v", err)
	}
}

// TestTargetRulesetPersistsAcrossSnapshotReload proves the target ruleset
// survives a snapshot/reload cycle, mirroring folder-rule persistence.
func TestTargetRulesetPersistsAcrossSnapshotReload(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	tid := newTestTarget(t, s)

	if _, err := s.SetTargetRuleset(ctx, &vaultv1.SetTargetRulesetRequest{
		Actor: admin, TargetId: tid,
		Ruleset: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetTargetRuleset: %v", err)
	}

	snap := s.snapshot()
	fresh, err := NewWithStore(ctx, newMemStore(), s.crypt, nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	fresh.hydrate(snap)

	got, err := fresh.GetTargetRuleset(ctx, &vaultv1.GetTargetRulesetRequest{Actor: admin, TargetId: tid})
	if err != nil {
		t.Fatalf("GetTargetRuleset after reload: %v", err)
	}
	if len(got.GetRuleset()) != 1 || got.GetRuleset()[0].GetSubjectName() != "user-turing" {
		t.Fatalf("target ruleset did not survive snapshot/reload: %+v", got.GetRuleset())
	}
}
