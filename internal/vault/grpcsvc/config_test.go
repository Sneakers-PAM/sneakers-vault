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

// TestSaveTargetUpdatePersistsKindDomainRealm covers a regression where the
// UPDATE branch of SaveTarget copied only Name/Hostname/ConnectionId/
// Description onto the existing record, silently dropping Kind/Domain/Realm
// on every update after the initial create.
func TestSaveTargetUpdatePersistsKindDomainRealm(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	created, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"},
		Target: &vaultv1.Target{
			Name: "db01", Hostname: "db01.example.test", ConnectionId: "conn-ssh-default",
			Kind: "linux", Domain: "corp.example", Realm: "CORP.EXAMPLE",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget (create): %v", err)
	}
	got := created.GetTarget()
	if got.GetKind() != "linux" || got.GetDomain() != "corp.example" || got.GetRealm() != "CORP.EXAMPLE" {
		t.Fatalf("create did not persist kind/domain/realm: %+v", got)
	}

	updated, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"},
		Target: &vaultv1.Target{
			Id: got.GetId(), Name: "db01", Hostname: "db01.example.test", ConnectionId: "conn-ssh-default",
			Kind: "windows", Domain: "new.example", Realm: "NEW.EXAMPLE",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget (update): %v", err)
	}
	gotUpdated := updated.GetTarget()
	if gotUpdated.GetKind() != "windows" {
		t.Errorf("Kind dropped on update: got %q, want %q", gotUpdated.GetKind(), "windows")
	}
	if gotUpdated.GetDomain() != "new.example" {
		t.Errorf("Domain dropped on update: got %q, want %q", gotUpdated.GetDomain(), "new.example")
	}
	if gotUpdated.GetRealm() != "NEW.EXAMPLE" {
		t.Errorf("Realm dropped on update: got %q, want %q", gotUpdated.GetRealm(), "NEW.EXAMPLE")
	}

	// Confirm the mutation stuck in the store, not just the returned copy.
	list, err := s.ListTargets(ctx, &vaultv1.ListTargetsRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"},
	})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	var found *vaultv1.Target
	for _, tgt := range list.GetTargets() {
		if tgt.GetId() == got.GetId() {
			found = tgt
		}
	}
	if found == nil {
		t.Fatalf("updated target %q not found in ListTargets", got.GetId())
	}
	if found.GetKind() != "windows" || found.GetDomain() != "new.example" || found.GetRealm() != "NEW.EXAMPLE" {
		t.Errorf("persisted target missing update: %+v", found)
	}
}

// TestTargetOwnerScoping covers personal-scoped targets: a non-admin create is
// owned by the actor (personal), an admin create is owner-less (shared),
// ListTargets scopes to shared + own, and editing/deleting another user's
// personal target is denied for a non-admin.
func TestTargetOwnerScoping(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	base := func(name string) *vaultv1.Target {
		return &vaultv1.Target{Name: name, Hostname: name + ".example.test", ConnectionId: "conn-ssh-default"}
	}

	// Non-admin create → personal (owner = actor).
	personal, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-turing"}, Target: base("mine"),
	})
	if err != nil {
		t.Fatalf("SaveTarget personal: %v", err)
	}
	if personal.GetTarget().GetOwnerUserId() != "user-turing" {
		t.Fatalf("non-admin create should be owned by actor, got %q", personal.GetTarget().GetOwnerUserId())
	}

	// Admin create → shared (owner empty).
	shared, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}, Target: base("ours"),
	})
	if err != nil {
		t.Fatalf("SaveTarget shared: %v", err)
	}
	if shared.GetTarget().GetOwnerUserId() != "" {
		t.Fatalf("admin create should be shared, got owner %q", shared.GetTarget().GetOwnerUserId())
	}

	// Turing sees shared + own personal; not other users' personal.
	byUser := func(uid string, admin bool) map[string]bool {
		list, err := s.ListTargets(ctx, &vaultv1.ListTargetsRequest{
			Actor: &vaultv1.ActorContext{UserId: uid, IsSiteAdmin: admin},
		})
		if err != nil {
			t.Fatalf("ListTargets(%s): %v", uid, err)
		}
		ids := map[string]bool{}
		for _, tgt := range list.GetTargets() {
			ids[tgt.GetId()] = true
		}
		return ids
	}
	turingView := byUser("user-turing", false)
	if !turingView[personal.GetTarget().GetId()] || !turingView[shared.GetTarget().GetId()] {
		t.Errorf("turing should see own personal + shared: %v", turingView)
	}
	otherView := byUser("user-lovelace", false)
	if otherView[personal.GetTarget().GetId()] {
		t.Errorf("lovelace must not see turing's personal target")
	}
	if !otherView[shared.GetTarget().GetId()] {
		t.Errorf("lovelace should see the shared target")
	}
	adminView := byUser("user-admin", true)
	if !adminView[personal.GetTarget().GetId()] || !adminView[shared.GetTarget().GetId()] {
		t.Errorf("admin should see all targets: %v", adminView)
	}

	// A non-owner non-admin cannot edit or delete the personal target.
	edit := base("mine")
	edit.Id = personal.GetTarget().GetId()
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-lovelace"}, Target: edit,
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-owner edit: want PermissionDenied, got %v", err)
	}
	if _, err := s.DeleteTarget(ctx, &vaultv1.DeleteTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-lovelace"}, Id: personal.GetTarget().GetId(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-owner delete: want PermissionDenied, got %v", err)
	}

	// The owner may delete their own personal target.
	if _, err := s.DeleteTarget(ctx, &vaultv1.DeleteTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-turing"}, Id: personal.GetTarget().GetId(),
	}); err != nil {
		t.Errorf("owner delete: %v", err)
	}
}

// TestDeleteTargetDropsRuleset proves DeleteTarget removes the target's own
// RACI ruleset along with the target itself, so a deleted target's grants
// don't linger in memory (or get re-persisted into a future snapshot).
func TestDeleteTargetDropsRuleset(t *testing.T) {
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
	tgtBefore := findByID(s.targets, tid)
	s.mu.RUnlock()
	if !s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-turing"}, tgtBefore) {
		t.Fatal("precondition: user-turing should be able to connect before delete")
	}

	if _, err := s.DeleteTarget(ctx, &vaultv1.DeleteTargetRequest{Actor: admin, Id: tid}); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}

	s.mu.RLock()
	_, stillPresent := s.targetRulesets[tid]
	s.mu.RUnlock()
	if stillPresent {
		t.Fatalf("targetRulesets[%q] still present after DeleteTarget", tid)
	}

	// The target itself is gone too, so GetTargetRuleset now 404s rather than
	// returning an empty ruleset — confirming there's no orphaned entry to see.
	if _, err := s.GetTargetRuleset(ctx, &vaultv1.GetTargetRulesetRequest{Actor: admin, TargetId: tid}); code(err) != codes.NotFound {
		t.Fatalf("GetTargetRuleset after delete: want NotFound, got %v", err)
	}
}
