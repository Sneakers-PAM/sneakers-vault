// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// saveTestTarget creates a minimal usable target (its own connection) owned
// by nobody (shared), returning its id.
func saveTestTarget(t *testing.T, s *Server, name, hostname string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "conn-" + name, Protocol: "ssh", Port: 22},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	tgt, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Name: name, Hostname: hostname, ConnectionId: conn.GetConnection().GetId(), Kind: "linux",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	return tgt.GetTarget().GetId()
}

// TestAttachDetachSecretTarget_HumanAddsAndRemovesWithoutDisturbingOthers is
// #168's core data-model path: a human attaches a second target to a secret
// that already has one (becomes a list of two), detaches the first (one
// remains), and the legacy target_id alias stays the first/primary entry
// throughout.
func TestAttachDetachSecretTarget_HumanAddsAndRemovesWithoutDisturbingOthers(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	tgtA := saveTestTarget(t, s, "host-a", "host-a.example.org")
	tgtB := saveTestTarget(t, s, "host-b", "host-b.example.org")

	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "claude ssh key", FolderId: fid, TypeId: "type-password", TargetId: tgtA,
		Fields: map[string]string{"username": "claude", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	if got := created.GetSecret().GetTargetIds(); len(got) != 1 || got[0] != tgtA {
		t.Fatalf("a single-target create should be a one-item list, got %v", got)
	}

	attached, err := s.AttachSecretTarget(ctx, &vaultv1.AttachSecretTargetRequest{Actor: carol, SecretId: sid, TargetId: tgtB})
	if err != nil {
		t.Fatalf("AttachSecretTarget: %v", err)
	}
	if got := attached.GetSecret().GetTargetIds(); len(got) != 2 || got[0] != tgtA || got[1] != tgtB {
		t.Fatalf("want [tgtA, tgtB], got %v", got)
	}
	if got := attached.GetSecret().GetTargetId(); got != tgtA {
		t.Fatalf("legacy target_id alias should stay the primary (first), got %q", got)
	}

	// Attaching the same target again is a no-op, not an error or a duplicate.
	if _, err := s.AttachSecretTarget(ctx, &vaultv1.AttachSecretTargetRequest{Actor: carol, SecretId: sid, TargetId: tgtB}); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	again := s.findSecret(sid)
	if got := again.GetTargetIds(); len(got) != 2 {
		t.Fatalf("re-attaching an already-attached target must not duplicate it, got %v", got)
	}

	detached, err := s.DetachSecretTarget(ctx, &vaultv1.DetachSecretTargetRequest{Actor: carol, SecretId: sid, TargetId: tgtA})
	if err != nil {
		t.Fatalf("DetachSecretTarget: %v", err)
	}
	if got := detached.GetSecret().GetTargetIds(); len(got) != 1 || got[0] != tgtB {
		t.Fatalf("detaching tgtA should leave only tgtB, got %v", got)
	}
	if got := detached.GetSecret().GetTargetId(); got != tgtB {
		t.Fatalf("legacy target_id alias should move to the remaining target, got %q", got)
	}

	// Detaching something not attached is a no-op, not an error.
	if _, err := s.DetachSecretTarget(ctx, &vaultv1.DetachSecretTargetRequest{Actor: carol, SecretId: sid, TargetId: "target-never-attached"}); err != nil {
		t.Fatalf("detach of an unattached target: %v", err)
	}
}

// TestUpdateSecret_TargetIdReplacesWholeList proves UpdateSecret's target_id
// keeps its existing "replace with just this one" meaning, distinct from
// Attach/Detach.
func TestUpdateSecret_TargetIdReplacesWholeList(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	tgtA := saveTestTarget(t, s, "host-a", "host-a.example.org")
	tgtB := saveTestTarget(t, s, "host-b", "host-b.example.org")
	tgtC := saveTestTarget(t, s, "host-c", "host-c.example.org")

	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "claude ssh key", FolderId: fid, TypeId: "type-password", TargetId: tgtA,
		Fields: map[string]string{"username": "claude", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.AttachSecretTarget(ctx, &vaultv1.AttachSecretTargetRequest{Actor: carol, SecretId: sid, TargetId: tgtB}); err != nil {
		t.Fatalf("AttachSecretTarget: %v", err)
	}

	updated, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: sid, TargetId: tgtC})
	if err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if got := updated.GetSecret().GetTargetIds(); len(got) != 1 || got[0] != tgtC {
		t.Fatalf("UpdateSecret(target_id) should replace the whole list with just tgtC, got %v", got)
	}
}

// TestAttachDetachSecretTargetForPrincipal_AuthorGrantAddsAndRemoves mirrors
// the human test for the non-human principal path, with the same RACI-
// Author gate RotateSecretForPrincipal uses.
func TestAttachDetachSecretTargetForPrincipal_AuthorGrantAddsAndRemoves(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := authorGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	tgtA := saveTestTarget(t, s, "host-a", "host-a.example.org")
	tgtB := saveTestTarget(t, s, "host-b", "host-b.example.org")

	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password", TargetId: tgtA,
		Fields: map[string]string{"username": "admin", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	sid := created.GetSecret().GetId()

	attached, err := s.AttachSecretTargetForPrincipal(ctx, &vaultv1.AttachSecretTargetForPrincipalRequest{Actor: sa, SecretId: sid, TargetId: tgtB})
	if err != nil {
		t.Fatalf("AttachSecretTargetForPrincipal: %v", err)
	}
	if got := attached.GetSecret().GetTargetIds(); len(got) != 2 || got[0] != tgtA || got[1] != tgtB {
		t.Fatalf("want [tgtA, tgtB], got %v", got)
	}

	detached, err := s.DetachSecretTargetForPrincipal(ctx, &vaultv1.DetachSecretTargetForPrincipalRequest{Actor: sa, SecretId: sid, TargetId: tgtA})
	if err != nil {
		t.Fatalf("DetachSecretTargetForPrincipal: %v", err)
	}
	if got := detached.GetSecret().GetTargetIds(); len(got) != 1 || got[0] != tgtB {
		t.Fatalf("want [tgtB], got %v", got)
	}
}

// TestAttachSecretTargetForPrincipal_RefusedWithoutAuthorAccess mirrors
// RotateSecretForPrincipal's refusal test: no RACI-Author, no attach.
func TestAttachSecretTargetForPrincipal_RefusedWithoutAuthorAccess(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	tgtA := saveTestTarget(t, s, "host-a", "host-a.example.org")
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "host-a admin", FolderId: fid, TypeId: "type-password", TargetId: tgtA,
		Fields: map[string]string{"username": "admin", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	_, err = s.AttachSecretTargetForPrincipal(ctx, &vaultv1.AttachSecretTargetForPrincipalRequest{
		Actor: sa, SecretId: created.GetSecret().GetId(), TargetId: tgtA,
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

// TestAttachSecretTargetForPrincipal_RefusedForAnotherUsersPersonalTarget
// proves AttachSecretTargetForPrincipal gates the target the same way
// SetSecretTargetForPrincipal does: a personal target owned by someone else
// is refused even with folder Author.
func TestAttachSecretTargetForPrincipal_RefusedForAnotherUsersPersonalTarget(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	fid := authorGrantFolder(t, s, "sa-laps")
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-laps"}
	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "dave's conn", Protocol: "ssh", Port: 22},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	personal, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-dave"}, Target: &vaultv1.Target{
			Name: "dave's box", Hostname: "dave-box.example.org", ConnectionId: conn.GetConnection().GetId(),
			OwnerUserId: "user-dave", Kind: "linux",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	created, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
		Actor: sa, Name: "host-a admin", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "admin", "password": "pw1"},
	})
	if err != nil {
		t.Fatalf("CreateSecretForPrincipal: %v", err)
	}
	_, err = s.AttachSecretTargetForPrincipal(ctx, &vaultv1.AttachSecretTargetForPrincipalRequest{
		Actor: sa, SecretId: created.GetSecret().GetId(), TargetId: personal.GetTarget().GetId(),
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for another user's personal target, got %v", err)
	}
}
