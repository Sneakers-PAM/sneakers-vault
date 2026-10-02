// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// The secret/folder move rule. A PERSONAL secret can be promoted to a shared
// (group/role) folder freely, but a SHARED secret can NOT be demoted into a
// personal folder except by a site-admin — a non-admin is rejected here
// server-side (the gateway routes that case through an approval that re-applies
// the move as the system actor). These tests lock in the vault-side
// enforcement, independent of any UI or approval routing, for both MoveSecret
// (an UpdateSecret with dest_folder_id) and MoveFolder. They also pin the two
// invariants moving must preserve: a moved secret keeps its identity, version
// ledger and audit trail; and moving a folder never touches the secrets that
// live inside it.

// appendPersonalFolder inserts an extra personal folder (owned by userID) with a
// caller-chosen id, so a test can exercise moves between two personal folders of
// the same owner. Mirrors seedPersonalFolder's shape.
func appendPersonalFolder(s *Server, id, userID, parent string) {
	s.folders = append(s.folders, &vaultv1.Folder{
		Id: id, Name: id, ParentId: parent,
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: userID,
	})
}

// moveRuleSecret creates a password secret in folderID as actor and returns its id.
func moveRuleSecret(t *testing.T, s *Server, actor *vaultv1.ActorContext, folderID, name string) string {
	t.Helper()
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: actor, Name: name, FolderId: folderID, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(%s): %v", name, err)
	}
	return created.GetSecret().GetId()
}

// ---- MoveSecret (UpdateSecret with dest_folder_id) --------------------------

func TestMoveSecret_PersonalToSharedAllowed(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	shared := newSharedFolder(t, s) // carol is OWNER
	secID := moveRuleSecret(t, s, carol, "folder-personal-carol", "svc token")

	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, DestFolderId: shared,
	}); err != nil {
		t.Fatalf("personal->shared move should be allowed: %v", err)
	}
	if got := s.findSecret(secID).GetFolderId(); got != shared {
		t.Errorf("after move folderId = %q, want %q", got, shared)
	}
}

func TestMoveSecret_SharedToOwnPersonalNonAdminDenied(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	shared := newSharedFolder(t, s)
	secID := moveRuleSecret(t, s, carol, shared, "shared token")

	// Even into their OWN personal folder, a non-admin can't demote a shared
	// secret — that requires site-admin (the gateway files an approval).
	_, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, DestFolderId: "folder-personal-carol",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("shared->personal by non-admin: want PermissionDenied, got %v", err)
	}
	if got := s.findSecret(secID).GetFolderId(); got != shared {
		t.Errorf("secret moved despite denial: folderId = %q, want %q (unchanged)", got, shared)
	}
}

func TestMoveSecret_SharedToPersonalSiteAdminAllowed(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	seedPersonalFolder(s, "user-grace")
	shared := newSharedFolder(t, s)
	secID := moveRuleSecret(t, s, carol, shared, "shared token")

	// A site-admin may demote a shared secret into ANY user's personal folder.
	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: admin, Id: secID, DestFolderId: "folder-personal-grace",
	}); err != nil {
		t.Fatalf("shared->personal by site-admin should be allowed: %v", err)
	}
	if got := s.findSecret(secID).GetFolderId(); got != "folder-personal-grace" {
		t.Errorf("after admin move folderId = %q, want folder-personal-grace", got)
	}
}

func TestMoveSecret_RearrangeOwnPersonalTreeAllowed(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol") // folder-personal-carol
	appendPersonalFolder(s, "folder-personal-carol-work", "user-carol", "folder-personal-root")
	secID := moveRuleSecret(t, s, carol, "folder-personal-carol", "personal note")

	// personal -> personal within the SAME owner's tree is free (alreadyYours).
	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, DestFolderId: "folder-personal-carol-work",
	}); err != nil {
		t.Fatalf("rearranging own personal tree should be allowed: %v", err)
	}
	if got := s.findSecret(secID).GetFolderId(); got != "folder-personal-carol-work" {
		t.Errorf("after move folderId = %q, want folder-personal-carol-work", got)
	}
}

func TestMoveSecret_NoPermissionOnDestDenied(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	grace := &vaultv1.ActorContext{UserId: "user-grace"}
	seedPersonalFolder(s, "user-carol")
	secID := moveRuleSecret(t, s, carol, "folder-personal-carol", "svc token")

	// A shared folder carol neither owns nor manages.
	gf, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: grace, Name: "Grace Team"})
	if err != nil {
		t.Fatalf("CreateFolder(grace): %v", err)
	}
	_, err = s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, DestFolderId: gf.GetFolder().GetId(),
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("move into a folder carol can't place in: want PermissionDenied, got %v", err)
	}
}

// TestMoveSecret_PreservesIdentityHistoryAndAudit pins the invariant that moving
// a secret does NOT wipe its history/audit: the move is an in-place folder
// reassignment (same secret id, same sealed record — no re-seal, so the version
// ledger is untouched), recorded as an appended "secret.move" audit event and
// never as a destroy+recreate.
func TestMoveSecret_PreservesIdentityHistoryAndAudit(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	shared := newSharedFolder(t, s)
	secID := moveRuleSecret(t, s, carol, "folder-personal-carol", "svc token")

	recBefore := s.records[secID] // sealed field set snapshot (value copy)

	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, DestFolderId: shared,
	}); err != nil {
		t.Fatalf("move: %v", err)
	}

	// Identity stable: same id, now in the destination.
	sec := s.findSecret(secID)
	if sec == nil || sec.GetId() != secID {
		t.Fatalf("secret identity changed by the move (want id %q)", secID)
	}
	if sec.GetFolderId() != shared {
		t.Errorf("folderId = %q, want %q", sec.GetFolderId(), shared)
	}
	// Sealed record untouched — a pure move must not re-seal, so no new version
	// is minted and the ledger/history is preserved.
	if !reflect.DeepEqual(recBefore, s.records[secID]) {
		t.Error("move re-sealed the secret record (would mint a spurious version / disturb history)")
	}
	// Audited as a move, not a destroy+recreate.
	if ca.find("secret.move") == nil {
		t.Error("no secret.move audit event emitted")
	}
	if ev := ca.find("secret.delete"); ev != nil {
		t.Error("move emitted secret.delete — it must never destroy+recreate the secret")
	}
}

// ---- MoveFolder ------------------------------------------------------------

func TestMoveFolder_PersonalToSharedAllowed(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	appendPersonalFolder(s, "folder-personal-carol-sub", "user-carol", "folder-personal-carol")

	// Move a personal subfolder up to the top level (shared) — allowed for its owner.
	if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: carol, Id: "folder-personal-carol-sub", NewParentId: "",
	}); err != nil {
		t.Fatalf("personal->shared folder move should be allowed: %v", err)
	}
	moved := s.findFolder("folder-personal-carol-sub")
	if moved.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_GROUP {
		t.Errorf("after move to top level scope = %v, want GROUP (shared)", moved.GetScope())
	}
}

func TestMoveFolder_SharedToPersonalNonAdminDenied(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-grace")
	shared := newSharedFolder(t, s) // carol owns it

	_, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: carol, Id: shared, NewParentId: "folder-personal-grace",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("shared->personal folder move by non-admin: want PermissionDenied, got %v", err)
	}
	if got := s.findFolder(shared).GetScope(); got != vaultv1.FolderScope_FOLDER_SCOPE_GROUP {
		t.Errorf("folder rescoped despite denial: scope = %v, want GROUP (unchanged)", got)
	}
}

func TestMoveFolder_SharedToPersonalSiteAdminAllowedRescopes(t *testing.T) {
	s := newServer(t)
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	seedPersonalFolder(s, "user-grace")
	shared := newSharedFolder(t, s) // created owned by user-carol

	if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: admin, Id: shared, NewParentId: "folder-personal-grace",
	}); err != nil {
		t.Fatalf("shared->personal folder move by site-admin should be allowed: %v", err)
	}
	// The subtree is rescoped to the destination personal owner.
	moved := s.findFolder(shared)
	if moved.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL || moved.GetOwnerUserId() != "user-grace" {
		t.Errorf("after admin move scope/owner = %v/%q, want PERSONAL/user-grace", moved.GetScope(), moved.GetOwnerUserId())
	}
}

func TestMoveFolder_RearrangeOwnPersonalTreeAllowed(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	appendPersonalFolder(s, "folder-personal-carol-a", "user-carol", "folder-personal-carol")
	appendPersonalFolder(s, "folder-personal-carol-b", "user-carol", "folder-personal-carol")

	// Rearranging within your own personal tree is free.
	if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: carol, Id: "folder-personal-carol-a", NewParentId: "folder-personal-carol-b",
	}); err != nil {
		t.Fatalf("rearranging own personal tree should be allowed: %v", err)
	}
	if got := s.findFolder("folder-personal-carol-a").GetParentId(); got != "folder-personal-carol-b" {
		t.Errorf("after move parentId = %q, want folder-personal-carol-b", got)
	}
}

func TestMoveFolder_CycleGuardRejected(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	parent := newSharedFolder(t, s)
	child, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{
		Actor: carol, ParentId: parent, Name: "child",
	})
	if err != nil {
		t.Fatalf("CreateFolder(child): %v", err)
	}
	_, err = s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: carol, Id: parent, NewParentId: child.GetFolder().GetId(),
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("moving a folder into its own descendant: want InvalidArgument, got %v", err)
	}
}

// TestMoveFolder_PreservesInnerSecretsHistory pins the invariant that moving a
// folder does not affect the secrets living inside it: a folder move only
// rescopes/repartents folder rows, so a secret in the moved subtree keeps its
// id, its enclosing folder, and its sealed record (version ledger untouched).
func TestMoveFolder_PreservesInnerSecretsHistory(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	seedPersonalFolder(s, "user-grace")
	shared := newSharedFolder(t, s)
	secID := moveRuleSecret(t, s, carol, shared, "svc token")

	recBefore := s.records[secID]

	// Site-admin demotes the whole shared folder into grace's personal space.
	if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{
		Actor: admin, Id: shared, NewParentId: "folder-personal-grace",
	}); err != nil {
		t.Fatalf("folder move: %v", err)
	}

	sec := s.findSecret(secID)
	if sec == nil || sec.GetId() != secID {
		t.Fatalf("inner secret identity changed by the folder move (want id %q)", secID)
	}
	if sec.GetFolderId() != shared {
		t.Errorf("inner secret folderId = %q, want %q (still in the moved folder)", sec.GetFolderId(), shared)
	}
	if !reflect.DeepEqual(recBefore, s.records[secID]) {
		t.Error("folder move re-sealed an inner secret (would disturb its history)")
	}
	if ev := ca.find("secret.move"); ev != nil {
		t.Error("folder move emitted a per-secret secret.move — it must not touch inner secrets")
	}
	if ev := ca.find("secret.delete"); ev != nil {
		t.Error("folder move emitted secret.delete on an inner secret")
	}
}
