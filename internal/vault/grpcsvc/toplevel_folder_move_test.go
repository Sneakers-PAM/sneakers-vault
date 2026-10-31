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

// "Restrict top-level folders to admins" holds for a move as it does for a
// create: a subfolder can't be promoted to get round the setting. A folder
// already at the top level isn't a new one, so reordering stays with the
// existing admin rule.

var moveBob = &vaultv1.ActorContext{UserId: "user-bob"}

// bobsTree returns a top-level folder bob owns, with a subfolder in it. It's
// built before the restriction goes on, the way a person gets one in practice.
func bobsTree(t *testing.T, s *Server) (top, sub string) {
	t.Helper()
	ctx := context.Background()
	made, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: moveBob, Name: "Team"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	top = made.GetFolder().GetId()
	return top, subFolderAs(t, s, moveBob, top, "Databases")
}

func subFolderAs(t *testing.T, s *Server, a *vaultv1.ActorContext, parent, name string) string {
	t.Helper()
	f, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: a, ParentId: parent, Name: name})
	if err != nil {
		t.Fatalf("CreateFolder(%s): %v", name, err)
	}
	return f.GetFolder().GetId()
}

func moveToTop(s *Server, actor *vaultv1.ActorContext, id string) error {
	_, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{Actor: actor, Id: id})
	return err
}

func moveToTopAsPrincipal(s *Server, actor *vaultv1.ActorContext, id string) error {
	_, err := s.MoveFolderForPrincipal(context.Background(), &vaultv1.MoveFolderForPrincipalRequest{Actor: actor, Id: id})
	return err
}

func wantStillUnder(t *testing.T, s *Server, ca *capAudit, id, parent string) {
	t.Helper()
	if got := s.findFolder(id).GetParentId(); got != parent {
		t.Fatalf("parent = %q, want %q", got, parent)
	}
	if ca.find("folder.move") != nil || ca.find("folder.move.principal") != nil {
		t.Fatal("a refused move must not audit a move")
	}
}

func TestMoveToTopLevelRefusedToPeopleWhileRestricted(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"folder's owner":                 moveBob,
		"person carrying the token flag": {UserId: "user-bob", TokenOwnerIsSiteAdmin: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			top, sub := bobsTree(t, s)
			setRestrictTopLevel(t, s, true)
			ca := &capAudit{}
			s.audit = ca
			wantRestricted(t, s, ca, moveToTop(s, a, sub), len(s.folders))
			wantStillUnder(t, s, ca, sub, top)
		})
	}
}

func TestMoveToTopLevelAllowedToAdminsWhileRestricted(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"site admin": {UserId: "user-ada", IsSiteAdmin: true},
		"root":       {UserId: "user-ada", IsRoot: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			_, sub := bobsTree(t, s)
			setRestrictTopLevel(t, s, true)
			ca := &capAudit{}
			s.audit = ca
			if err := moveToTop(s, a, sub); err != nil {
				t.Fatalf("MoveFolder: %v", err)
			}
			if s.findFolder(sub).GetParentId() != "" || ca.find("folder.move") == nil {
				t.Fatalf("folder = %+v, want it moved and audited", s.findFolder(sub))
			}
		})
	}
}

func TestMoveToTopLevelAllowedToOwnerWhileNotRestricted(t *testing.T) {
	s := newServer(t)
	_, sub := bobsTree(t, s)
	if err := moveToTop(s, moveBob, sub); err != nil {
		t.Fatalf("MoveFolder: %v", err)
	}
	if got := s.findFolder(sub); got.GetParentId() != "" || got.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_GROUP {
		t.Fatalf("folder = %+v, want top level and shared", got)
	}
}

// The restriction covers new top-level folders, not ordinary moves or a
// folder that's already there.
func TestRestrictionLeavesOtherMovesAlone(t *testing.T) {
	s := newServer(t)
	top, sub := bobsTree(t, s)
	other := subFolderAs(t, s, moveBob, top, "Other")
	setRestrictTopLevel(t, s, true)

	if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{Actor: moveBob, Id: sub, NewParentId: other}); err != nil {
		t.Fatalf("move between subfolders: %v", err)
	}
	if err := moveToTop(s, moveBob, top); err != nil {
		t.Fatalf("a folder already at the top level isn't a new one: %v", err)
	}
}

func TestReorderingTopLevelFoldersWorksWhileRestricted(t *testing.T) {
	s := newServer(t)
	a, _ := bobsTree(t, s)
	made, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: moveBob, Name: "Second"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	b := made.GetFolder().GetId()
	setRestrictTopLevel(t, s, true)

	if _, err := s.ReorderFolders(context.Background(), &vaultv1.ReorderFoldersRequest{Actor: siteAdmin, OrderedIds: []string{b, a}}); err != nil {
		t.Fatalf("ReorderFolders: %v", err)
	}
	if s.findFolder(b).GetOrder() != 0 || s.findFolder(a).GetOrder() != 1 {
		t.Fatalf("order: %d, %d", s.findFolder(b).GetOrder(), s.findFolder(a).GetOrder())
	}
	if s.findFolder(a).GetParentId() != "" || s.findFolder(b).GetParentId() != "" {
		t.Fatal("reordering must not re-parent")
	}
}

// A destination that doesn't exist used to read as "top level", which rescoped
// the folder and left it pointing at nothing, restricted or not.
func TestMoveToMissingParentIsNotFound(t *testing.T) {
	for _, on := range []bool{false, true} {
		s := newServer(t)
		top, sub := bobsTree(t, s)
		setRestrictTopLevel(t, s, on)
		ca := &capAudit{}
		s.audit = ca
		before := s.findFolder(sub).GetGroupId()
		_, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{Actor: moveBob, Id: sub, NewParentId: "folder-missing"})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("restrict %v: err %v, want NotFound", on, err)
		}
		wantStillUnder(t, s, ca, sub, top)
		if s.findFolder(sub).GetGroupId() != before {
			t.Fatalf("restrict %v: the refused move rescoped the folder", on)
		}
	}
}

func TestPrincipalMoveToTopLevelRefusedToTokensWhileRestricted(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"non-admin's token":              tokenActor("user-bob", false),
		"token with spoofed admin flags": tokenActor("user-bob", true),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			top, sub := bobsTree(t, s)
			setRestrictTopLevel(t, s, true)
			ca := &capAudit{}
			s.audit = ca
			wantRestricted(t, s, ca, moveToTopAsPrincipal(s, a, sub), len(s.folders))
			wantStillUnder(t, s, ca, sub, top)
		})
	}
}

// A machine has never been able to move a folder to the top level. The
// setting changes only the reason a restricted token hears.
func TestPrincipalMoveToTopLevelStaysClosed(t *testing.T) {
	for _, on := range []bool{false, true} {
		for name, a := range map[string]*vaultv1.ActorContext{
			"admin's token":   adminTokenActor("user-ada"),
			"service account": agentGroupActor("sa-1"),
		} {
			s := newServer(t)
			top, sub := bobsTree(t, s)
			setRestrictTopLevel(t, s, on)
			ca := &capAudit{}
			s.audit = ca
			if err := moveToTopAsPrincipal(s, a, sub); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("restrict %v, %s: err %v, want InvalidArgument", on, name, err)
			}
			if ca.find("authz.denied") != nil {
				t.Fatalf("restrict %v, %s: audited a restriction denial", on, name)
			}
			wantStillUnder(t, s, ca, sub, top)
		}
	}
	s := newServer(t)
	top, sub := bobsTree(t, s)
	ca := &capAudit{}
	s.audit = ca
	if err := moveToTopAsPrincipal(s, tokenActor("user-bob", false), sub); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unrestricted token: err %v, want InvalidArgument", err)
	}
	wantStillUnder(t, s, ca, sub, top)
}

// Moving a folder to where it already is must leave its access alone: anyone
// who reaches it through its group keeps it.
func TestMoveToWhereItAlreadyIsChangesNothing(t *testing.T) {
	t.Run("top-level folder with a group and role", func(t *testing.T) {
		s := newServer(t)
		top, sub := bobsTree(t, s)
		f := s.findFolder(top)
		f.GroupId, f.Role = "group-team", "operators"
		child := s.findFolder(sub)
		child.GroupId, child.Role = "group-team", "operators"
		ca := &capAudit{}
		s.audit = ca

		if err := moveToTop(s, moveBob, top); err != nil {
			t.Fatalf("MoveFolder: %v", err)
		}
		for _, got := range []*vaultv1.Folder{s.findFolder(top), s.findFolder(sub)} {
			if got.GetGroupId() != "group-team" || got.GetRole() != "operators" {
				t.Fatalf("folder %s = %+v, want group and role kept", got.GetId(), got)
			}
		}
		if ca.find("folder.move") != nil {
			t.Fatal("nothing moved, so nothing should be audited as a move")
		}
	})

	t.Run("top-level personal folder stays personal", func(t *testing.T) {
		s := newServer(t)
		id := "folder-bob-personal"
		s.folders = append(s.folders, &vaultv1.Folder{
			Id: id, Name: "Mine", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: moveBob.GetUserId(),
		})
		if err := moveToTop(s, moveBob, id); err != nil {
			t.Fatalf("MoveFolder: %v", err)
		}
		got := s.findFolder(id)
		if got.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL || got.GetOwnerUserId() != moveBob.GetUserId() {
			t.Fatalf("folder = %+v, want it still personal to bob", got)
		}
	})

	t.Run("subfolder keeping its parent keeps its own role", func(t *testing.T) {
		s := newServer(t)
		top, sub := bobsTree(t, s)
		s.findFolder(sub).Role = "readers"
		if _, err := s.MoveFolder(context.Background(), &vaultv1.MoveFolderRequest{Actor: moveBob, Id: sub, NewParentId: top}); err != nil {
			t.Fatalf("MoveFolder: %v", err)
		}
		if got := s.findFolder(sub).GetRole(); got != "readers" {
			t.Fatalf("role = %q, want it kept", got)
		}
	})

	t.Run("a stranger is still refused", func(t *testing.T) {
		s := newServer(t)
		top, _ := bobsTree(t, s)
		err := moveToTop(s, &vaultv1.ActorContext{UserId: "user-eve"}, top)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("err = %v, want PermissionDenied", err)
		}
	})
}
