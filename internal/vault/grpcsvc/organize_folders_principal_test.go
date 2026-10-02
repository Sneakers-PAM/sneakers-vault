// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// Organize verbs: ListFoldersForPrincipal, CreateFolderForPrincipal,
// RenameFolderForPrincipal, MoveFolderForPrincipal. RACI for the principal id
// only (no admin flag, no ownership), personal folders only when explicitly
// granted (never via an everyone rule, never the master root), no machine
// create/move into a personal subtree, no cycles, audited as the principal.

// subFolder creates a child folder as carol (who owns the top-level parent).
func subFolder(t *testing.T, s *Server, parentID, name string) string {
	t.Helper()
	f, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{
		Actor: orgCarol, ParentId: parentID, Name: name,
	})
	if err != nil {
		t.Fatalf("CreateFolder(%s under %s): %v", name, parentID, err)
	}
	return f.GetFolder().GetId()
}

// setGroupGrants replaces a folder's ruleset with one g-agents rule.
func setGroupGrants(t *testing.T, s *Server, folderID string, grants map[string]string) {
	t.Helper()
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: orgCarol, FolderId: folderID, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: grants,
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(%s): %v", folderID, err)
	}
}

func orgFolderIDs(fs []*vaultv1.Folder) map[string]*vaultv1.Folder {
	out := map[string]*vaultv1.Folder{}
	for _, f := range fs {
		out[f.GetId()] = f
	}
	return out
}

// ---- ListFoldersForPrincipal -------------------------------------------------

func TestListFoldersForPrincipal_OnlyReadableMetadataOnly(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.ensureMasterPersonalFolder()
	readable := mutFolder(t, s, "Readable")
	grantGroup(t, s, orgCarol, readable, "C")
	authored := mutFolder(t, s, "Authored")
	grantGroup(t, s, orgCarol, authored, "R")
	hidden := mutFolder(t, s, "Hidden")
	denied := subFolder(t, s, readable, "Denied child")
	setGroupGrants(t, s, denied, map[string]string{"C": "deny"})
	inherited := subFolder(t, s, readable, "Inherited child")
	mutSecret(t, s, readable)

	seedPersonalFolder(s, "user-carol")
	seedPersonalFolder(s, "user-alice")
	appendPersonalFolder(s, "folder-personal-bob", "user-bob", "folder-personal-root")
	grantGroup(t, s, orgCarol, "folder-personal-carol", "C")                                              // explicit grant
	injectEveryoneRule(s, "folder-personal-alice", map[string]string{"C": "allow"})                       // everyone only
	injectEveryoneRule(s, "folder-personal-root", map[string]string{"C": "allow", "R": "allow"})          // admin-set on the master root
	s.raciRules = append(s.raciRules, &vaultv1.RaciRule{Id: "r-master", FolderId: "folder-personal-root", // admin-set group grant on the master root
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: map[string]string{"C": "allow"}})

	resp, err := s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{Actor: agentGroupActor("sa-1")})
	if err != nil {
		t.Fatalf("ListFoldersForPrincipal: %v", err)
	}
	got := orgFolderIDs(resp.GetFolders())
	for _, want := range []string{readable, authored, inherited, "folder-personal-carol"} {
		if got[want] == nil {
			t.Errorf("readable folder %s missing", want)
		}
	}
	for _, not := range []string{hidden, denied, "folder-personal-alice", "folder-personal-bob", "folder-personal-root"} {
		if got[not] != nil {
			t.Errorf("folder %s must not be listed", not)
		}
	}
	if len(got) != 4 {
		t.Errorf("listed %d folders, want 4: %v", len(got), got)
	}
	if !got[authored].GetCanManage() || got[readable].GetCanManage() {
		t.Errorf("can_manage must reflect Author: authored=%v readable=%v", got[authored].GetCanManage(), got[readable].GetCanManage())
	}
	for id, f := range got {
		if len(f.GetOwners()) != 0 || f.GetOwnerUserId() != "" || f.GetGroupId() != "" || f.GetRole() != "" || f.GetSubtreeSecretCount() != 0 {
			t.Errorf("folder %s leaks non-metadata fields: %+v", id, f)
		}
	}
	ev := ca.find("folder.list.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["count"] != "4" {
		t.Fatalf("list audit = %+v", ev)
	}
}

func TestListFoldersForPrincipal_Filters(t *testing.T) {
	s := newServer(t)
	top := mutFolder(t, s, "Platform")
	grantGroup(t, s, orgCarol, top, "C")
	a := subFolder(t, s, top, "Databases")
	b := subFolder(t, s, top, "web tier")
	subFolder(t, s, a, "Deep DB")
	resp, err := s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), ParentId: top,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := orgFolderIDs(resp.GetFolders()); len(got) != 2 || got[a] == nil || got[b] == nil {
		t.Fatalf("parent filter = %v", got)
	}
	resp, err = s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Query: "db",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetFolders(); len(got) != 1 || got[0].GetName() != "Deep DB" {
		t.Fatalf("query filter = %v", got)
	}
}

func TestListFoldersForPrincipal_HumanAndSpoofedAdmin(t *testing.T) {
	s := newServer(t)
	mutFolder(t, s, "Shared")
	_, err := s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{Actor: humanAdmin})
	wantCode(t, err, codes.PermissionDenied)
	resp, err := s.ListFoldersForPrincipal(context.Background(), &vaultv1.ListFoldersForPrincipalRequest{Actor: spoofedAdminSA})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(resp.GetFolders()); n != 0 {
		t.Fatalf("spoofed admin SA with no grants sees %d folders", n)
	}
}

// ---- CreateFolderForPrincipal ------------------------------------------------

func TestCreateFolderForPrincipal_AuthorOnParent(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	parent := mutFolder(t, s, "Platform")
	grantGroup(t, s, orgCarol, parent, "R")
	resp, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), ParentId: parent, Name: " Databases ",
	})
	if err != nil {
		t.Fatalf("CreateFolderForPrincipal: %v", err)
	}
	f := s.findFolder(resp.GetFolder().GetId())
	if f == nil || f.GetName() != "Databases" || f.GetParentId() != parent {
		t.Fatalf("created folder = %+v", f)
	}
	p := s.findFolder(parent)
	if f.GetScope() != p.GetScope() || f.GetGroupId() != p.GetGroupId() || len(f.GetOwners()) != 0 {
		t.Fatalf("new folder must inherit scope and have no owners: %+v", f)
	}
	if !s.canManage(agentGroupActor("sa-1"), f.GetId()) {
		t.Fatal("principal must keep Author on its new folder through inheritance")
	}
	if len(resp.GetFolder().GetOwners()) != 0 || resp.GetFolder().GetGroupId() != "" {
		t.Fatalf("response must be metadata only: %+v", resp.GetFolder())
	}
	ev := ca.find("folder.create.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Subject != f.GetId() || ev.Attributes["parent_id"] != parent {
		t.Fatalf("create audit = %+v", ev)
	}
	for _, x := range s.folders {
		if x.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && x.GetOwnerUserId() == "" && !x.GetIsMasterPersonal() {
			t.Fatal("machine create must not provision a personal folder")
		}
	}
}

func TestCreateFolderForPrincipal_Denials(t *testing.T) {
	type tc struct {
		name  string
		setup func(t *testing.T, s *Server) string // returns parent id
		actor *vaultv1.ActorContext
		fname string
		code  codes.Code
	}
	shared := func(grant string) func(t *testing.T, s *Server) string {
		return func(t *testing.T, s *Server) string {
			p := mutFolder(t, s, "P")
			if grant != "" {
				grantGroup(t, s, orgCarol, p, grant)
			}
			return p
		}
	}
	personalGranted := func(t *testing.T, s *Server) string {
		seedPersonalFolder(s, "user-carol")
		grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
		return "folder-personal-carol"
	}
	cases := []tc{
		{"no rights on parent", shared(""), agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"read-only parent", shared("C"), agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"per-folder deny on parent", func(t *testing.T, s *Server) string {
			top := shared("R")(t, s)
			child := subFolder(t, s, top, "child")
			setGroupGrants(t, s, child, map[string]string{"R": "deny"})
			return child
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"human caller", shared("R"), humanAdmin, "x", codes.PermissionDenied},
		{"spoofed admin flags", shared(""), spoofedAdminSA, "x", codes.PermissionDenied},
		{"personal parent even when granted", personalGranted, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"personal parent not granted", func(t *testing.T, s *Server) string {
			seedPersonalFolder(s, "user-carol")
			return "folder-personal-carol"
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"master personal root", func(t *testing.T, s *Server) string {
			s.ensureMasterPersonalFolder()
			injectEveryoneRule(s, "folder-personal-root", map[string]string{"R": "allow"})
			return "folder-personal-root"
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"top level (no parent)", func(*testing.T, *Server) string { return "" }, agentGroupActor("sa-1"), "x", codes.InvalidArgument},
		{"missing parent", func(*testing.T, *Server) string { return "folder-missing" }, agentGroupActor("sa-1"), "x", codes.NotFound},
		{"empty name", shared("R"), agentGroupActor("sa-1"), "  ", codes.InvalidArgument},
		{"duplicate sibling name", func(t *testing.T, s *Server) string {
			p := shared("R")(t, s)
			subFolder(t, s, p, "Databases")
			return p
		}, agentGroupActor("sa-1"), "databases", codes.AlreadyExists},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			parent := c.setup(t, s)
			n := len(s.folders)
			_, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
				Actor: c.actor, ParentId: parent, Name: c.fname,
			})
			wantCode(t, err, c.code)
			if len(s.folders) != n || ca.find("folder.create.principal") != nil {
				t.Fatal("denied create must not add or audit a folder")
			}
		})
	}
}

// ---- RenameFolderForPrincipal ------------------------------------------------

func TestRenameFolderForPrincipal_Author(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := mutFolder(t, s, "Old")
	grantGroup(t, s, orgCarol, f, "R")
	resp, err := s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: f, Name: "New",
	})
	if err != nil {
		t.Fatalf("RenameFolderForPrincipal: %v", err)
	}
	if s.findFolder(f).GetName() != "New" || resp.GetFolder().GetName() != "New" || len(resp.GetFolder().GetOwners()) != 0 {
		t.Fatalf("rename result = %+v", resp.GetFolder())
	}
	ev := ca.find("folder.rename.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["from_name"] != "Old" || ev.Attributes["to_name"] != "New" {
		t.Fatalf("rename audit = %+v", ev)
	}
}

func TestRenameFolderForPrincipal_Denials(t *testing.T) {
	type tc struct {
		name  string
		setup func(t *testing.T, s *Server) string
		actor *vaultv1.ActorContext
		fname string
		code  codes.Code
	}
	shared := func(grant string) func(t *testing.T, s *Server) string {
		return func(t *testing.T, s *Server) string {
			f := mutFolder(t, s, "F")
			if grant != "" {
				grantGroup(t, s, orgCarol, f, grant)
			}
			return f
		}
	}
	cases := []tc{
		{"no rights", shared(""), agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"read-only", shared("C"), agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"per-folder deny under an author parent", func(t *testing.T, s *Server) string {
			top := shared("R")(t, s)
			child := subFolder(t, s, top, "child")
			setGroupGrants(t, s, child, map[string]string{"R": "deny"})
			return child
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"human caller", shared("R"), humanAdmin, "x", codes.PermissionDenied},
		{"spoofed admin flags", shared(""), spoofedAdminSA, "x", codes.PermissionDenied},
		{"personal folder not granted", func(t *testing.T, s *Server) string {
			seedPersonalFolder(s, "user-carol")
			return "folder-personal-carol"
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"personal folder with only an everyone rule", func(t *testing.T, s *Server) string {
			seedPersonalFolder(s, "user-carol")
			injectEveryoneRule(s, "folder-personal-carol", map[string]string{"R": "allow"})
			return "folder-personal-carol"
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"master personal root", func(t *testing.T, s *Server) string {
			s.ensureMasterPersonalFolder()
			injectEveryoneRule(s, "folder-personal-root", map[string]string{"R": "allow"})
			grantGroup(t, s, humanAdmin, "folder-personal-root", "R")
			return "folder-personal-root"
		}, agentGroupActor("sa-1"), "x", codes.PermissionDenied},
		{"same name", shared("R"), agentGroupActor("sa-1"), "F", codes.InvalidArgument},
		{"sibling name taken", func(t *testing.T, s *Server) string {
			top := shared("R")(t, s)
			subFolder(t, s, top, "Taken")
			return subFolder(t, s, top, "Mine")
		}, agentGroupActor("sa-1"), "TAKEN", codes.AlreadyExists},
		{"control characters", shared("R"), agentGroupActor("sa-1"), "a\tb", codes.InvalidArgument},
		{"missing folder", func(*testing.T, *Server) string { return "folder-missing" }, agentGroupActor("sa-1"), "x", codes.NotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			id := c.setup(t, s)
			before := s.findFolder(id).GetName()
			_, err := s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{
				Actor: c.actor, Id: id, Name: c.fname,
			})
			wantCode(t, err, c.code)
			if f := s.findFolder(id); f != nil && f.GetName() != before {
				t.Fatal("denied rename must not change the folder")
			}
			if ca.find("folder.rename.principal") != nil {
				t.Fatal("denied rename must not audit")
			}
		})
	}
}

// ---- MoveFolderForPrincipal --------------------------------------------------

func TestMoveFolderForPrincipal_AuthorOnSourceAndDest(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	src, dst := mutFolder(t, s, "Src"), mutFolder(t, s, "Dst")
	grantGroup(t, s, orgCarol, src, "R")
	grantGroup(t, s, orgCarol, dst, "R")
	moving := subFolder(t, s, src, "Moving")
	child := subFolder(t, s, moving, "Child")
	secID := mutSecret(t, s, child)

	resp, err := s.MoveFolderForPrincipal(context.Background(), &vaultv1.MoveFolderForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: moving, NewParentId: dst,
	})
	if err != nil {
		t.Fatalf("MoveFolderForPrincipal: %v", err)
	}
	if s.findFolder(moving).GetParentId() != dst || resp.GetFolder().GetParentId() != dst {
		t.Fatalf("folder not moved: %+v", s.findFolder(moving))
	}
	if s.findFolder(child).GetParentId() != moving || s.findSecret(secID).GetFolderId() != child {
		t.Fatal("subtree and its secrets must move with the folder, untouched")
	}
	if s.findFolder(child).GetGroupId() != s.findFolder(dst).GetGroupId() {
		t.Fatal("moved subtree must take on the destination's scope")
	}
	ev := ca.find("folder.move.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["from_parent_id"] != src || ev.Attributes["to_parent_id"] != dst {
		t.Fatalf("move audit = %+v", ev)
	}
}

// Rearranging inside one owner's personal tree mirrors the human rule: allowed
// when the owner has explicitly granted the principal Author there.
func TestMoveFolderForPrincipal_WithinSamePersonalTreeWhenGranted(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-carol")
	grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
	a := subFolder(t, s, "folder-personal-carol", "A")
	b := subFolder(t, s, "folder-personal-carol", "B")
	if _, err := s.MoveFolderForPrincipal(context.Background(), &vaultv1.MoveFolderForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: a, NewParentId: b,
	}); err != nil {
		t.Fatalf("same-owner personal rearrange: %v", err)
	}
	if f := s.findFolder(a); f.GetParentId() != b || f.GetOwnerUserId() != "user-carol" {
		t.Fatalf("moved folder = %+v", f)
	}
}

// A move into a personal subtree (that is not rearranging within the same
// owner's tree) needs a site-admin approval. After every RACI check passes the
// vault moves nothing and signals approval_required, audited as the principal.
func TestMoveFolderForPrincipal_IntoPersonalNeedsApproval(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server) (id, dest string){
		"shared into a granted personal folder": func(t *testing.T, s *Server) (string, string) {
			src := mutFolder(t, s, "Src")
			grantGroup(t, s, orgCarol, src, "R")
			seedPersonalFolder(s, "user-carol")
			grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
			return subFolder(t, s, src, "Moving"), "folder-personal-carol"
		},
		"one user's personal tree into another's": func(t *testing.T, s *Server) (string, string) {
			seedPersonalFolder(s, "user-carol")
			seedPersonalFolder(s, "user-alice")
			grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
			s.raciRules = append(s.raciRules, &vaultv1.RaciRule{Id: "r-alice", FolderId: "folder-personal-alice",
				SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: map[string]string{"R": "allow"}})
			return subFolder(t, s, "folder-personal-carol", "Mine"), "folder-personal-alice"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			id, dest := setup(t, s)
			before := s.findFolder(id).GetParentId()
			resp, err := s.MoveFolderForPrincipal(context.Background(), &vaultv1.MoveFolderForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, NewParentId: dest,
			})
			if err != nil || !resp.GetApprovalRequired() {
				t.Fatalf("want approval_required, got resp=%v err=%v", resp, err)
			}
			if s.findFolder(id).GetParentId() != before || resp.GetFolder().GetParentId() != before {
				t.Fatal("an approval-required move must not move the folder")
			}
			if d := resp.GetDestination(); d.GetId() != dest || d.GetOwnerUserId() != "" {
				t.Fatalf("destination view = %+v", d)
			}
			ev := ca.find("folder.move.approval_required.principal")
			if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["to_parent_id"] != dest {
				t.Fatalf("approval audit = %+v", ev)
			}
			if ca.find("folder.move.principal") != nil {
				t.Fatal("no move may be audited when approval is required")
			}
		})
	}
}

func TestMoveFolderForPrincipal_Denials(t *testing.T) {
	type fx struct{ id, dest string }
	type tc struct {
		name  string
		setup func(t *testing.T, s *Server) fx
		actor *vaultv1.ActorContext
		code  codes.Code
	}
	// base: Src(grant srcG) > Moving > Child ; Dst(grant dstG)
	base := func(srcG, dstG string) func(t *testing.T, s *Server) fx {
		return func(t *testing.T, s *Server) fx {
			src, dst := mutFolder(t, s, "Src"), mutFolder(t, s, "Dst")
			if srcG != "" {
				grantGroup(t, s, orgCarol, src, srcG)
			}
			if dstG != "" {
				grantGroup(t, s, orgCarol, dst, dstG)
			}
			moving := subFolder(t, s, src, "Moving")
			subFolder(t, s, moving, "Child")
			return fx{moving, dst}
		}
	}
	sa := agentGroupActor("sa-1")
	cases := []tc{
		{"no rights on source", base("", "R"), sa, codes.PermissionDenied},
		{"no rights on destination", base("R", ""), sa, codes.PermissionDenied},
		{"read-only on destination", base("R", "C"), sa, codes.PermissionDenied},
		{"read-only on source", base("C", "R"), sa, codes.PermissionDenied},
		{"author on folder but read-only on its current parent", func(t *testing.T, s *Server) fx {
			f := base("C", "R")(t, s)
			setGroupGrants(t, s, f.id, map[string]string{"R": "allow"})
			return f
		}, sa, codes.PermissionDenied},
		{"per-folder deny on the moved folder", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			setGroupGrants(t, s, f.id, map[string]string{"R": "deny"})
			return f
		}, sa, codes.PermissionDenied},
		{"deny on a descendant folder", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			deep := subFolder(t, s, f.id, "Locked")
			setGroupGrants(t, s, deep, map[string]string{"R": "deny"})
			return f
		}, sa, codes.PermissionDenied},
		{"per-secret deny inside the subtree", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			denySecretAuthor(t, s, mutSecret(t, s, f.id))
			return f
		}, sa, codes.PermissionDenied},
		{"human caller", base("R", "R"), humanAdmin, codes.PermissionDenied},
		{"spoofed admin flags", base("", ""), spoofedAdminSA, codes.PermissionDenied},
		{"personal destination with only an everyone rule", func(t *testing.T, s *Server) fx {
			f := base("R", "")(t, s)
			seedPersonalFolder(s, "user-carol")
			injectEveryoneRule(s, "folder-personal-carol", map[string]string{"R": "allow"})
			return fx{f.id, "folder-personal-carol"}
		}, sa, codes.PermissionDenied},
		{"personal destination but a descendant is locked", func(t *testing.T, s *Server) fx {
			f := base("R", "")(t, s)
			seedPersonalFolder(s, "user-carol")
			grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
			deep := subFolder(t, s, f.id, "Locked")
			setGroupGrants(t, s, deep, map[string]string{"R": "deny"})
			return fx{f.id, "folder-personal-carol"}
		}, sa, codes.PermissionDenied},
		{"source personal folder not granted", func(t *testing.T, s *Server) fx {
			seedPersonalFolder(s, "user-carol")
			dst := mutFolder(t, s, "Dst")
			grantGroup(t, s, orgCarol, dst, "R")
			return fx{subFolder(t, s, "folder-personal-carol", "Mine"), dst}
		}, sa, codes.PermissionDenied},
		{"master personal root", func(t *testing.T, s *Server) fx {
			s.ensureMasterPersonalFolder()
			injectEveryoneRule(s, "folder-personal-root", map[string]string{"R": "allow"})
			dst := mutFolder(t, s, "Dst")
			grantGroup(t, s, orgCarol, dst, "R")
			return fx{"folder-personal-root", dst}
		}, sa, codes.PermissionDenied},
		{"cycle: into its own child", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			return fx{f.id, subFolder(t, s, f.id, "Kid")}
		}, sa, codes.InvalidArgument},
		{"cycle: into a deep descendant", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			kid := subFolder(t, s, f.id, "Kid")
			return fx{f.id, subFolder(t, s, kid, "Grandkid")}
		}, sa, codes.InvalidArgument},
		{"cycle: into itself", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			return fx{f.id, f.id}
		}, sa, codes.InvalidArgument},
		{"top-level destination", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			return fx{f.id, ""}
		}, sa, codes.InvalidArgument},
		{"already under that parent", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			return fx{f.id, s.findFolder(f.id).GetParentId()}
		}, sa, codes.InvalidArgument},
		{"missing destination", func(t *testing.T, s *Server) fx {
			f := base("R", "R")(t, s)
			return fx{f.id, "folder-missing"}
		}, sa, codes.NotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			f := c.setup(t, s)
			before := map[string]string{}
			for _, x := range s.folders {
				before[x.GetId()] = x.GetParentId() + "|" + x.GetScope().String() + "|" + x.GetOwnerUserId() + "|" + x.GetGroupId()
			}
			_, err := s.MoveFolderForPrincipal(context.Background(), &vaultv1.MoveFolderForPrincipalRequest{
				Actor: c.actor, Id: f.id, NewParentId: f.dest,
			})
			wantCode(t, err, c.code)
			for _, x := range s.folders {
				if before[x.GetId()] != x.GetParentId()+"|"+x.GetScope().String()+"|"+x.GetOwnerUserId()+"|"+x.GetGroupId() {
					t.Fatalf("denied move changed folder %s", x.GetId())
				}
			}
			if ca.find("folder.move.principal") != nil || ca.find("folder.move.approval_required.principal") != nil {
				t.Fatal("denied move must not audit a move or an approval")
			}
			if strings.Contains(err.Error(), "Locked") {
				t.Fatalf("denial must not name content the principal cannot see: %v", err)
			}
		})
	}
}
