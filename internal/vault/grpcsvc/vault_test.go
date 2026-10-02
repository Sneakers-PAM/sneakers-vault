// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	return New(crypto.New(kek), nil)
}

// newServerWithEnv builds a Server as newServer does, but running as the
// given environment (e.g. "prod"), for exercising the DeleteSecret prod gate.
func newServerWithEnv(t *testing.T, environment string) *Server {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kek), nil, environment)
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	// NewWithStore no longer seeds an empty store (a real fresh DB now stays
	// empty until /setup runs SeedBuiltins); seed the in-memory test server so
	// tests still have the built-in baseline, mirroring New().
	s.seed()
	return s
}

func code(err error) codes.Code { return status.Code(err) }

// newSharedFolder creates a top-level shared "Platform Team" folder and grants
// user-carol OWNER on it, returning its id. No shared folder is
// seeded, so tests exercising shared access build their own.
func newSharedFolder(t *testing.T, s *Server) string {
	t.Helper()
	// The creator (carol) becomes the folder's RACI owner (auto read+approve+author).
	f, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "Platform Team",
	})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	return f.GetFolder().GetId()
}

// seedPersonalFolder inserts a user's personal folder with the deterministic id
// folder-personal-<short> that these tests assert on. The live code creates
// personal folders on demand via ensurePersonalFolder with a generated id, so
// tests that need a known id seed one directly (same shape ensurePersonalFolder
// produces: PERSONAL scope, hung under the master personal root, owned by user).
func seedPersonalFolder(s *Server, userID string) {
	s.folders = append(s.folders, &vaultv1.Folder{
		Id: "folder-personal-" + strings.TrimPrefix(userID, "user-"), Name: "Personal",
		ParentId: "folder-personal-root", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL,
		OwnerUserId: userID,
	})
}

// TestEmptyStoreStaysEmpty proves a fresh (Postgres-like) empty store is NOT
// auto-seeded: the built-in baseline is installed on demand by SeedBuiltins as
// part of /setup, and the vault runs fine empty in the meantime.
func TestEmptyStoreStaysEmpty(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	// PROD: a fresh empty store stays empty (no auto-seed) — the baseline is
	// installed on demand by SeedBuiltins via /setup. (Dev/qa auto-seed on boot;
	// see TestDevAutoSeedsBaseline below.)
	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kek), nil, "prod")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	types, _ := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if len(types.GetTypes()) != 0 {
		t.Fatalf("fresh empty store has %d types, want 0", len(types.GetTypes()))
	}
	folders, err := s.ListFolders(context.Background(), &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}})
	if err != nil {
		t.Fatalf("ListFolders on empty vault: %v", err)
	}
	if len(folders.GetFolders()) != 0 {
		t.Fatalf("fresh empty store has %d folders, want 0", len(folders.GetFolders()))
	}
}

// TestDevAutoSeedsBaseline proves dev/qa auto-installs the built-in baseline on
// boot (no /setup): a fresh dev store comes up with the secret-type catalog
// (incl. type-oauth) already present.
func TestDevAutoSeedsBaseline(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kek), nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	types, _ := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if len(types.GetTypes()) == 0 {
		t.Fatal("dev boot did not auto-seed the built-in secret types")
	}
	var hasOAuth bool
	for _, tp := range types.GetTypes() {
		if tp.GetId() == "type-oauth" {
			hasOAuth = true
		}
	}
	if !hasOAuth {
		t.Fatal("dev auto-seed missing type-oauth")
	}
}

// TestSeedBuiltinsInstallsBaselineIdempotently proves SeedBuiltins installs the
// full baseline into an empty vault, ensures the acting admin's personal
// folder, and is idempotent (a second call adds nothing and returns the same
// totals).
func TestSeedBuiltinsInstallsBaselineIdempotently(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kek), nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	actor := &vaultv1.ActorContext{UserId: "user-admin", IsRoot: true, IsSiteAdmin: true}
	first, err := s.SeedBuiltins(context.Background(), &vaultv1.SeedBuiltinsRequest{Actor: actor})
	if err != nil {
		t.Fatalf("SeedBuiltins: %v", err)
	}
	if int(first.GetTypes()) != len(BuiltinTypes()) {
		t.Fatalf("types = %d, want %d", first.GetTypes(), len(BuiltinTypes()))
	}
	if int(first.GetConnections()) != len(BuiltinConnections()) {
		t.Fatalf("connections = %d, want %d", first.GetConnections(), len(BuiltinConnections()))
	}
	// master personal root + the acting admin's personal folder.
	if first.GetFolders() != 2 {
		t.Fatalf("folders = %d, want 2 (master root + admin personal)", first.GetFolders())
	}
	// The admin now sees exactly their own personal folder + the master root.
	fl, _ := s.ListFolders(context.Background(), &vaultv1.ListFoldersRequest{Actor: actor})
	var adminPersonal int
	for _, f := range fl.GetFolders() {
		if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && !f.GetIsMasterPersonal() && f.GetOwnerUserId() == "user-admin" {
			adminPersonal++
		}
	}
	if adminPersonal != 1 {
		t.Fatalf("admin personal folders = %d, want 1", adminPersonal)
	}
	// Idempotent: a second call adds nothing and returns identical totals.
	second, err := s.SeedBuiltins(context.Background(), &vaultv1.SeedBuiltinsRequest{Actor: actor})
	if err != nil {
		t.Fatalf("SeedBuiltins (2nd): %v", err)
	}
	if second.GetTypes() != first.GetTypes() || second.GetConnections() != first.GetConnections() || second.GetFolders() != first.GetFolders() {
		t.Fatalf("idempotency broken: first=%v second=%v", first, second)
	}
}

func TestSeedTypesListed(t *testing.T) {
	s := newServer(t)
	resp, err := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	if want := len(BuiltinTypes()); len(resp.GetTypes()) != want {
		t.Fatalf("got %d seed types, want %d (the full built-in catalogue)", len(resp.GetTypes()), want)
	}
}

func TestCreateThenRevealRequiresAccess(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s) // carol is OWNER
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "api token", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret", "notes": "n"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	// Owner reveals the sensitive field.
	rev, err := s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: carol, Id: created.GetSecret().GetId(), FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretField(owner): %v", err)
	}
	if rev.GetValue() != "Sup3r$ecret" {
		t.Fatalf("revealed %q, want Sup3r$ecret", rev.GetValue())
	}

	// A user with no grant is denied.
	_, err = s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-nobody"}, Id: created.GetSecret().GetId(), FieldKey: "password",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("reveal by non-member: want PermissionDenied, got %v", err)
	}
}

func TestRevealNonSensitiveRejected(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, _ := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "x", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "p"},
	})
	_, err := s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: carol, Id: created.GetSecret().GetId(), FieldKey: "username",
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("reveal non-sensitive: want InvalidArgument, got %v", err)
	}
}

func TestGetSecretFieldsExcludesSensitive(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, _ := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "x", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "secret", "notes": "hi"},
	})
	resp, err := s.GetSecretFields(context.Background(), &vaultv1.GetSecretFieldsRequest{Actor: carol, Id: created.GetSecret().GetId()})
	if err != nil {
		t.Fatalf("GetSecretFields: %v", err)
	}
	if _, leaked := resp.GetFields()["password"]; leaked {
		t.Fatal("password (sensitive) leaked via GetSecretFields")
	}
	if resp.GetFields()["username"] != "svc" {
		t.Fatalf("username = %q, want svc", resp.GetFields()["username"])
	}
}

func TestDeleteSystemTypeBlocked(t *testing.T) {
	s := newServer(t)
	_, err := s.DeleteSecretType(context.Background(), &vaultv1.DeleteSecretTypeRequest{Actor: siteAdmin, Id: "type-password"})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("delete system type: want FailedPrecondition, got %v", err)
	}
}

func TestDeleteTypeInUseBlocked(t *testing.T) {
	s := newServer(t)
	// type-windows-domain is used by the seed secret.
	_, err := s.DeleteSecretType(context.Background(), &vaultv1.DeleteSecretTypeRequest{Actor: siteAdmin, Id: "type-windows-domain"})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("delete in-use type: want FailedPrecondition, got %v", err)
	}
}

func TestCloneProducesEditableCustom(t *testing.T) {
	s := newServer(t)
	resp, err := s.CloneSecretType(context.Background(), &vaultv1.CloneSecretTypeRequest{Actor: siteAdmin, Id: "type-password"})
	if err != nil {
		t.Fatalf("CloneSecretType: %v", err)
	}
	if resp.GetType().GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM {
		t.Fatalf("clone origin = %v, want CUSTOM", resp.GetType().GetOrigin())
	}
	// The clone is now deletable (custom, unused).
	del, err := s.DeleteSecretType(context.Background(), &vaultv1.DeleteSecretTypeRequest{Actor: siteAdmin, Id: resp.GetType().GetId()})
	if err != nil || !del.GetRemoved() {
		t.Fatalf("delete cloned custom type: removed=%v err=%v", del.GetRemoved(), err)
	}
}

func TestPersonalFolderRejectsRule(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-turing")
	_, err := s.AddFolderRule(context.Background(), &vaultv1.AddFolderRuleRequest{
		Rule: &vaultv1.FolderAccessRule{FolderId: "folder-personal-turing", SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectId: "user-x", Role: vaultv1.FolderRole_FOLDER_ROLE_READ},
	})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("rule on personal folder: want FailedPrecondition, got %v", err)
	}
}

func TestListFoldersHidesOthersPersonal(t *testing.T) {
	s := newServer(t)
	has := func(resp *vaultv1.ListFoldersResponse, id string) bool {
		for _, f := range resp.GetFolders() {
			if f.GetId() == id {
				return true
			}
		}
		return false
	}
	fid := newSharedFolder(t, s)
	seedPersonalFolder(s, "user-turing")
	carol, _ := s.ListFolders(context.Background(), &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}})
	if has(carol, "folder-personal-turing") {
		t.Fatal("Carol must NOT see Alan Turing's personal folder")
	}
	if !has(carol, fid) || !has(carol, "folder-personal-root") {
		t.Fatal("Carol must see shared folders and the master personal root")
	}
	turing, _ := s.ListFolders(context.Background(), &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-turing"}})
	if !has(turing, "folder-personal-turing") {
		t.Fatal("Turing must see their own personal folder")
	}
}

// countOwnedPersonal counts non-master personal folders in resp owned by userID.
func countOwnedPersonal(resp *vaultv1.ListFoldersResponse, userID string) int {
	n := 0
	for _, f := range resp.GetFolders() {
		if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && !f.GetIsMasterPersonal() && f.GetOwnerUserId() == userID {
			n++
		}
	}
	return n
}

// TestListFoldersNeverCreatesPersonalFolder proves ListFolders is a pure read: calling it for a brand-new actor — including a repeat call, and
// including an actor that looks like a synthetic/service caller rather than a
// real logged-in user — never provisions a personal folder as a side effect.
// Only an actual write (CreateFolder, see TestCreateFolderProvisionsOwnPersonalFolder
// below) or SeedBuiltins does that.
func TestListFoldersNeverCreatesPersonalFolder(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	before := len(s.folders)

	for range 2 { // repeat: still must not create, and must not error
		resp, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-newbie"}})
		if err != nil {
			t.Fatalf("ListFolders: %v", err)
		}
		if n := countOwnedPersonal(resp, "user-newbie"); n != 0 {
			t.Fatalf("ListFolders must not create a personal folder; got %d", n)
		}
	}
	if len(s.folders) != before {
		t.Fatalf("folders = %d after ListFolders access, want unchanged %d", len(s.folders), before)
	}
}

// TestCreateFolderProvisionsOwnPersonalFolder proves the legitimate
// provisioning path: a real user's first WRITE — here, creating a
// top-level shared folder — ensures their own personal folder as a side
// effect, exactly once, without leaking it to other users' folder lists.
func TestCreateFolderProvisionsOwnPersonalFolder(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	newbie := &vaultv1.ActorContext{UserId: "user-newbie"}

	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: newbie, Name: "My Shared Folder"}); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	first, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: newbie})
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if n := countOwnedPersonal(first, "user-newbie"); n != 1 {
		t.Fatalf("personal folders after CreateFolder = %d, want 1", n)
	}

	// Another user must never see it.
	other, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-someone-else"}})
	if err != nil {
		t.Fatalf("ListFolders(other): %v", err)
	}
	if countOwnedPersonal(other, "user-newbie") != 0 {
		t.Fatal("another user must not see user-newbie's provisioned personal folder")
	}

	// A second write is idempotent: no duplicate is created.
	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: newbie, Name: "Another Shared Folder"}); err != nil {
		t.Fatalf("CreateFolder (2nd): %v", err)
	}
	second, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: newbie})
	if err != nil {
		t.Fatalf("ListFolders (2nd): %v", err)
	}
	if n := countOwnedPersonal(second, "user-newbie"); n != 1 {
		t.Fatalf("personal folders after second CreateFolder = %d, want 1 (no duplicate)", n)
	}
}

// TestListFoldersSystemAndEmptyActorCreateNothing proves ListFolders never
// creates anything for a "system" or empty actor (seed()'s demo path and any
// non-user caller) either — a narrower case of TestListFoldersNeverCreatesPersonalFolder,
// kept as its own regression since it once had dedicated handling.
func TestListFoldersSystemAndEmptyActorCreateNothing(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	before := len(s.folders)
	if _, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "system"}}); err != nil {
		t.Fatalf("ListFolders(system): %v", err)
	}
	if _, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{}); err != nil {
		t.Fatalf("ListFolders(empty actor): %v", err)
	}
	if len(s.folders) != before {
		t.Fatalf("folders = %d after system/empty actor access, want unchanged %d", len(s.folders), before)
	}
}

// TestRaciInheritanceAndFirewall exercises the firewall-RACI engine end-to-end
// through the vault: a C-allow on a parent inherits to a child; a deny below an
// allow wins (first-match); site-admin reads; a no-rule user is denied.
func TestRaciInheritanceAndFirewall(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	parent := newSharedFolder(t, s)
	child, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: carol, ParentId: parent, Name: "Web Tier"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	cid := child.GetFolder().GetId()

	// Owner grants user-turing C (read) on the PARENT.
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: parent, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(parent): %v", err)
	}
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: cid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss", "notes": "n"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(child): %v", err)
	}
	sid := created.GetSecret().GetId()
	reveal := func(user string) codes.Code {
		_, err := s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
			Actor: &vaultv1.ActorContext{UserId: user}, Id: sid, FieldKey: "password",
		})
		return code(err)
	}

	// turing inherits C from the parent → can reveal in the child.
	if reveal("user-turing") != codes.OK {
		t.Fatal("turing should inherit read (C) from the parent folder")
	}
	// A user with no rule anywhere → default deny.
	if reveal("user-nobody") != codes.PermissionDenied {
		t.Fatal("no-rule user must be denied")
	}
	// site-admin reads everything.
	if _, err := s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}, Id: sid, FieldKey: "password",
	}); err != nil {
		t.Fatalf("site-admin reveal: %v", err)
	}
	// Firewall: a DENY on the child (target, evaluated first) beats the parent's allow.
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: cid,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"C": "deny"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(child deny): %v", err)
	}
	if reveal("user-turing") != codes.PermissionDenied {
		t.Fatal("child deny must override the parent allow (first-match-wins down the chain)")
	}
	// A non-owner cannot edit the ruleset.
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-nobody"}, FolderId: parent,
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-owner SetFolderRuleset: want PermissionDenied, got %v", err)
	}
}

// ---- DeleteFolder: empty-subtree cascade vs reassign vs RACI gate ----------

func folderIDs(t *testing.T, s *Server, actor string) map[string]bool {
	t.Helper()
	resp, err := s.ListFolders(context.Background(), &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: actor}})
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	ids := map[string]bool{}
	for _, f := range resp.GetFolders() {
		ids[f.GetId()] = true
	}
	return ids
}

func TestDeleteFolderEmptyCascades(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	parent := newSharedFolder(t, s) // carol OWNER
	child, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, ParentId: parent, Name: "empty child"})
	if err != nil {
		t.Fatalf("CreateFolder child: %v", err)
	}
	cid := child.GetFolder().GetId()
	// No secrets anywhere → delete parent with NO reassign cascades parent+child.
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: carol, Id: parent}); err != nil {
		t.Fatalf("DeleteFolder(empty, no reassign): %v", err)
	}
	ids := folderIDs(t, s, "user-carol")
	if ids[parent] || ids[cid] {
		t.Fatalf("parent %q or child %q still present after cascade delete", parent, cid)
	}
}

func TestDeleteFolderWithSecretsNeedsReassign(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	src := newSharedFolder(t, s)
	dst, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "Dest"})
	if err != nil {
		t.Fatalf("CreateFolder dst: %v", err)
	}
	did := dst.GetFolder().GetId()
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "api token", FolderId: src, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	// No reassign + a secret present → refused.
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: carol, Id: src}); code(err) != codes.InvalidArgument {
		t.Fatalf("delete non-empty w/o reassign: got %v, want InvalidArgument", code(err))
	}
	// With reassign → secret relocated to dst, folder gone.
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: carol, Id: src, ReassignToId: did}); err != nil {
		t.Fatalf("delete w/ reassign: %v", err)
	}
	if folderIDs(t, s, "user-carol")[src] {
		t.Fatalf("src folder still present after reassign delete")
	}
	got, err := s.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: carol, Id: sid})
	if err != nil {
		t.Fatalf("GetSecret after reassign: %v", err)
	}
	if got.GetSecret().GetFolderId() != did {
		t.Fatalf("secret folder = %q, want reassign target %q", got.GetSecret().GetFolderId(), did)
	}
}

func TestDeleteFolderNonOwnerDenied(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	parent := newSharedFolder(t, s) // carol OWNER
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: &vaultv1.ActorContext{UserId: "user-nobody"}, Id: parent}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-owner delete: got %v, want PermissionDenied", code(err))
	}
}

// ---- Per-secret RACI ruleset (evaluated before the folder's ruleset) ------

func TestPerSecretDenyOverridesFolderAllow(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	// Everyone rules are admin-only to set; the owner (carol) does not touch it here.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: admin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: carol, SecretId: sid,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"C": "deny"},
		}},
	}); err != nil {
		t.Fatalf("SetSecretRuleset: %v", err)
	}
	reveal := func(user string) codes.Code {
		_, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{
			Actor: &vaultv1.ActorContext{UserId: user}, Id: sid, FieldKey: "password",
		})
		return code(err)
	}
	if reveal("user-x") != codes.PermissionDenied {
		t.Fatal("per-secret deny for user-x must override the folder's everyone-allow")
	}
	if reveal("user-y") != codes.OK {
		t.Fatal("user-y (no per-secret deny) must still inherit the folder's everyone-allow")
	}
}

func TestPerSecretDenyDoesNotAffectOwner(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	// Everyone rules are admin-only to set; the owner (carol) does not touch it here.
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: admin, SecretId: sid,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "deny"},
		}},
	}); err != nil {
		t.Fatalf("SetSecretRuleset: %v", err)
	}
	if _, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{
		Actor: carol, Id: sid, FieldKey: "password",
	}); err != nil {
		t.Fatalf("owner reveal despite everyone-deny secret ruleset: %v", err)
	}
}

func TestPerSecretAllowWidens(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	// Folder grants user-x only I (informed), not C.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"I": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: carol, SecretId: sid,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetSecretRuleset: %v", err)
	}
	if _, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-x"}, Id: sid, FieldKey: "password",
	}); err != nil {
		t.Fatalf("per-secret allow should widen access beyond the folder's I-only grant: %v", err)
	}
}

func TestManageRulesetFlag(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	// Grant a plain member read on the folder so their GetMy*Access calls
	// resolve without a NotFound/PermissionDenied side-effect masking the flag.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-member",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}

	folderAccess := func(actor *vaultv1.ActorContext) bool {
		resp, err := s.GetMyAccess(ctx, &vaultv1.GetMyAccessRequest{Actor: actor, FolderId: fid})
		if err != nil {
			t.Fatalf("GetMyAccess: %v", err)
		}
		return resp.GetAccess().GetManageRuleset()
	}
	secretAccess := func(actor *vaultv1.ActorContext) bool {
		resp, err := s.GetMySecretAccess(ctx, &vaultv1.GetMySecretAccessRequest{Actor: actor, SecretId: sid})
		if err != nil {
			t.Fatalf("GetMySecretAccess: %v", err)
		}
		return resp.GetAccess().GetManageRuleset()
	}

	if !folderAccess(carol) {
		t.Fatal("owner GetMyAccess.manage_ruleset must be true")
	}
	if !secretAccess(carol) {
		t.Fatal("owner GetMySecretAccess.manage_ruleset must be true")
	}
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if !folderAccess(admin) {
		t.Fatal("site-admin GetMyAccess.manage_ruleset must be true")
	}
	if !secretAccess(admin) {
		t.Fatal("site-admin GetMySecretAccess.manage_ruleset must be true")
	}
	member := &vaultv1.ActorContext{UserId: "user-member"}
	if folderAccess(member) {
		t.Fatal("plain member GetMyAccess.manage_ruleset must be false")
	}
	if secretAccess(member) {
		t.Fatal("plain member GetMySecretAccess.manage_ruleset must be false")
	}
}

func TestNonOwnerReadsFolderRuleset(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-member",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	member := &vaultv1.ActorContext{UserId: "user-member"}
	if _, err := s.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: member, FolderId: fid}); err != nil {
		t.Fatalf("GetFolderRuleset(non-owner reader): %v", err)
	}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{Actor: member, FolderId: fid}); code(err) != codes.PermissionDenied {
		t.Fatalf("SetFolderRuleset(non-owner): want PermissionDenied, got %v", err)
	}
}

func TestSetSecretRulesetGating(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	rules := []*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
		Grants: map[string]string{"C": "deny"},
	}}
	nonOwner := &vaultv1.ActorContext{UserId: "user-nobody"}
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: nonOwner, SecretId: sid, Rules: rules}); code(err) != codes.PermissionDenied {
		t.Fatalf("SetSecretRuleset(non-owner): want PermissionDenied, got %v", err)
	}
	setResp, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: carol, SecretId: sid, Rules: rules})
	if err != nil {
		t.Fatalf("SetSecretRuleset(owner): %v", err)
	}
	if len(setResp.GetRules()) != 1 {
		t.Fatalf("SetSecretRuleset response rules = %d, want 1", len(setResp.GetRules()))
	}
	getResp, err := s.GetSecretRuleset(ctx, &vaultv1.GetSecretRulesetRequest{Actor: carol, SecretId: sid})
	if err != nil {
		t.Fatalf("GetSecretRuleset: %v", err)
	}
	if len(getResp.GetRules()) != 1 || getResp.GetRules()[0].GetSubjectName() != "user-x" {
		t.Fatalf("GetSecretRuleset did not return the persisted rule: %+v", getResp.GetRules())
	}
}

func TestSubtreeSecretCountReported(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	parent := newSharedFolder(t, s)
	if _, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s1", FolderId: parent, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	}); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	resp, _ := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: carol})
	for _, f := range resp.GetFolders() {
		if f.GetId() == parent && f.GetSubtreeSecretCount() != 1 {
			t.Fatalf("subtree_secret_count = %d, want 1", f.GetSubtreeSecretCount())
		}
	}
}

// subtreeSecretCountOf finds a folder by id in a ListFolders response and
// returns its reported subtree_secret_count (-1 if not found).
func subtreeSecretCountOf(resp *vaultv1.ListFoldersResponse, id string) int32 {
	for _, f := range resp.GetFolders() {
		if f.GetId() == id {
			return f.GetSubtreeSecretCount()
		}
	}
	return -1
}

// TestSubtreeSecretCountDecrementsOnDelete proves that after hard-deleting
// the last secret under a subtree AND deleting the (now-empty) folder that
// held it, an ancestor's subtree_secret_count must reflect 0 — not a stale
// non-zero value. subtree_secret_count is computed live on every ListFolders
// call (never cached), so this exercises that live recompute end-to-end.
func TestSubtreeSecretCountDecrementsOnDelete(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	parent := newSharedFolder(t, s)
	childResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, ParentId: parent, Name: "sub"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	child := childResp.GetFolder().GetId()
	secResp, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s1", FolderId: child, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	before, _ := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: carol})
	if got := subtreeSecretCountOf(before, parent); got != 1 {
		t.Fatalf("before delete: parent subtree_secret_count = %d, want 1", got)
	}

	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: carol, Id: secResp.GetSecret().GetId()}); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: carol, Id: child}); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}

	after, _ := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: carol})
	if got := subtreeSecretCountOf(after, parent); got != 0 {
		t.Fatalf("after delete: parent subtree_secret_count = %d, want 0", got)
	}
}

// TestSubtreeSecretCountExcludesRetired covers this case:
// retiring (the common soft-"delete" affordance) a folder's only secret and
// then deleting the folder itself via reassign — which, unlike a no-reassign
// cascade delete, does not require the subtree to be empty and so does not
// hard-remove the retired secret — must not leave an ancestor's
// subtree_secret_count stuck above 0. A retired secret is already excluded
// from ListSecretsInFolder's default view, so the count must read 0,
// matching what the user sees.
func TestSubtreeSecretCountExcludesRetired(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	root := newSharedFolder(t, s)
	childResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, ParentId: root, Name: "sub"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	child := childResp.GetFolder().GetId()
	secResp, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "s1", FolderId: child, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: secResp.GetSecret().GetId()}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	// A retired secret still counts toward the folder-emptiness safety gate,
	// so a no-reassign cascade delete would be (correctly) blocked here;
	// reassign the (retired) contents up to root instead, the same path a
	// reassigning delete takes when contents land under folder-personal-root.
	if _, err := s.DeleteFolder(ctx, &vaultv1.DeleteFolderRequest{Actor: carol, Id: child, ReassignToId: root}); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}

	resp, _ := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: carol})
	if got := subtreeSecretCountOf(resp, root); got != 0 {
		t.Fatalf("root subtree_secret_count = %d, want 0 (retired secret must not count)", got)
	}
}

// ---- everyone-rule admin-only gate ------------------------------------------

func TestNonAdminCannotAddEveryoneRule(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	_, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin adding an everyone rule: want PermissionDenied, got %v", err)
	}
}

func TestNonAdminCannotChangeOrRemoveEveryoneRule(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	// Seed an everyone rule as admin.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: admin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("seed everyone rule as admin: %v", err)
	}
	// Non-admin owner tries to change the everyone rule's grants.
	_, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "deny"},
		}},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin changing an everyone rule: want PermissionDenied, got %v", err)
	}
	// Non-admin owner tries to remove the everyone rule (omit it entirely).
	_, err = s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin removing an everyone rule: want PermissionDenied, got %v", err)
	}
}

func TestNonAdminMayEditNonEveryoneRulesWhenEveryoneUnchanged(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	everyoneRule := &vaultv1.RaciRule{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
		Grants:      map[string]string{"C": "allow"},
	}
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: admin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{everyoneRule},
	}); err != nil {
		t.Fatalf("seed everyone rule as admin: %v", err)
	}
	// Non-admin owner keeps the everyone rule's grants identical but adds a USER rule.
	_, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{
			everyoneRule,
			{
				SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
				Grants: map[string]string{"C": "allow"},
			},
		},
	})
	if err != nil {
		t.Fatalf("non-admin editing non-everyone rules with everyone unchanged: want OK, got %v", err)
	}
}

func TestAdminMaySetEveryoneRule(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: admin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("admin setting an everyone rule: want OK, got %v", err)
	}
	// Admin may also change it afterward.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: admin, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
			Grants:      map[string]string{"C": "deny"},
		}},
	}); err != nil {
		t.Fatalf("admin changing an everyone rule: want OK, got %v", err)
	}
}

func TestSecretRulesetEveryoneAdminOnly(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()
	everyoneRule := &vaultv1.RaciRule{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE,
		Grants:      map[string]string{"C": "allow"},
	}
	// Non-admin owner adding a secret-level everyone rule → denied.
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: carol, SecretId: sid, Rules: []*vaultv1.RaciRule{everyoneRule},
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin adding a secret everyone rule: want PermissionDenied, got %v", err)
	}
	// Admin adding the same rule → OK.
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: admin, SecretId: sid, Rules: []*vaultv1.RaciRule{everyoneRule},
	}); err != nil {
		t.Fatalf("admin adding a secret everyone rule: want OK, got %v", err)
	}
}

// TestSimulateFolderDraftRules exercises the simulator against DRAFT (unsaved)
// rules: the folder owner previews a rule granting user-turing C=allow before
// saving, and a user with no matching rule still resolves to denied.
func TestSimulateFolderDraftRules(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	draft := []*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
		Grants: map[string]string{"C": "allow"},
	}}

	resp, err := s.SimulateFolder(ctx, &vaultv1.SimulateFolderRequest{
		Actor: carol, FolderId: fid, SimUserId: "user-turing", DraftRules: draft,
	})
	if err != nil {
		t.Fatalf("SimulateFolder(user-turing): %v", err)
	}
	dec := resp.GetDecision()
	if !dec.GetRead() || !dec.GetReveal() {
		t.Fatalf("user-turing: want read+reveal allowed from draft rule, got %+v", dec)
	}
	if dec.GetReadReason() == "" || dec.GetRevealReason() == "" {
		t.Fatalf("user-turing: want non-empty reasons, got %+v", dec)
	}

	// The draft rule is unsaved — GetFolderRuleset must not see it.
	rs, err := s.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: carol, FolderId: fid})
	if err != nil {
		t.Fatalf("GetFolderRuleset: %v", err)
	}
	if len(rs.GetRules()) != 0 {
		t.Fatalf("draft rule leaked into persisted ruleset: %+v", rs.GetRules())
	}

	// A different simulated user, matching no rule, resolves to denied.
	resp2, err := s.SimulateFolder(ctx, &vaultv1.SimulateFolderRequest{
		Actor: carol, FolderId: fid, SimUserId: "user-clarke", DraftRules: draft,
	})
	if err != nil {
		t.Fatalf("SimulateFolder(user-clarke): %v", err)
	}
	if resp2.GetDecision().GetRead() {
		t.Fatalf("user-clarke: want read denied (no matching draft rule), got %+v", resp2.GetDecision())
	}
}

// TestSimulateFolderGating asserts SimulateFolder is owner-gated: a caller
// with no ownership on the folder — even one who can read it — is denied.
func TestSimulateFolderGating(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // creator ⇒ owner
	fid := newSharedFolder(t, s)
	// Grant user-x read (C) on the folder — enough to see in, not enough to
	// manage its ruleset or run the simulator.
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-x",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}

	nonOwner := &vaultv1.ActorContext{UserId: "user-x"}
	if _, err := s.SimulateFolder(ctx, &vaultv1.SimulateFolderRequest{
		Actor: nonOwner, FolderId: fid, SimUserId: "user-x",
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-owner SimulateFolder: want PermissionDenied, got %v", err)
	}
}

// ---- secret lifecycle: retire / restore / hard-delete -----------------------

// createLifecycleSecret creates a shared folder owned by user-carol plus one
// secret in it, returning (folderID, secretID).
func createLifecycleSecret(t *testing.T, s *Server) (string, string) {
	t.Helper()
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "db creds", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return fid, created.GetSecret().GetId()
}

func TestRetireHidesFromListingIncludeRetiredShowsIt(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid, sid := createLifecycleSecret(t, s)

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}

	listed, err := s.ListSecretsInFolder(ctx, &vaultv1.ListSecretsInFolderRequest{FolderId: fid})
	if err != nil {
		t.Fatalf("ListSecretsInFolder: %v", err)
	}
	if len(listed.GetSecrets()) != 0 {
		t.Fatalf("retired secret should be hidden by default, got %d", len(listed.GetSecrets()))
	}

	withRetired, err := s.ListSecretsInFolder(ctx, &vaultv1.ListSecretsInFolderRequest{FolderId: fid, IncludeRetired: true})
	if err != nil {
		t.Fatalf("ListSecretsInFolder(include_retired): %v", err)
	}
	if len(withRetired.GetSecrets()) != 1 {
		t.Fatalf("include_retired should show the retired secret, got %d", len(withRetired.GetSecrets()))
	}
	if !withRetired.GetSecrets()[0].GetRetired() || withRetired.GetSecrets()[0].GetRetiredAt() == "" {
		t.Fatalf("retired secret should carry Retired=true and a RetiredAt timestamp")
	}
}

func TestRestoreBringsSecretBack(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid, sid := createLifecycleSecret(t, s)

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	if _, err := s.RestoreSecret(ctx, &vaultv1.RestoreSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("RestoreSecret: %v", err)
	}

	listed, err := s.ListSecretsInFolder(ctx, &vaultv1.ListSecretsInFolderRequest{FolderId: fid})
	if err != nil {
		t.Fatalf("ListSecretsInFolder: %v", err)
	}
	if len(listed.GetSecrets()) != 1 {
		t.Fatalf("restored secret should reappear in default listing, got %d", len(listed.GetSecrets()))
	}
	if listed.GetSecrets()[0].GetRetired() || listed.GetSecrets()[0].GetRetiredAt() != "" {
		t.Fatalf("restored secret should have Retired=false and empty RetiredAt")
	}
}

func TestRevealAndCopyRejectRetiredSecret(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	_, sid := createLifecycleSecret(t, s)

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}

	if _, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: carol, Id: sid, FieldKey: "password"}); code(err) != codes.FailedPrecondition {
		t.Fatalf("reveal on retired secret: want FailedPrecondition, got %v", err)
	}
	if _, err := s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: carol, Id: sid}); code(err) != codes.FailedPrecondition {
		t.Fatalf("copy on retired secret: want FailedPrecondition, got %v", err)
	}

	// GetSecret still returns the retired secret (so a retired view can show it).
	got, err := s.GetSecret(ctx, &vaultv1.GetSecretRequest{Id: sid})
	if err != nil {
		t.Fatalf("GetSecret on retired secret: %v", err)
	}
	if !got.GetSecret().GetRetired() {
		t.Fatalf("GetSecret should still return the retired secret")
	}
}

func TestDeleteSecretHardRemovesIt(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	_, sid := createLifecycleSecret(t, s)

	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.GetSecret(ctx, &vaultv1.GetSecretRequest{Id: sid}); code(err) != codes.NotFound {
		t.Fatalf("GetSecret after delete: want NotFound, got %v", err)
	}
}

func TestNonManagerCannotRetireOrDeleteSecret(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	_, sid := createLifecycleSecret(t, s)
	outsider := &vaultv1.ActorContext{UserId: "user-turing"} // no grant on this folder at all

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: outsider, Id: sid}); code(err) != codes.PermissionDenied {
		t.Fatalf("outsider RetireSecret: want PermissionDenied, got %v", err)
	}
	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: outsider, Id: sid}); code(err) != codes.PermissionDenied {
		t.Fatalf("outsider DeleteSecret: want PermissionDenied, got %v", err)
	}
}

func TestDeleteSecretProdGateRequiresSiteAdmin(t *testing.T) {
	s := newServerWithEnv(t, "prod")
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // folder owner, but not a site admin
	_, sid := createLifecycleSecret(t, s)

	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: carol, Id: sid}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin DeleteSecret in prod: want PermissionDenied, got %v", err)
	}

	admin := &vaultv1.ActorContext{UserId: "admin", IsSiteAdmin: true}
	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: admin, Id: sid}); err != nil {
		t.Fatalf("site-admin DeleteSecret in prod: want OK, got %v", err)
	}
	if _, err := s.GetSecret(ctx, &vaultv1.GetSecretRequest{Id: sid}); code(err) != codes.NotFound {
		t.Fatalf("GetSecret after admin delete: want NotFound, got %v", err)
	}
}

// TestCreateFolderUnderGroupGate proves that creating a folder under a
// group-scoped parent must be permitted for a site-admin (even a non-owner) and
// for the group folder's own owner, and denied for a non-owner non-admin.
// For example, a site-admin who owns a top-level group folder (Scope=GROUP,
// Owners:[user-dave]) must not be denied, even though RACI Author is never
// auto-granted to a site-admin.
func TestCreateFolderUnderGroupGate(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	// user-dave creates the top-level group folder and becomes its RACI owner
	// (Scope=GROUP, Owners:[user-dave]).
	dave := &vaultv1.ActorContext{UserId: "user-dave"}
	parentResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: dave, Name: "Infrastructure"})
	if err != nil {
		t.Fatalf("CreateFolder(group parent): %v", err)
	}
	parent := parentResp.GetFolder().GetId()
	if got := parentResp.GetFolder().GetScope(); got != vaultv1.FolderScope_FOLDER_SCOPE_GROUP {
		t.Fatalf("parent scope: want GROUP, got %v", got)
	}

	// (a) a site-admin who does NOT own the folder may create under it.
	admin := &vaultv1.ActorContext{UserId: "user-otheradmin", IsSiteAdmin: true}
	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: admin, ParentId: parent, Name: "admin-child"}); err != nil {
		t.Fatalf("site-admin CreateFolder under group: want OK, got %v", err)
	}

	// (b) the group folder's owner may create under it (and down its subtree).
	childResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: dave, ParentId: parent, Name: "owner-child"})
	if err != nil {
		t.Fatalf("owner CreateFolder under group: want OK, got %v", err)
	}
	// ownership inherits DOWN the subtree: the owner may create under a descendant.
	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{
		Actor: dave, ParentId: childResp.GetFolder().GetId(), Name: "owner-grandchild",
	}); err != nil {
		t.Fatalf("owner CreateFolder under descendant: want OK, got %v", err)
	}

	// (c) a non-owner non-admin is denied.
	nobody := &vaultv1.ActorContext{UserId: "user-nobody"}
	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: nobody, ParentId: parent, Name: "nope"}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-owner non-admin CreateFolder under group: want PermissionDenied, got %v", err)
	}

	// root (is_root) may likewise create anywhere.
	root := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true}
	if _, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: root, ParentId: parent, Name: "root-child"}); err != nil {
		t.Fatalf("root CreateFolder under group: want OK, got %v", err)
	}
}

// TestListFoldersSetsCanManage proves ListFolders derives Folder.can_manage
// from the SAME isFolderOwner gate CreateFolder enforces for creating a
// subfolder, so the UI can gate the folder context-menu/create affordance on
// the actual backend authorization instead of guessing at it.
func TestListFoldersSetsCanManage(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	canManage := func(resp *vaultv1.ListFoldersResponse, id string) bool {
		for _, f := range resp.GetFolders() {
			if f.GetId() == id {
				return f.GetCanManage()
			}
		}
		t.Fatalf("folder %s not found in response", id)
		return false
	}

	// owner creates a top-level group folder (becomes its RACI owner) and a
	// child under it; the child inherits ownership rather than getting its
	// own Owners entry (see CreateFolder), which is exactly the inheritance
	// case can_manage must cover.
	owner := &vaultv1.ActorContext{UserId: "user-dave"}
	parentResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: owner, Name: "Infrastructure"})
	if err != nil {
		t.Fatalf("CreateFolder(parent): %v", err)
	}
	parent := parentResp.GetFolder().GetId()
	childResp, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: owner, ParentId: parent, Name: "child"})
	if err != nil {
		t.Fatalf("CreateFolder(child): %v", err)
	}
	child := childResp.GetFolder().GetId()
	if owners := childResp.GetFolder().GetOwners(); len(owners) != 0 {
		t.Fatalf("child folder must have its own Owners empty (inherited ownership), got %v", owners)
	}

	// direct owner: can_manage = true on the folder they own directly.
	ownerResp, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: owner})
	if err != nil {
		t.Fatalf("ListFolders(owner): %v", err)
	}
	if !canManage(ownerResp, parent) {
		t.Fatal("direct owner: can_manage on own folder want true, got false")
	}
	// ownership inherits DOWN: the ancestor owner also can_manage a descendant
	// whose own Owners list is empty.
	if !canManage(ownerResp, child) {
		t.Fatal("ancestor owner viewing descendant (inherited ownership): can_manage want true, got false")
	}

	// admin-role (site-admin, non-root) actor who owns nothing: can_manage =
	// true everywhere via isFolderOwner's site-admin short-circuit.
	admin := &vaultv1.ActorContext{UserId: "user-otheradmin", IsSiteAdmin: true}
	adminResp, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: admin})
	if err != nil {
		t.Fatalf("ListFolders(admin): %v", err)
	}
	if !canManage(adminResp, parent) || !canManage(adminResp, child) {
		t.Fatal("site-admin: can_manage want true for both parent and child")
	}

	// root (is_root) actor: can_manage = true everywhere too.
	root := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true}
	rootResp, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: root})
	if err != nil {
		t.Fatalf("ListFolders(root): %v", err)
	}
	if !canManage(rootResp, parent) || !canManage(rootResp, child) {
		t.Fatal("root: can_manage want true for both parent and child")
	}

	// a non-owner stranger: can_manage = false on both.
	stranger := &vaultv1.ActorContext{UserId: "user-stranger"}
	strangerResp, err := s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: stranger})
	if err != nil {
		t.Fatalf("ListFolders(stranger): %v", err)
	}
	if canManage(strangerResp, parent) || canManage(strangerResp, child) {
		t.Fatal("non-owner stranger: can_manage want false for both parent and child")
	}
}
