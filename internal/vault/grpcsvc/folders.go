// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *Server) ListFolders(_ context.Context, req *vaultv1.ListFoldersRequest) (*vaultv1.ListFoldersResponse, error) {
	reqActor := req.GetActor()
	actor := reqActor.GetUserId()
	// ListFolders is a pure read and must never mutate state: personal
	// folders are provisioned on an actual WRITE (CreateFolder — see there),
	// never as a side effect of merely listing. Without this, ANY actor whose
	// user_id reaches this RPC — including a synthetic/service caller that
	// never legitimately "owns" a vault presence — spawns an orphan Personal
	// folder just by looking. A real interactive user still ends up with one
	// the moment they actually create something (or via SeedBuiltins for the
	// /setup admin).
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Shared folders + the master personal root are visible to everyone; a
	// user's own personal folders only to them. Another user's personal folders
	// are never listed here — NOT even for a site-admin/root: access to someone
	// else's personal folder is by explicit share or an audited break-the-glass
	// (which notifies the owner), never by blanket admin visibility.
	out := make([]*vaultv1.Folder, 0, len(s.folders))
	for _, f := range s.folders {
		if f.Scope != vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL || f.IsMasterPersonal || f.OwnerUserId == actor {
			// Clone so the derived subtree count never mutates stored state.
			cp := proto.Clone(f).(*vaultv1.Folder)
			cp.SubtreeSecretCount = s.activeSubtreeSecretCount(f.GetId())
			// can_manage mirrors the SAME gate CreateFolder enforces for
			// creating a subfolder here, so the UI can show/hide the
			// folder context-menu/create affordance without guessing at
			// backend authorization: site-admin/root, the personal-folder
			// owner, or any owner in the ancestor chain (inherits down).
			cp.CanManage = s.isFolderOwner(reqActor, cp)
			out = append(out, cp)
		}
	}
	return &vaultv1.ListFoldersResponse{Folders: out}, nil
}

// descendantIDs returns the folder id plus every descendant's id.
func (s *Server) descendantIDs(id string) map[string]bool {
	set := map[string]bool{id: true}
	for grew := true; grew; {
		grew = false
		for _, f := range s.folders {
			if f.ParentId != "" && set[f.ParentId] && !set[f.Id] {
				set[f.Id] = true
				grew = true
			}
		}
	}
	return set
}

// subtreeSecretCount counts ALL secrets in a folder and all its descendants,
// including retired (soft-deleted) ones. This is the folder-emptiness SAFETY
// gate a no-reassign DeleteFolder checks before cascade-deleting: cascadeDelete
// never touches s.secrets, so a retired-but-not-hard-deleted secret left
// pointing at a removed folder would be silently orphaned if it weren't
// counted here. Not what the UI should display — see activeSubtreeSecretCount.
func (s *Server) subtreeSecretCount(id string) int32 {
	sub := s.descendantIDs(id)
	var n int32
	for _, sec := range s.secrets {
		if sub[sec.FolderId] {
			n++
		}
	}
	return n
}

// activeSubtreeSecretCount is subtreeSecretCount excluding retired secrets —
// the count ListFolders reports as Folder.SubtreeSecretCount. Retired
// secrets are already hidden from ListSecretsInFolder's default view, so
// counting them here made a folder look non-empty ("subtree_secret_count"
// stuck above 0) even after its only secret had been retired/deleted and the
// folder itself deleted via reassign — i.e. no live secret left — while the
// raw (all-secrets) count still saw the retired row. Always computed live from current state, never cached, so it
// can never go stale independent of this exclusion.
func (s *Server) activeSubtreeSecretCount(id string) int32 {
	sub := s.descendantIDs(id)
	var n int32
	for _, sec := range s.secrets {
		if sub[sec.FolderId] && !sec.GetRetired() {
			n++
		}
	}
	return n
}

func (s *Server) CreateFolder(ctx context.Context, req *vaultv1.CreateFolderRequest) (*vaultv1.CreateFolderResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "folder name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Provision the actor's own personal folder here — a genuine WRITE the
	// actor explicitly asked for — rather than as a side effect of a read.
	// This is the "legitimate provisioning" moment for every real user
	// (dev seed users, the /setup admin via SeedBuiltins, and any user's first
	// CreateFolder alike); it's a no-op once already provisioned, and never
	// fires for "system"/empty actors. Same lock, so no separate persist/
	// invalidate call is needed — PersistUnary covers this RPC already.
	s.ensurePersonalFolder(req.GetActor().GetUserId())
	id := s.nextID("folder")
	var f *vaultv1.Folder
	if pid := req.GetParentId(); pid != "" {
		parent := s.findFolder(pid)
		if parent == nil {
			return nil, errNotFound("parent folder")
		}
		// Creating a subfolder is owner-gated on the parent subtree. isFolderOwner
		// already short-circuits for site-admin/root, so a site-admin (e.g. an
		// `admin`-role user) can always create anywhere, and a group folder's owner
		// (its Owners entry, inherited DOWN the subtree) can create under it —
		// even though neither is auto-granted RACI Author. A non-owner
		// non-admin is denied.
		if !s.isFolderOwner(req.GetActor(), parent) {
			return nil, status.Error(codes.PermissionDenied, "not permitted to create a folder here")
		}
		// A subfolder inherits its parent's scope and owning subject.
		f = &vaultv1.Folder{
			Id: id, Name: req.GetName(), ParentId: pid, Scope: parent.Scope,
			OwnerUserId: parent.OwnerUserId, GroupId: parent.GroupId, Role: parent.Role,
			Order: safeconv.Int32(s.childCount(pid)),
		}
	} else {
		// A new top-level folder is a shared group folder; the creator becomes
		// its RACI owner so they can immediately manage its ruleset.
		var owners []string
		if a := req.GetActor().GetUserId(); a != "" {
			owners = []string{a}
		}
		f = &vaultv1.Folder{
			Id: id, Name: req.GetName(), Scope: vaultv1.FolderScope_FOLDER_SCOPE_GROUP,
			GroupId: "group-" + id, Order: safeconv.Int32(s.childCount("")), Owners: owners,
		}
	}
	s.folders = append(s.folders, f)
	s.emit(ctx, req.GetActor().GetUserId(), "folder.create", f.Id, false)
	return &vaultv1.CreateFolderResponse{Folder: f}, nil
}

func (s *Server) RenameFolder(ctx context.Context, req *vaultv1.RenameFolderRequest) (*vaultv1.RenameFolderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if err := s.requireFolderOwner(ctx, req.GetActor(), f, "RenameFolder"); err != nil {
		return nil, err
	}
	f.Name = req.GetName()
	s.emit(ctx, req.GetActor().GetUserId(), "folder.rename", f.Id, false)
	return &vaultv1.RenameFolderResponse{Folder: f}, nil
}

func (s *Server) MoveFolder(ctx context.Context, req *vaultv1.MoveFolderRequest) (*vaultv1.MoveFolderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	actor := req.GetActor()
	// You must own or manage the folder being moved (mirrors DeleteFolder).
	if !s.isFolderOwner(actor, f) && !s.canManage(actor, f.GetId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to move this folder")
	}
	// Guard against cycles: a folder cannot move into itself or a descendant.
	if req.GetNewParentId() != "" && s.descendantIDs(f.GetId())[req.GetNewParentId()] {
		return nil, status.Error(codes.InvalidArgument, "cannot move a folder into itself or one of its descendants")
	}

	dest := s.findFolder(req.GetNewParentId()) // nil = move to top level (shared)
	destPersonal, destOwner := s.destPersonal(dest)

	// Move rule: personal -> shared and rearranging your own personal tree
	// are free (subject to the ownership check above). Moving content INTO a
	// personal space that isn't already yours (shared content, or another user's
	// personal content) requires site-admin. A non-admin never reaches here for
	// that case directly — the gateway routes it to an approval whose effect
	// re-invokes MoveFolder with a system/site-admin actor.
	if destPersonal {
		alreadyOwned := f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && f.GetOwnerUserId() == destOwner
		if !alreadyOwned && !isHumanAdmin(actor) {
			return nil, status.Error(codes.PermissionDenied, "moving content into a personal folder requires site-admin approval")
		}
	}

	f.ParentId = req.GetNewParentId()
	// Reconcile the moved subtree's scope/owner/group/role to its new location so
	// content actually takes on where it now lives (shared -> personal becomes
	// personal-owned; personal -> shared adopts the group/role). Without this the
	// subtree kept its old scope — a latent bug that made "move to personal"
	// leave content group-visible.
	s.rescopeSubtree(f, dest, destPersonal, destOwner)
	s.emit(ctx, actor.GetUserId(), "folder.move", f.Id, false)
	return &vaultv1.MoveFolderResponse{Folder: f}, nil
}

// destPersonal reports whether a destination parent lives in a personal subtree
// and, if so, the owning user. dest=nil (top level) is not personal.
func (s *Server) destPersonal(dest *vaultv1.Folder) (bool, string) {
	if dest == nil {
		return false, ""
	}
	for _, anc := range s.ancestorsInclusive(dest.GetId()) {
		if anc.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL {
			return true, anc.GetOwnerUserId()
		}
	}
	return false, ""
}

// rescopeSubtree reconciles a moved folder + all its descendants to the scope,
// owner, group and role of its new location. A personal destination makes the
// subtree personal-owned by that user; a shared destination adopts the dest's
// group/role; top level (dest=nil) becomes a top-level shared (group) folder.
func (s *Server) rescopeSubtree(f, dest *vaultv1.Folder, destPersonal bool, destOwner string) {
	var scope vaultv1.FolderScope
	var owner, group, role string
	switch {
	case destPersonal:
		scope, owner = vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, destOwner
	case dest == nil:
		scope = vaultv1.FolderScope_FOLDER_SCOPE_GROUP // top-level shared
	default:
		scope, group, role = dest.GetScope(), dest.GetGroupId(), dest.GetRole()
	}
	ids := s.descendantIDs(f.GetId())
	for _, fld := range s.folders {
		if ids[fld.GetId()] {
			fld.Scope, fld.OwnerUserId, fld.GroupId, fld.Role = scope, owner, group, role
			fld.IsMasterPersonal = false
		}
	}
}

// DeleteFolder removes a folder (RACI-gated: owner or manage). With no
// reassign target the subtree must hold NO secrets — then the folder and all
// its (empty) descendants are cascade-deleted. If secrets exist, a reassign
// target is required and the folder's direct children + secrets move to it.
func (s *Server) DeleteFolder(ctx context.Context, req *vaultv1.DeleteFolderRequest) (*vaultv1.DeleteFolderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetId())
	if f == nil {
		return &vaultv1.DeleteFolderResponse{}, nil
	}
	if !s.isFolderOwner(req.GetActor(), f) && !s.canManage(req.GetActor(), f.GetId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to delete this folder")
	}
	chain := s.chainFor(f.GetId()) // captured before removal
	if reassign := req.GetReassignToId(); reassign != "" {
		s.reassignChildren(req.GetId(), reassign)
		s.removeFolders(map[string]bool{req.GetId(): true})
	} else {
		if s.subtreeSecretCount(req.GetId()) > 0 {
			return nil, status.Error(codes.InvalidArgument, "folder is not empty — reassign its secrets to another folder first")
		}
		s.cascadeDelete(req.GetId())
	}
	s.emit(ctx, req.GetActor().GetUserId(), "folder.delete", req.GetId(), false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "folder.delete", "folder", f.GetId(), f.GetName(), chain)
	return &vaultv1.DeleteFolderResponse{}, nil
}

// reassignChildren moves a folder's DIRECT children + secrets to another folder.
func (s *Server) reassignChildren(id, reassign string) {
	for _, f := range s.folders {
		if f.ParentId == id {
			f.ParentId = reassign
		}
	}
	for _, sec := range s.secrets {
		if sec.FolderId == id {
			sec.FolderId = reassign
		}
	}
}

// cascadeDelete removes a folder, all descendants, and their RACI rules
// (caller has verified the subtree holds no secrets).
func (s *Server) cascadeDelete(id string) {
	sub := s.descendantIDs(id)
	s.removeFolders(sub)
	kept := s.raciRules[:0]
	for _, r := range s.raciRules {
		if !sub[r.GetFolderId()] {
			kept = append(kept, r)
		}
	}
	s.raciRules = kept
}

func (s *Server) removeFolders(ids map[string]bool) {
	out := s.folders[:0]
	for _, f := range s.folders {
		if !ids[f.Id] {
			out = append(out, f)
		}
	}
	s.folders = out
}

// ReorderFolders orders a parent's children: the parent's owner may, and for
// top-level folders only a site admin.
func (s *Server) ReorderFolders(ctx context.Context, req *vaultv1.ReorderFoldersRequest) (*vaultv1.ReorderFoldersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.GetParentId() == "" {
		if err := s.requireSiteAdmin(ctx, req.GetActor(), "ReorderFolders"); err != nil {
			return nil, err
		}
	} else {
		parent := s.findFolder(req.GetParentId())
		if parent == nil {
			return nil, errNotFound("folder")
		}
		if err := s.requireFolderOwner(ctx, req.GetActor(), parent, "ReorderFolders"); err != nil {
			return nil, err
		}
	}
	for i, id := range req.GetOrderedIds() {
		if f := s.findFolder(id); f != nil && f.ParentId == req.GetParentId() {
			f.Order = int32(i)
		}
	}
	return &vaultv1.ReorderFoldersResponse{}, nil
}

func (s *Server) ListFolderRules(_ context.Context, req *vaultv1.ListFolderRulesRequest) (*vaultv1.ListFolderRulesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultv1.FolderAccessRule
	for _, r := range s.rules {
		if r.FolderId == req.GetFolderId() {
			out = append(out, r)
		}
	}
	return &vaultv1.ListFolderRulesResponse{Rules: out}, nil
}

func (s *Server) GetInheritedFolderRules(_ context.Context, req *vaultv1.GetInheritedFolderRulesRequest) (*vaultv1.GetInheritedFolderRulesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultv1.InheritedFolderRule
	start := s.findFolder(req.GetFolderId())
	if start == nil {
		return &vaultv1.GetInheritedFolderRulesResponse{}, nil
	}
	// Walk ancestors (excluding the folder itself), each at most once so a
	// parent cycle cannot spin.
	seen := map[string]bool{start.Id: true}
	for cur := s.findFolder(start.ParentId); cur != nil && !seen[cur.Id]; cur = s.findFolder(cur.ParentId) {
		seen[cur.Id] = true
		for _, r := range s.rules {
			if r.FolderId == cur.Id {
				out = append(out, &vaultv1.InheritedFolderRule{Rule: r, FromFolderId: cur.Id, FromFolderName: cur.Name})
			}
		}
		if cur.ParentId == "" {
			break
		}
	}
	return &vaultv1.GetInheritedFolderRulesResponse{Rules: out}, nil
}

func (s *Server) AddFolderRule(ctx context.Context, req *vaultv1.AddFolderRuleRequest) (*vaultv1.AddFolderRuleResponse, error) {
	in := req.GetRule()
	if in == nil || in.GetFolderId() == "" || in.GetSubjectId() == "" {
		return nil, status.Error(codes.InvalidArgument, "rule requires folder and subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	folder := s.findFolder(in.GetFolderId())
	if folder == nil {
		return nil, errNotFound("folder")
	}
	// Personal folders belong to their owner (always full access) — no RBAC.
	if folder.Scope == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL {
		return nil, status.Error(codes.FailedPrecondition, "personal folders cannot have RBAC rules")
	}
	if err := s.requireFolderOwner(ctx, req.GetActor(), folder, "AddFolderRule"); err != nil {
		return nil, err
	}
	rule := &vaultv1.FolderAccessRule{
		Id: s.nextID("rule"), FolderId: in.GetFolderId(),
		SubjectKind: in.GetSubjectKind(), SubjectId: in.GetSubjectId(), Role: in.GetRole(),
	}
	s.rules = append(s.rules, rule)
	s.emit(ctx, req.GetActor().GetUserId(), "folder.rule.add", in.GetFolderId(), false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "folder.rule.add", "folder", in.GetFolderId(), folder.GetName(), s.chainFor(in.GetFolderId()))
	return &vaultv1.AddFolderRuleResponse{Rule: rule}, nil
}

func (s *Server) RemoveFolderRule(ctx context.Context, req *vaultv1.RemoveFolderRuleRequest) (*vaultv1.RemoveFolderRuleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The rule holds the folder id; capture it before the rule is removed so
	// the Informed notification can still resolve which folder this affects.
	var folderID string
	for _, r := range s.rules {
		if r.Id == req.GetId() {
			folderID = r.GetFolderId()
			break
		}
	}
	if folderID == "" {
		return &vaultv1.RemoveFolderRuleResponse{}, nil
	}
	if err := s.requireFolderOwner(ctx, req.GetActor(), s.findFolder(folderID), "RemoveFolderRule"); err != nil {
		return nil, err
	}
	out := s.rules[:0]
	for _, r := range s.rules {
		if r.Id != req.GetId() {
			out = append(out, r)
		}
	}
	s.rules = out
	s.emit(ctx, req.GetActor().GetUserId(), "folder.rule.remove", req.GetId(), false)
	f := s.findFolder(folderID)
	label := ""
	if f != nil {
		label = f.GetName()
	}
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "folder.rule.remove", "folder", folderID, label, s.chainFor(folderID))
	return &vaultv1.RemoveFolderRuleResponse{}, nil
}

func (s *Server) childCount(parentID string) int {
	n := 0
	for _, f := range s.folders {
		if f.ParentId == parentID {
			n++
		}
	}
	return n
}
