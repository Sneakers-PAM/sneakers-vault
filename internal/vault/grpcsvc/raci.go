// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"maps"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// everyoneRules filters a ruleset down to its SUBJECT_KIND_EVERYONE rules.
func everyoneRules(rules []*vaultv1.RaciRule) []*vaultv1.RaciRule {
	var out []*vaultv1.RaciRule
	for _, r := range rules {
		if r.GetSubjectKind() == vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE {
			out = append(out, r)
		}
	}
	return out
}

// everyoneRulesUnchanged reports whether the everyone-subject rules in
// existing and incoming are equivalent: same count and, in order, the same
// Grants map per rule. Id/Order/FolderId are ignored, since a non-admin
// legitimately reordering or editing other rules can shift an everyone
// rule's absolute index without changing the everyone rule itself.
func everyoneRulesUnchanged(existing, incoming []*vaultv1.RaciRule) bool {
	existing, incoming = everyoneRules(existing), everyoneRules(incoming)
	if len(existing) != len(incoming) {
		return false
	}
	for i, e := range existing {
		if !maps.Equal(e.GetGrants(), incoming[i].GetGrants()) {
			return false
		}
	}
	return true
}

// GetFolderRuleset returns a folder's own owners + ordered firewall-RACI rules
// (the editable ruleset for that folder; ancestors are separate). Read-gated:
// anyone who can see into the folder may inspect its ruleset (e.g. to
// understand why they have the access they have); editing stays owner-gated
// (SetFolderRuleset, below).
func (s *Server) GetFolderRuleset(_ context.Context, req *vaultv1.GetFolderRulesetRequest) (*vaultv1.GetFolderRulesetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if !s.resolve(req.GetActor(), f.GetId()).Read.Allowed && !s.isFolderOwner(req.GetActor(), f) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to view this folder's ruleset")
	}
	return &vaultv1.GetFolderRulesetResponse{
		Owners: append([]string(nil), f.GetOwners()...),
		Rules:  s.raciRulesFor(f.GetId()),
	}, nil
}

// SetFolderRuleset replaces a folder's owners + ordered ruleset. Owner-gated.
// Rule ids/order are assigned server-side.
func (s *Server) SetFolderRuleset(ctx context.Context, req *vaultv1.SetFolderRulesetRequest) (*vaultv1.SetFolderRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if !s.isFolderOwner(req.GetActor(), f) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this folder's ruleset")
	}
	if !isHumanAdmin(req.GetActor()) &&
		!everyoneRulesUnchanged(s.raciRulesFor(f.GetId()), req.GetRules()) {
		return nil, status.Error(codes.PermissionDenied, "only admins can set everyone rules")
	}
	// Drop the folder's existing rules, then append the new ordered set.
	kept := s.raciRules[:0]
	for _, r := range s.raciRules {
		if r.GetFolderId() != f.GetId() {
			kept = append(kept, r)
		}
	}
	s.raciRules = kept
	for i, in := range req.GetRules() {
		s.raciRules = append(s.raciRules, &vaultv1.RaciRule{
			Id: s.nextID("raci"), FolderId: f.GetId(), Order: int32(i),
			SubjectKind: in.GetSubjectKind(), SubjectName: in.GetSubjectName(), Grants: in.GetGrants(),
		})
	}
	f.Owners = append([]string(nil), req.GetOwners()...)
	s.emit(ctx, req.GetActor().GetUserId(), "folder.ruleset.set", f.GetId(), false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "folder.ruleset.set", "folder", f.GetId(), f.GetName(), s.chainFor(f.GetId()))
	return &vaultv1.SetFolderRulesetResponse{}, nil
}

// GetTargetRuleset returns a target's own ordered RACI ruleset. A
// target has no ancestry (unlike a folder or secret), so this is just its own
// rules. Read-gated: anyone who can connect (C) via the target, or its owner,
// may inspect the ruleset — mirrors GetFolderRuleset's reasoning.
func (s *Server) GetTargetRuleset(_ context.Context, req *vaultv1.GetTargetRulesetRequest) (*vaultv1.GetTargetRulesetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := findByID(s.targets, req.GetTargetId())
	if t == nil {
		return nil, errNotFound("target")
	}
	if !s.canConnectTarget(req.GetActor(), t) && !s.isTargetOwner(req.GetActor(), t) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to view this target's ruleset")
	}
	return &vaultv1.GetTargetRulesetResponse{Ruleset: raciRulesOrdered(s.targetRulesets[t.GetId()])}, nil
}

// SetTargetRuleset replaces a target's own ordered ruleset. Owner-gated
// (site-admin/root, or the target's own personal OwnerUserId) — mirrors
// SetFolderRuleset, including the admin-only everyone-rule gate. Rule ids/
// order are assigned server-side.
func (s *Server) SetTargetRuleset(ctx context.Context, req *vaultv1.SetTargetRulesetRequest) (*vaultv1.SetTargetRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := findByID(s.targets, req.GetTargetId())
	if t == nil {
		return nil, errNotFound("target")
	}
	if !s.isTargetOwner(req.GetActor(), t) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this target's ruleset")
	}
	if !isHumanAdmin(req.GetActor()) &&
		!everyoneRulesUnchanged(s.targetRulesets[t.GetId()], req.GetRuleset()) {
		return nil, status.Error(codes.PermissionDenied, "only admins can set everyone rules")
	}
	rules := make([]*vaultv1.RaciRule, 0, len(req.GetRuleset()))
	for i, in := range req.GetRuleset() {
		rules = append(rules, &vaultv1.RaciRule{
			Id: s.nextID("raci"), Order: int32(i),
			SubjectKind: in.GetSubjectKind(), SubjectName: in.GetSubjectName(), Grants: in.GetGrants(),
		})
	}
	if s.targetRulesets == nil {
		s.targetRulesets = map[string][]*vaultv1.RaciRule{}
	}
	s.targetRulesets[t.GetId()] = rules
	s.emit(ctx, req.GetActor().GetUserId(), "target.ruleset.set", t.GetId(), false)
	return &vaultv1.SetTargetRulesetResponse{}, nil
}

// GetMyAccess resolves the actor's effective access on a folder (for UI gating).
func (s *Server) GetMyAccess(_ context.Context, req *vaultv1.GetMyAccessRequest) (*vaultv1.GetMyAccessResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	res := s.resolve(req.GetActor(), req.GetFolderId())
	return &vaultv1.GetMyAccessResponse{Access: &vaultv1.FolderAccess{
		Read:          res.Read.Allowed,
		Reveal:        res.Read.Allowed, // v1: reveal == read (RACI C)
		Manage:        res.Author.Allowed,
		Approve:       res.Approve.Allowed,
		Informed:      res.Ack.Allowed,
		ManageRuleset: s.isFolderOwner(req.GetActor(), f),
	}}, nil
}

// GetSecretRuleset returns a secret's own ordered firewall-RACI overrides.
// Read-gated: allowed to anyone who can see the secret (read OR ack on the
// secret-inclusive chain), so a member who only has "informed" can still
// understand why they see (or don't see) it.
func (s *Server) GetSecretRuleset(_ context.Context, req *vaultv1.GetSecretRulesetRequest) (*vaultv1.GetSecretRulesetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	res := s.resolveSecret(req.GetActor(), sec)
	if !res.Read.Allowed && !res.Ack.Allowed {
		return nil, status.Error(codes.PermissionDenied, "not permitted to view this secret's ruleset")
	}
	return &vaultv1.GetSecretRulesetResponse{Rules: raciRulesOrdered(sec.GetRuleset())}, nil
}

// SetSecretRuleset replaces a secret's own ordered ruleset. Gated by
// ownership of the secret's folder (secrets have no owners of their own).
func (s *Server) SetSecretRuleset(ctx context.Context, req *vaultv1.SetSecretRulesetRequest) (*vaultv1.SetSecretRulesetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	f := s.findFolder(sec.GetFolderId())
	if f == nil || !s.isFolderOwner(req.GetActor(), f) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this secret's ruleset")
	}
	if !isHumanAdmin(req.GetActor()) &&
		!everyoneRulesUnchanged(sec.GetRuleset(), req.GetRules()) {
		return nil, status.Error(codes.PermissionDenied, "only admins can set everyone rules")
	}
	rules := make([]*vaultv1.RaciRule, 0, len(req.GetRules()))
	for i, in := range req.GetRules() {
		rules = append(rules, &vaultv1.RaciRule{
			Id: s.nextID("raci"), Order: int32(i),
			SubjectKind: in.GetSubjectKind(), SubjectName: in.GetSubjectName(), Grants: in.GetGrants(),
		})
	}
	sec.Ruleset = rules
	s.emit(ctx, req.GetActor().GetUserId(), "secret.ruleset.set", sec.GetId(), false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.ruleset.set", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.SetSecretRulesetResponse{Rules: append([]*vaultv1.RaciRule(nil), rules...)}, nil
}

// GetMySecretAccess resolves the actor's effective access on a secret (its own
// ruleset first, then its folder chain), for UI gating.
func (s *Server) GetMySecretAccess(_ context.Context, req *vaultv1.GetMySecretAccessRequest) (*vaultv1.GetMySecretAccessResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	res := s.resolveSecret(req.GetActor(), sec)
	manageRuleset := false
	if f := s.findFolder(sec.GetFolderId()); f != nil {
		manageRuleset = s.isFolderOwner(req.GetActor(), f)
	}
	return &vaultv1.GetMySecretAccessResponse{Access: &vaultv1.FolderAccess{
		Read:          res.Read.Allowed,
		Reveal:        res.Read.Allowed, // v1: reveal == read (RACI C)
		Manage:        res.Author.Allowed,
		Approve:       res.Approve.Allowed,
		Informed:      res.Ack.Allowed,
		ManageRuleset: manageRuleset,
	}}, nil
}
