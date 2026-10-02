// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// simRequest is satisfied by both Simulate*Request messages: the sim_* fields
// describing the SIMULATED user under evaluation (never the real caller, which
// is req.Actor and only gates the simulate call itself).
type simRequest interface {
	GetSimUserId() string
	GetSimIsSiteAdmin() bool
	GetSimIsRoot() bool
	GetSimGroupNames() []string
	GetSimGroupIds() []string
}

// simSubject builds the authz subject for the simulated user a Simulate*
// request describes.
func simSubject(req simRequest) authz.EvalSubject {
	return authz.EvalSubject{
		UserID:      req.GetSimUserId(),
		IsSiteAdmin: req.GetSimIsSiteAdmin(),
		IsRoot:      req.GetSimIsRoot(),
		GroupNames:  req.GetSimGroupNames(),
		GroupIDs:    req.GetSimGroupIds(),
	}
}

// draftRulesToAuthz converts unsaved RaciRule drafts to authz Rules,
// using the same subject-kind/grant mapping as the persisted path (rulesetOf /
// rulesetOfSecret).
func draftRulesToAuthz(draft []*vaultv1.RaciRule) []authz.Rule {
	ordered := raciRulesOrdered(draft)
	rules := make([]authz.Rule, 0, len(ordered))
	for _, r := range ordered {
		grants := make(map[authz.Action]authz.Grant, len(r.GetGrants()))
		for k, v := range r.GetGrants() {
			grants[authz.Action(k)] = authz.Grant(v)
		}
		rules = append(rules, authz.Rule{
			Subject: ruleSubjectOf(r),
			Grants:  grants,
		})
	}
	return rules
}

// draftRuleset maps a folder to an authz CategoryRuleset like
// rulesetOf, but with Rules built from an unsaved draft instead of the
// persisted raciRulesFor — used by SimulateFolder to preview in-progress
// ruleset edits before they're saved. Owners still come from the folder as
// usual (a draft never edits ownership).
func draftRuleset(f *vaultv1.Folder, draft []*vaultv1.RaciRule) authz.CategoryRuleset {
	owners := append([]string(nil), f.GetOwners()...)
	if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && f.GetOwnerUserId() != "" {
		owners = append(owners, f.GetOwnerUserId())
	}
	return authz.CategoryRuleset{Name: f.GetName(), Owners: owners, Rules: draftRulesToAuthz(draft)}
}

// raciDecisionOf maps a resolved authz.ActionResult to the wire RaciDecision:
// reveal mirrors read (v1: C == reveal), manage/approve/informed map to
// author/approve/ack.
func raciDecisionOf(res authz.ActionResult) *vaultv1.RaciDecision {
	return &vaultv1.RaciDecision{
		Read: res.Read.Allowed, ReadReason: res.Read.Reason,
		Reveal: res.Read.Allowed, RevealReason: res.Read.Reason,
		Manage: res.Author.Allowed, ManageReason: res.Author.Reason,
		Approve: res.Approve.Allowed, ApproveReason: res.Approve.Reason,
		Informed: res.Ack.Allowed, InformedReason: res.Ack.Reason,
	}
}

// SimulateFolder evaluates a DRAFT (unsaved) folder ruleset for an arbitrary
// simulated user, so a ruleset editor can preview the effect of in-progress
// changes before saving. Read-only —
// never persisted — so it is deliberately absent from mutatingMethods.
// Gated to the folder's owners: simulate is an editor tool, not a general
// read.
func (s *Server) SimulateFolder(_ context.Context, req *vaultv1.SimulateFolderRequest) (*vaultv1.SimulateFolderResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if !s.isFolderOwner(req.GetActor(), f) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to simulate this folder's ruleset")
	}
	// The folder's own ruleset comes from the draft; its ancestors are
	// unaffected by an in-progress edit, so they're resolved as persisted.
	chain := []authz.CategoryRuleset{draftRuleset(f, req.GetDraftRules())}
	chain = append(chain, s.chainFor(f.GetParentId())...)
	return &vaultv1.SimulateFolderResponse{
		Decision: raciDecisionOf(authz.Resolve(simSubject(req), chain)),
	}, nil
}

// SimulateSecret evaluates a DRAFT (unsaved) secret-level ruleset for an
// arbitrary simulated user, against the secret's real (persisted) folder
// chain. Gated to the secret's folder owners, same rationale as
// SimulateFolder.
func (s *Server) SimulateSecret(_ context.Context, req *vaultv1.SimulateSecretRequest) (*vaultv1.SimulateSecretResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	f := s.findFolder(sec.GetFolderId())
	if f == nil || !s.isFolderOwner(req.GetActor(), f) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to simulate this secret's ruleset")
	}
	// Secrets have no owners of their own; the draft ruleset is evaluated
	// first (most specific), then the secret's real folder chain.
	chain := []authz.CategoryRuleset{{Name: sec.GetName(), Rules: draftRulesToAuthz(req.GetDraftRules())}}
	chain = append(chain, s.chainFor(sec.GetFolderId())...)
	return &vaultv1.SimulateSecretResponse{
		Decision: raciDecisionOf(authz.Resolve(simSubject(req), chain)),
	}, nil
}
