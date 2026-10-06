// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"google.golang.org/grpc/codes"
)

// Secret use approval refusal reasons.
const (
	ReasonApprovalRequired = "APPROVAL_REQUIRED"
	ReasonSelfApproval     = "SELF_APPROVAL"
	ReasonNotApprover      = "NOT_APPROVER"
	ReasonNotRequester     = "NOT_REQUESTER"
	ReasonOtherApprover    = "OTHER_APPROVER"
	ReasonNoApprover       = "NO_APPROVER"
)

// runConfirmSpan is how long one confirmation covers later uses in the same
// run by the same requester, so one task asks at most once.
const runConfirmSpan = time.Hour

// approvalLevel is a secret's approval level: 0 none, 1 approval-required
// (owners exempt), 2 always-approve (everyone).
func approvalLevel(sec *vaultv1.Secret) int {
	switch {
	case sec.GetAlwaysRequireApproval():
		return 2
	case sec.GetRequireTokenApproval():
		return 1
	}
	return 0
}

// secretOwners lists the secret's owners: every owner of its folder and the
// folder's ancestors, and a personal folder's owner. Caller holds s.mu.
func (s *Server) secretOwners(sec *vaultv1.Secret) []string {
	var out []string
	for _, c := range s.chainFor(sec.GetFolderId()) {
		for _, o := range c.Owners {
			if o != "" && !slices.Contains(out, o) {
				out = append(out, o)
			}
		}
	}
	return out
}

func (s *Server) isSecretOwner(uid string, sec *vaultv1.Secret) bool {
	return uid != "" && slices.Contains(s.secretOwners(sec), uid)
}

// useNeedsApproval reports whether a use by uid waits for a decision.
// Caller holds s.mu.
func (s *Server) useNeedsApproval(uid string, sec *vaultv1.Secret) bool {
	switch approvalLevel(sec) {
	case 2:
		return true
	case 1:
		return !s.isSecretOwner(uid, sec)
	}
	return false
}

// eligibleApprover reports whether the person a may decide uses of sec,
// whoever asked: an owner of the secret, or for an always-approve secret also
// a designated approver (RACI A on the secret). Caller holds s.mu.
func (s *Server) eligibleApprover(a *vaultv1.ActorContext, sec *vaultv1.Secret) bool {
	uid := a.GetUserId()
	if uid == "" || uid == "system" {
		return false
	}
	if s.isSecretOwner(uid, sec) {
		return true
	}
	if approvalLevel(sec) < 2 {
		return false
	}
	human := &vaultv1.ActorContext{UserId: uid, GroupNames: a.GetGroupNames(), GroupIds: a.GetGroupIds(), IsSiteAdmin: a.GetIsSiteAdmin(), IsRoot: a.GetIsRoot()}
	return s.resolveSecret(human, sec).Approve.Allowed
}

// mayDecide reports whether the signed-in person a may approve a use that
// requester asked for: never their own. Caller holds s.mu.
func (s *Server) mayDecide(a *vaultv1.ActorContext, sec *vaultv1.Secret, requester string) bool {
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || a.GetUserId() == requester {
		return false
	}
	return s.eligibleApprover(a, sec)
}

// soleUser reports a single-user install: the active people are known and
// none of them is anyone but the requester.
func soleUser(users *vaultv1.ActiveUsers, requester string) bool {
	if users == nil {
		return false
	}
	for _, id := range users.GetUserIds() {
		if id != requester {
			return false
		}
	}
	return true
}

// otherDeciderMayExist reports whether someone besides the requester could
// decide a use of sec. Owners and user approver rules are counted only when
// active (when the active people are known). A group or everyone approver
// rule counts unless the install is single-user, since its members aren't
// known here. Caller holds s.mu.
func (s *Server) otherDeciderMayExist(sec *vaultv1.Secret, requester string, users *vaultv1.ActiveUsers) bool {
	var act map[string]bool
	if users != nil {
		act = make(map[string]bool, len(users.GetUserIds()))
		for _, id := range users.GetUserIds() {
			act[id] = true
		}
	}
	isOther := func(id string) bool { return id != "" && id != requester && (act == nil || act[id]) }
	for _, o := range s.secretOwners(sec) {
		if isOther(o) {
			return true
		}
	}
	if approvalLevel(sec) < 2 {
		return false
	}
	sole := soleUser(users, requester)
	for _, c := range s.secretChain(sec) {
		for _, r := range c.Rules {
			if approverRuleMayCoverOther(r, sole, isOther) {
				return true
			}
		}
	}
	return false
}

// approverRuleMayCoverOther reports whether rule r grants approve to someone
// besides the requester: a named other user, or any group or everyone rule
// outside a single-user install.
func approverRuleMayCoverOther(r authz.Rule, sole bool, isOther func(string) bool) bool {
	if r.Grants[authz.ActApprove] != authz.GrantAllow {
		return false
	}
	if r.Subject.Kind == authz.SubjUser {
		return isOther(r.Subject.Name)
	}
	return !sole
}

// confirmMode reports whether a pending use by requester (acting as a) is
// confirmed by the requester rather than decided by someone else, and
// whether anyone can settle it at all. Caller holds s.mu.
func (s *Server) confirmMode(a *vaultv1.ActorContext, sec *vaultv1.Secret, users *vaultv1.ActiveUsers) (confirm, decidable bool) {
	uid := a.GetUserId()
	if s.otherDeciderMayExist(sec, uid, users) {
		return false, true
	}
	if soleUser(users, uid) || s.eligibleApprover(a, sec) {
		return true, true
	}
	return false, false
}

// checkWebApproval refuses a person's direct reveal or copy when the secret's
// approval level says they need a decision: the web then prepares a reveal
// use instead. Machine principals take the principal paths. Caller holds
// s.mu.
func (s *Server) checkWebApproval(ctx context.Context, actor *vaultv1.ActorContext, sec *vaultv1.Secret, action string) error {
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || !s.useNeedsApproval(actor.GetUserId(), sec) {
		return nil
	}
	s.lg(ctx).Info("web reveal needs approval", log.F("secret_id", sec.GetId()), log.F("user_id", actor.GetUserId()), log.F("action", action))
	s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal.approval_required", sec.GetId(), true, map[string]string{
		"action": action, "via": "web", "approval_level": strconv.Itoa(approvalLevel(sec)),
	})
	return refuseCode(codes.FailedPrecondition, ReasonApprovalRequired, "this secret needs an owner's or approver's approval for each reveal; prepare a reveal use")
}
