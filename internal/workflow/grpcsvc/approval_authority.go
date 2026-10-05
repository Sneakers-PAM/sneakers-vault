// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"google.golang.org/grpc/codes"
)

// Approval refusal reasons.
const (
	ReasonNotApprover  = "NOT_APPROVER"
	ReasonSelfApproval = "SELF_APPROVAL"
)

// isSiteAdmin reports whether a is a site admin or root naming a real user;
// an empty or "system" user id never passes as an admin.
func isSiteAdmin(a *workflowv1.ActorContext) bool {
	uid := a.GetUserId()
	return uid != "" && uid != "system" && (a.GetIsSiteAdmin() || a.GetIsRoot())
}

// checkApprover refuses a resolve by anyone but an eligible approver: RACI A
// on the secret for an access request, a site admin for a move. Nobody
// resolves their own request. Unknown requests pass through to the store's
// not-found handling.
func (s *Server) checkApprover(ctx context.Context, actor *workflowv1.ActorContext, requestID string) error {
	r, err := s.store.GetRequest(ctx, requestID)
	if err != nil || r == nil {
		return err
	}
	uid := actor.GetUserId()
	deny := func(reason, msg string) error {
		s.lg(ctx).Warn("approval refused", log.F("request_id", requestID), log.F("user_id", uid), log.F("reason", reason))
		s.emit(ctx, uid, "approval.denied", requestID, map[string]string{"reason": reason, "kind": r.GetKind().String()})
		return refuse(codes.PermissionDenied, reason, msg, nil)
	}
	if uid != "" && uid == r.GetRequestedByUserId() {
		return deny(ReasonSelfApproval, "you can't resolve your own request")
	}
	if r.GetKind() != workflowv1.RequestKind_REQUEST_KIND_UNSPECIFIED {
		if !isSiteAdmin(actor) {
			return deny(ReasonNotApprover, "a move request is resolved by a site admin")
		}
		return nil
	}
	if uid == "" {
		return deny(ReasonNotApprover, "you can't approve this request")
	}
	acc, err := s.vault.GetMySecretAccess(ctx, &vaultv1.GetMySecretAccessRequest{Actor: vaultActor(actor), SecretId: r.GetSecretId()})
	if err != nil {
		return fmt.Errorf("check approver: %w", err)
	}
	if !acc.GetAccess().GetApprove() {
		return deny(ReasonNotApprover, "you can't approve requests for this secret")
	}
	return nil
}

// checkPending refuses to resolve a request that's already approved or
// denied. Unknown requests pass through to the store's not-found handling.
func (s *Server) checkPending(ctx context.Context, uid, requestID string) error {
	r, err := s.store.GetRequest(ctx, requestID)
	if err != nil || r == nil || r.GetStatus() == workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		return err
	}
	return s.refuseNotPending(ctx, uid, requestID)
}

// refuseNotPending logs, audits and builds the REQUEST_NOT_PENDING refusal.
func (s *Server) refuseNotPending(ctx context.Context, uid, requestID string) error {
	s.lg(ctx).Warn("approval refused", log.F("request_id", requestID), log.F("user_id", uid), log.F("reason", ReasonRequestNotPending))
	s.emit(ctx, uid, "approval.denied", requestID, map[string]string{"reason": ReasonRequestNotPending})
	return refuse(codes.FailedPrecondition, ReasonRequestNotPending, "this request has already been resolved", nil)
}
