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
	"google.golang.org/grpc/status"
)

// vaultActor is the signed-in user as the vault's RACI decision needs them.
func vaultActor(a *workflowv1.ActorContext) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		UserId:            a.GetUserId(),
		IsSiteAdmin:       a.GetIsSiteAdmin(),
		IsRoot:            a.GetIsRoot(),
		GroupNames:        a.GetGroupNames(),
		GroupIds:          a.GetGroupIds(),
		MfaVerifiedAtUnix: a.GetMfaVerifiedAtUnix(),
		PrincipalKind:     vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN,
	}
}

// checkCheckout refuses a check-out the caller may not make: no read on the
// secret, a type with check-out off, or a lease already held. Each refusal is
// audited as checkout.denied with its reason.
func (s *Server) checkCheckout(ctx context.Context, actor *workflowv1.ActorContext, secretID string) error {
	userID := actor.GetUserId()
	if userID == "" || secretID == "" {
		return status.Error(codes.InvalidArgument, "an actor and a secret are required")
	}
	l := s.lg(ctx).With(log.F("secret_id", secretID), log.F("user_id", userID))
	deny := func(err error, reason string) error {
		l.Warn("check-out refused", log.F("reason", reason))
		s.emit(ctx, userID, "checkout.denied", secretID, map[string]string{"reason": reason})
		return err
	}

	acc, err := s.vault.GetMySecretAccess(ctx, &vaultv1.GetMySecretAccessRequest{Actor: vaultActor(actor), SecretId: secretID})
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}
	if !acc.GetAccess().GetRead() {
		return deny(refuse(codes.PermissionDenied, ReasonCheckoutNoAccess, "you have no access to this secret", nil), ReasonCheckoutNoAccess)
	}
	t, err := s.secretType(ctx, secretID)
	if err != nil {
		return err
	}
	if !t.GetCheckout() {
		return deny(refuse(codes.FailedPrecondition, ReasonCheckoutTypeDisabled, "this secret's type doesn't allow check-out", nil), ReasonCheckoutTypeDisabled)
	}
	need, err := s.sensitiveCheckoutNeedsMFA(ctx, t)
	if err != nil {
		return err
	}
	if need && !s.mfaFresh(actor) {
		return deny(refuse(codes.PermissionDenied, ReasonStepUpRequired, "confirm your MFA again to check out this secret", nil), ReasonStepUpRequired)
	}
	if err := s.checkNoLease(ctx, userID, secretID); err != nil {
		return deny(err, ReasonCheckoutLeaseHeld)
	}
	l.Debug("check-out allowed")
	return nil
}

// secretType reads the secret's type from the vault; an unknown type reads
// as one with nothing allowed.
func (s *Server) secretType(ctx context.Context, secretID string) (*vaultv1.SecretType, error) {
	sec, err := s.vault.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: systemAdminActor(), Id: secretID})
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	types, err := s.vault.ListSecretTypes(ctx, &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		return nil, fmt.Errorf("read secret types: %w", err)
	}
	for _, t := range types.GetTypes() {
		if t.GetId() == sec.GetSecret().GetTypeId() {
			return t, nil
		}
	}
	return &vaultv1.SecretType{}, nil
}

// sensitiveCheckoutNeedsMFA reports whether checking out a secret of type t
// needs a fresh MFA: "require MFA for sensitive checkout" is on and the type
// has a super-sensitive field.
func (s *Server) sensitiveCheckoutNeedsMFA(ctx context.Context, t *vaultv1.SecretType) (bool, error) {
	super := false
	for _, f := range t.GetFields() {
		super = super || f.GetSuperSensitive()
	}
	if !super {
		return false, nil
	}
	st, err := s.vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		return false, fmt.Errorf("read security settings: %w", err)
	}
	return st.GetSettings().GetRequireMfaForSensitiveCheckout(), nil
}

// checkNoLease refuses when the secret has an active lease, naming its holder.
func (s *Server) checkNoLease(ctx context.Context, userID, secretID string) error {
	held, err := s.store.ActiveLeaseForSecret(ctx, secretID)
	if err != nil {
		return err
	}
	if held == nil {
		return nil
	}
	msg := "this secret is checked out by someone else"
	if held.GetUserId() == userID {
		msg = "you already have this secret checked out"
	}
	return refuse(codes.FailedPrecondition, ReasonCheckoutLeaseHeld, msg, map[string]string{"holder_user_id": held.GetUserId()})
}

// checkGrantFree refuses to approve an access request while someone other
// than the requester holds a lease on the secret: the approval issues the
// requester a lease, and a secret has one at a time.
func (s *Server) checkGrantFree(ctx context.Context, requestID string) error {
	r, err := s.store.GetRequest(ctx, requestID)
	if err != nil || r == nil || r.GetKind() != workflowv1.RequestKind_REQUEST_KIND_UNSPECIFIED {
		return err
	}
	held, err := s.store.ActiveLeaseForSecret(ctx, r.GetSecretId())
	if err != nil || held == nil || held.GetUserId() == r.GetRequestedByUserId() {
		return err
	}
	return refuse(codes.FailedPrecondition, ReasonCheckoutLeaseHeld, "the secret is checked out; approve once it's checked in",
		map[string]string{"holder_user_id": held.GetUserId()})
}
