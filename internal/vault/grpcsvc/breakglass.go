// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Break-glass emergency access. A read-eligible user (or a site-admin/root, who
// auto-read-all including others' personal folders) reveals a secret's value in
// an emergency, bypassing the checkout-lock / approval-pending gate. The reveal
// is recorded as a HIGH-severity (tamper-evident tier) audit event, the secret's
// owner is notified, and a forced post-use rotation is enqueued so the exposed
// credential is rotated out. The gateway performs the MFA step-up before calling
// this RPC; vault owns the crypto, audit, notify and
// rotation queue, so the reveal + event + audit + notify + rotation happen in
// one place. Field values NEVER travel into the audit or the ledger.
package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BreakGlassSecret reveals all of a secret's fields in an emergency. Authz is
// the whole policy: read-eligibility over the secret's folder RACI (which
// site-admins/root auto-satisfy). The override is over the checkout/approval
// timing state, NOT over folder RACI — a user with no read grant is denied.
//
// The HIGH-severity break_glass audit event is the compensating control that
// justifies this deliberate bypass of the checkout-lock / approval-pending
// gate, so it is emitted fail-closed, before anything else and before any
// fields are returned: no disclosure without a recorded, tamper-evident audit.
// Everything after the audit (forced rotation enqueue, the operational ledger
// row, and the owner notification) is best-effort — none of it may deny or
// unwind an emergency reveal that is already, authoritatively, on the record.
func (s *Server) BreakGlassSecret(ctx context.Context, req *vaultv1.BreakGlassSecretRequest) (*vaultv1.BreakGlassSecretResponse, error) {
	if req.GetActor().GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "break-glass is available to signed-in people only")
	}
	// A write lock: nextID mutates s.seq, and it keeps the reveal + snapshot
	// atomic against concurrent mutation (mirrors RevealSecretField's Lock).
	s.mu.Lock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		s.mu.Unlock()
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		s.mu.Unlock()
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.resolveSecret(req.GetActor(), sec).Read.Allowed {
		s.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "not permitted to break glass on this secret")
	}
	rec, ok := s.records[sec.GetId()]
	if !ok {
		s.mu.Unlock()
		return nil, errNotFound("secret value")
	}
	fields, err := s.crypt.OpenAll(rec)
	if err != nil {
		s.mu.Unlock()
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	// Snapshot everything needed after the lock is released (no shared state is
	// touched during the DB/notify work below).
	secID := sec.GetId()
	secName := sec.GetName()
	rotationCapable := s.rotationEligible(sec)
	intervalDays := policyRotationDays(s.policyForSecret(sec))
	ownerUserID := ""
	if f := s.findFolder(sec.GetFolderId()); f != nil {
		ownerUserID = f.GetOwnerUserId()
	}
	eventID := s.nextID("break-glass")
	s.mu.Unlock()

	actor := req.GetActor().GetUserId()
	reason := req.GetReason()

	// HIGH-severity audit FIRST, FAIL-CLOSED: the tamper-evident tier
	// (audit.TierAudit), sensitive, with the reason as a non-sensitive attribute
	// (NEVER a field value). This event is the compensating control for the
	// deliberate policy bypass below, so if it can't be recorded, the secret
	// must not be disclosed either — no fields are returned.
	if err := s.emitTierErr(ctx, audit.TierAudit, actor, "break_glass", secID, true, map[string]string{"reason": reason}); err != nil {
		return nil, status.Errorf(codes.Internal, "record break-glass audit: %v", err)
	}

	// The audit above is now the authoritative record of this reveal. Everything
	// below is best-effort operational bookkeeping: none of it may deny or
	// unwind emergency access that has already been recorded.
	l := log.Ctx(ctx)

	// Forced post-use rotation: enqueue only rotation-capable secrets (managed
	// remote accounts with a password field). A static/personal entry has nothing
	// to rotate against, so we record that no rotation was scheduled. An enqueue
	// failure is logged, not fatal — it must not deny the emergency reveal.
	postRotationScheduled := false
	if s.rot != nil && rotationCapable {
		if err := s.rot.Enqueue(ctx, secID, "break-glass", intervalDays); err != nil {
			l.Error().Err(err).Str("secret_id", secID).Msg("break-glass: enqueue post-use rotation failed")
		} else {
			postRotationScheduled = true
		}
	}

	// Append the operational ledger row (never field values). Best-effort: a
	// ledger-insert failure is logged, not fatal — the audit event already
	// recorded this reveal.
	notified := ownerUserID != ""
	if s.bg != nil {
		if err := s.bg.Insert(ctx, eventID, secID, actor, reason, postRotationScheduled, notified); err != nil {
			l.Error().Err(err).Str("secret_id", secID).Msg("break-glass: ledger insert failed")
		}
	}

	// Notify the secret's owner (personal-folder owner_user_id), after the
	// ledger insert so we don't notify for a reveal we failed to record there
	// (the audit above remains the authoritative record either way). Best-effort
	// and only when there is an owner: a shared folder has no owner_user_id, so
	// notify is skipped (a shared-folder approver fan-out is a possible refinement).
	if notified {
		s.notifyBreakGlass(ctx, actor, secID, secName, ownerUserID)
	}

	return &vaultv1.BreakGlassSecretResponse{Fields: fields}, nil
}

// notifyBreakGlass fires a best-effort notification to the secret's owner that
// their secret was emergency-revealed. Unlike notifyInformed (Informed-subject
// fan-out), break-glass targets the owner directly. No-op on a nil notifier.
func (s *Server) notifyBreakGlass(ctx context.Context, actor, secID, secName, ownerUserID string) {
	if s.notifier == nil || ownerUserID == "" {
		return
	}
	s.notifier.Notify(context.WithoutCancel(ctx), NotifyEvent{
		Action:        "secret.break_glass",
		ResourceKind:  "secret",
		ResourceID:    secID,
		ResourceLabel: secName,
		ActorUserID:   actor,
		Subjects:      []authz.RuleSubject{{Kind: authz.SubjUser, Name: ownerUserID}},
	})
}
