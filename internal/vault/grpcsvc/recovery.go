// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Recovery refusal reasons.
const (
	ReasonRecoveryRoleRequired = "RECOVERY_ROLE_REQUIRED"
	ReasonStepUpRequired       = "STEP_UP_REQUIRED"
	ReasonRotationInProgress   = "ROTATION_IN_PROGRESS"
)

// stepUpClockSkew tolerates an MFA time slightly ahead of the vault's clock.
const stepUpClockSkew = 30 * time.Second

// SetMFAMaxAge sets how recent MFA must be (MFA_MAX_AGE); <= 0 keeps the
// default.
func (s *Server) SetMFAMaxAge(d time.Duration) { s.mfaMaxAge = d }

func (s *Server) mfaWindow() time.Duration {
	if s.mfaMaxAge > 0 {
		return s.mfaMaxAge
	}
	return config.DefaultMFAMaxAge
}

// mfaFresh reports whether a's MFA falls within the MFA_MAX_AGE window.
func (s *Server) mfaFresh(a *vaultv1.ActorContext) bool {
	at := a.GetMfaVerifiedAtUnix()
	if at <= 0 {
		return false
	}
	age := s.clock().Sub(time.Unix(at, 0))
	return age >= -stepUpClockSkew && age <= s.mfaWindow()
}

// requireRecovery refuses unless a is a human with a real user id holding the
// recovery role, with a fresh MFA. Site admin and root don't imply it.
func (s *Server) requireRecovery(ctx context.Context, a *vaultv1.ActorContext, method, subject string) error {
	uid := a.GetUserId()
	human := a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN && uid != "" && uid != "system"
	reason, msg := "", ""
	switch {
	case !human || !a.GetIsRecovery():
		reason, msg = ReasonRecoveryRoleRequired, "this needs the recovery role"
	case !s.mfaFresh(a):
		reason, msg = ReasonStepUpRequired, "confirm your MFA again to continue"
	default:
		return nil
	}
	s.lg(ctx).Warn("recovery check refused", log.F("method", method), log.F("reason", reason), log.F("user_id", uid), log.F("subject", subject))
	actor := uid
	if actor == "" {
		actor = a.GetPrincipalId()
	}
	s.emitTier(ctx, audit.TierAudit, actor, "recovery.denied", subject, false, map[string]string{
		"method": method, "reason": reason, "principal_kind": a.GetPrincipalKind().String(),
	})
	return refuse(reason, msg)
}

// rotationInProgress reports whether a rotation of the secret is queued or
// running. A server with no rotation queue has none.
func (s *Server) rotationInProgress(ctx context.Context, secretID string) (bool, error) {
	if s.rot == nil {
		return false, nil
	}
	return s.rot.InProgress(ctx, secretID)
}

// RestoreSecretVersion makes a prior version's fields current, as a new
// version. It needs the recovery role, a fresh MFA and read on the secret,
// and is refused while a rotation is queued or running. Only the vault's copy
// changes: a managed target is marked unchecked so the next heartbeat tells
// whether the restored value still works there. Never pushed to the target.
func (s *Server) RestoreSecretVersion(ctx context.Context, req *vaultv1.RestoreSecretVersionRequest) (*vaultv1.RestoreSecretVersionResponse, error) {
	actor := req.GetActor()
	if err := s.requireRecovery(ctx, actor, "RestoreSecretVersion", req.GetSecretId()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	l := s.lg(ctx).With(log.F("secret_id", sec.GetId()), log.F("version_no", req.GetVersionNo()), log.F("user_id", actor.GetUserId()))
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.canRead(actor, sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to restore this secret")
	}
	if s.vers == nil {
		return nil, errNotFound("secret version")
	}
	busy, err := s.rotationInProgress(ctx, sec.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check rotation: %v", err)
	}
	if busy {
		l.Info("restore refused: rotation in progress")
		return nil, refuseCode(codes.FailedPrecondition, ReasonRotationInProgress, "a rotation of this secret is queued or running; try again once it finishes")
	}
	newNo, err := s.restoreVersion(ctx, sec, int(req.GetVersionNo()), actor.GetUserId())
	if err != nil {
		return nil, err
	}
	if sec.GetTargetId() != "" {
		sec.LastHeartbeatResult = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN
		sec.LastHeartbeatDetail = fmt.Sprintf("restored to version %d; not yet checked against the target", req.GetVersionNo())
		if s.hb != nil {
			if _, _, err := s.hb.RequestNow(ctx, sec.GetId(), 0); err != nil {
				l.Error(err, "queue heartbeat after restore failed")
			}
		}
	}
	l.Info("secret version restored", log.F("new_version_no", newNo))
	s.emitTier(ctx, audit.TierAudit, actor.GetUserId(), "secret.version.restore", sec.GetId(), true, map[string]string{
		"version_no": strconv.Itoa(int(req.GetVersionNo())), "new_version_no": strconv.Itoa(newNo),
	})
	s.notifyInformed(ctx, actor.GetUserId(), "secret.version.restore", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.RestoreSecretVersionResponse{Secret: sec}, nil
}

// restoreVersion re-seals version versionNo's fields under the active key
// and appends them as the new current version. Caller holds s.mu.
func (s *Server) restoreVersion(ctx context.Context, sec *vaultv1.Secret, versionNo int, by string) (int, error) {
	metas, err := s.vers.List(ctx, sec.GetId(), s.crypt)
	if err != nil {
		return 0, status.Errorf(codes.Internal, "list versions: %v", err)
	}
	for _, m := range metas {
		if m.VersionNo == versionNo && m.Active {
			return 0, status.Error(codes.FailedPrecondition, "that version is already the current one")
		}
	}
	old, ok, err := s.vers.LoadVersion(ctx, sec.GetId(), versionNo)
	if err != nil {
		return 0, status.Errorf(codes.Internal, "load version: %v", err)
	}
	if !ok {
		return 0, errNotFound("secret version")
	}
	fields, err := s.crypt.OpenAll(old)
	if err != nil {
		return 0, status.Errorf(codes.Internal, "open version: %v", err)
	}
	var rec crypto.Record
	if rec, err = s.crypt.Seal(fields); err != nil {
		return 0, status.Errorf(codes.Internal, "seal fields: %v", err)
	}
	newNo, err := s.vers.AppendActive(ctx, sec.GetId(), rec, by)
	if err != nil {
		return 0, status.Errorf(codes.Internal, "store version: %v", err)
	}
	s.records[sec.GetId()] = rec
	return newNo, nil
}
