// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// RotateSecretForPrincipal and RestoreSecretVersionForPrincipal: a non-human
// principal with RACI-Author (R) on a secret's folder chain can rotate a
// secret it may author and roll back to an earlier version, under its own
// folder access — never RACI-C, and never the human-only recovery role
// RestoreSecretVersion needs. The order a local-admin-password broker uses is
// store first, then set on the host: RotateSecretForPrincipal always returns
// the new value (unlike GenerateSecretForPrincipal's opt-in
// generated_value), and if setting it on the host fails,
// RestoreSecretVersionForPrincipal rolls the stored value back to the
// previous version so the vault matches the host again. Kept out of the
// already-large secrets_principal.go.
package grpcsvc

import (
	"context"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RotateSecretForPrincipal regenerates the type's password-kind field under
// the secret's policy and stores it as a new version, as a non-human
// principal. Requires RACI-Author (R) — the same grant
// CreateSecretForPrincipal/GenerateSecretForPrincipal require. Refused
// (audited either way) while a rotation of the secret is already queued or
// running, mirroring RestoreSecretVersion's ROTATION_IN_PROGRESS guard.
func (s *Server) RotateSecretForPrincipal(ctx context.Context, req *vaultv1.RotateSecretForPrincipalRequest) (*vaultv1.RotateSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal rotate is for non-human principals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.canManage(actor, sec.GetFolderId()) {
		s.emitAttrs(ctx, principalActorID(actor), "secret.rotate.principal.denied", sec.GetId(), false, principalAttrs(actor, nil))
		return nil, status.Error(codes.PermissionDenied, "not permitted to rotate this secret")
	}
	busy, err := s.rotationInProgress(ctx, sec.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check rotation: %v", err)
	}
	if busy {
		s.lg(ctx).Info("principal rotate refused: rotation in progress", log.F("secret_id", sec.GetId()))
		return nil, refuseCode(codes.FailedPrecondition, ReasonRotationInProgress, "a rotation of this secret is queued or running; try again once it finishes")
	}
	if s.vers == nil {
		return nil, status.Error(codes.Unavailable, "version store not configured")
	}
	st := s.findType(sec.GetTypeId())
	pwField := passwordFieldKey(st)
	if pwField == "" {
		return nil, status.Error(codes.InvalidArgument, "type has no generatable password field")
	}
	rec, ok := s.records[sec.GetId()]
	if !ok {
		return nil, errNotFound("secret value")
	}
	fields, err := s.crypt.OpenAll(rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open existing: %v", err)
	}
	policy := s.passwordPolicyForField(st, pwField, req.GetPolicyId())
	pw, err := GeneratePassword(policy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate password: %v", err)
	}
	fields[pwField] = pw
	newRec, err := s.crypt.Seal(fields)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal fields: %v", err)
	}
	newNo, err := s.vers.AppendActive(ctx, sec.GetId(), newRec, principalActorID(actor))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store version: %v", err)
	}
	s.records[sec.GetId()] = newRec
	s.markValueChanged(ctx, sec, newNo)
	sec.RotatedAt = time.Now().UTC().Format(time.RFC3339)
	if sec.GetTargetId() != "" {
		// Only the vault's copy just changed; the caller (a broker) pushes it to
		// the target next. Mirrors RestoreSecretVersion: mark unchecked rather
		// than claim a result the vault hasn't observed.
		sec.LastHeartbeatResult = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN
		sec.LastHeartbeatDetail = "rotated by a principal; not yet checked against the target"
		if s.hb != nil {
			if _, _, err := s.hb.RequestNow(ctx, sec.GetId(), 0); err != nil {
				s.lg(ctx).Error(err, "queue heartbeat after principal rotate failed", log.F("secret_id", sec.GetId()))
			}
		}
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.rotate.principal", sec.GetId(), true, principalAttrs(actor, map[string]string{
		"new_version_no": strconv.Itoa(newNo),
	}))
	return &vaultv1.RotateSecretForPrincipalResponse{Secret: s.principalSecretView(sec), NewValue: pw}, nil
}

// RestoreSecretVersionForPrincipal makes a prior version current again, as a
// non-human principal. Requires RACI-Author (R) — never the human-only
// recovery role RestoreSecretVersion needs. Shares restoreVersion
// (recovery.go) with the human path: same re-seal-and-append-as-new-version
// core, so a restore is always a new version, never a history rewrite.
func (s *Server) RestoreSecretVersionForPrincipal(ctx context.Context, req *vaultv1.RestoreSecretVersionForPrincipalRequest) (*vaultv1.RestoreSecretVersionForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal restore is for non-human principals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.canManage(actor, sec.GetFolderId()) {
		s.emitAttrs(ctx, principalActorID(actor), "secret.version.restore.principal.denied", sec.GetId(), false, principalAttrs(actor, map[string]string{
			"version_no": strconv.Itoa(int(req.GetVersionNo())),
		}))
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
		s.lg(ctx).Info("principal restore refused: rotation in progress", log.F("secret_id", sec.GetId()))
		return nil, refuseCode(codes.FailedPrecondition, ReasonRotationInProgress, "a rotation of this secret is queued or running; try again once it finishes")
	}
	newNo, err := s.restoreVersion(ctx, sec, int(req.GetVersionNo()), principalActorID(actor))
	if err != nil {
		return nil, err
	}
	if sec.GetTargetId() != "" {
		sec.LastHeartbeatResult = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN
		sec.LastHeartbeatDetail = "restored by a principal; not yet checked against the target"
		if s.hb != nil {
			if _, _, err := s.hb.RequestNow(ctx, sec.GetId(), 0); err != nil {
				s.lg(ctx).Error(err, "queue heartbeat after principal restore failed", log.F("secret_id", sec.GetId()))
			}
		}
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.version.restore.principal", sec.GetId(), true, principalAttrs(actor, map[string]string{
		"version_no": strconv.Itoa(int(req.GetVersionNo())), "new_version_no": strconv.Itoa(newNo),
	}))
	return &vaultv1.RestoreSecretVersionForPrincipalResponse{Secret: s.principalSecretView(sec)}, nil
}
