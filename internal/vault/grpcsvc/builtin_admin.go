// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The domain's built-in Administrator (objectSid RID 500) is never rotated.
// The connector reports it, with adminCount, on heartbeat and on a refused
// rotation; vault records both on the secret and keeps a flagged secret out
// of every rotation path while heartbeat keeps running.
package grpcsvc

import (
	"context"
	"strconv"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// builtinAdministratorReason is why a secret whose target account is the
// domain's built-in Administrator (objectSid RID 500, reported by the
// connector) is never rotated. Heartbeat still runs.
const builtinAdministratorReason = "built-in Administrator account (RID 500), rotation is not allowed"

var errBuiltinAdministrator = status.Error(codes.FailedPrecondition, builtinAdministratorReason)

// skipsBuiltinAdministrator lists the system-triggered rotation reasons that
// skip the built-in Administrator instead of failing: they run inside a
// workflow saga after access was granted, and failing them would fail the
// saga's run rather than let the lease close normally.
var skipsBuiltinAdministrator = map[string]bool{"checkin": true, "break-glass": true}

// refuseBuiltinAdministratorEnqueue handles an EnqueueRotation for the
// built-in Administrator: nothing is scheduled either way.
func (s *Server) refuseBuiltinAdministratorEnqueue(ctx context.Context, req *vaultv1.EnqueueRotationRequest) (*vaultv1.EnqueueRotationResponse, error) {
	l := s.lg(ctx)
	attrs := map[string]string{"reason": builtinAdministratorReason, "trigger": req.GetReason()}
	if skipsBuiltinAdministrator[req.GetReason()] {
		l.Info("rotation skipped: built-in Administrator account", log.F("secret_id", req.GetSecretId()), log.F("trigger", req.GetReason()))
		s.emitAttrs(ctx, req.GetActor().GetUserId(), "rotate.skip", req.GetSecretId(), false, attrs)
		return &vaultv1.EnqueueRotationResponse{Ok: true}, nil
	}
	l.Warn("rotation refused: built-in Administrator account", log.F("secret_id", req.GetSecretId()), log.F("trigger", req.GetReason()))
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "rotate.refused", req.GetSecretId(), false, attrs)
	return nil, errBuiltinAdministrator
}

// applyAccountFlags records the AD account flags a heartbeat carried. An
// unset flag means the connector could not read it and leaves the recorded
// value alone. Becoming the built-in Administrator removes the rotation
// schedule; ceasing to be one schedules it again where it's eligible.
// Heartbeat scheduling is never touched. It returns the audit attributes
// when a flag changed, else nil. Caller holds s.mu (write).
func (s *Server) applyAccountFlags(ctx context.Context, sec *vaultv1.Secret, req *vaultv1.ReportHeartbeatRequest) map[string]string {
	changed := false
	if req.BuiltinAdministrator != nil && req.GetBuiltinAdministrator() != sec.GetBuiltinAdministrator() {
		changed = true
		sec.BuiltinAdministrator = req.GetBuiltinAdministrator()
		l := s.lg(ctx)
		if sec.BuiltinAdministrator {
			l.Warn("secret is the built-in Administrator account: rotation stopped, heartbeat continues", log.F("secret_id", sec.GetId()))
			if s.rot != nil {
				if err := s.rot.Remove(ctx, sec.GetId()); err != nil {
					l.Error(err, "remove rotation schedule for built-in Administrator failed", log.F("secret_id", sec.GetId()))
				}
			}
			sec.NextRotationAt = ""
		} else {
			l.Info("secret is no longer the built-in Administrator account", log.F("secret_id", sec.GetId()))
			s.ensureRotationScheduled(ctx, sec)
		}
	}
	if req.AdminCount != nil && req.GetAdminCount() != sec.GetAdminCount() {
		changed = true
		sec.AdminCount = req.GetAdminCount()
	}
	if !changed {
		return nil
	}
	return map[string]string{
		"builtin_administrator": strconv.FormatBool(sec.GetBuiltinAdministrator()),
		"admin_count":           strconv.FormatBool(sec.GetAdminCount()),
	}
}

// refuseBuiltinAdministratorReport records the connector's refusal to rotate
// the built-in Administrator: the revealed staging is discarded (the target
// was never changed, so the old credential stays active), the secret is
// flagged, and its rotation schedule is removed so it is never retried. A
// refusal is not a failure, so nothing is notified. alreadyFlagged accepts a
// report whose row a heartbeat already removed after the claim.
func (s *Server) refuseBuiltinAdministratorReport(ctx context.Context, req *vaultv1.ReportRotationRequest, alreadyFlagged bool) (*vaultv1.ReportRotationResponse, error) {
	secID := req.GetSecretId()
	if !alreadyFlagged && !s.rotationScheduled(ctx, secID) {
		return nil, status.Error(codes.PermissionDenied, "secret not scheduled for rotation")
	}
	if s.rot == nil || s.vers == nil {
		return nil, status.Error(codes.Unavailable, "rotation stores not configured")
	}
	if v := int(req.GetVersion()); v != 0 {
		if _, err := s.vers.DiscardVersion(ctx, secID, v); err != nil {
			return nil, status.Errorf(codes.Internal, "discard version: %v", err)
		}
	} else if err := s.vers.DiscardStaged(ctx, secID); err != nil {
		return nil, status.Errorf(codes.Internal, "discard staged: %v", err)
	}
	l := s.lg(ctx)
	if err := s.rot.Remove(ctx, secID); err != nil {
		return nil, status.Errorf(codes.Internal, "remove rotation schedule: %v", err)
	}
	s.mu.Lock()
	sec := findByID(s.secrets, secID)
	if sec == nil {
		s.mu.Unlock()
		return nil, errNotFound("secret")
	}
	sec.BuiltinAdministrator = true
	sec.NextRotationAt = ""
	s.mu.Unlock()
	l.Warn("rotation refused by connector: built-in Administrator account; staging discarded, schedule removed", log.F("secret_id", secID), log.F("version", req.GetVersion()))
	s.emitAttrs(ctx, "connector", "rotate.refused", secID, false, map[string]string{"reason": builtinAdministratorReason})
	return &vaultv1.ReportRotationResponse{Ok: true}, nil
}
