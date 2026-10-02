// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// A test binds with the stored credential, so it must not be a way to
	// hammer the target (or try credentials) faster than an operator would.
	heartbeatRequestGap = time.Minute
	maxHeartbeatDetail  = 512
)

// readableHeartbeatSecret returns a secret a non-human principal may read, for
// the on-demand heartbeat calls.
func (s *Server) readableHeartbeatSecret(actor *vaultv1.ActorContext, id string) (*vaultv1.Secret, error) {
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "this heartbeat path is for non-human principals")
	}
	if s.hb == nil {
		return nil, status.Error(codes.Unavailable, "heartbeat is not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(id)
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() || !s.canRead(actor, sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to check this secret")
	}
	return sec, nil
}

func (s *Server) RequestHeartbeatForPrincipal(ctx context.Context, req *vaultv1.RequestHeartbeatForPrincipalRequest) (*vaultv1.RequestHeartbeatForPrincipalResponse, error) {
	actor := req.GetActor()
	sec, err := s.readableHeartbeatSecret(actor, req.GetSecretId())
	if err != nil {
		return nil, err
	}
	l := s.lg(ctx)
	// Without a verifier every connector claim is refused, so a due row would
	// never be served and the caller would wait on it forever.
	if s.wid == nil {
		l.Info("heartbeat request refused: no worker-identity verifier, so no connector can serve it", log.F("secret_id", sec.GetId()))
		return nil, status.Error(codes.FailedPrecondition, "no connector is available in this environment, so a heartbeat check cannot run")
	}
	s.mu.RLock()
	reachable, targetID := s.rotationReachable(sec), sec.GetTargetId()
	s.mu.RUnlock()
	if !reachable {
		l.Info("heartbeat request refused: secret has no target with a connection", log.F("secret_id", sec.GetId()), log.F("target_id", targetID))
		return nil, status.Error(codes.FailedPrecondition, "secret has no target with a connection: attach a target before requesting a heartbeat")
	}
	paused, err := s.hb.Paused(ctx, sec.GetId())
	if err != nil {
		l.Error(err, "heartbeat request: store read failed", log.F("secret_id", sec.GetId()))
		return nil, status.Errorf(codes.Internal, "request heartbeat: %v", err)
	}
	requested, exists, err := s.hb.RequestNow(ctx, sec.GetId(), heartbeatRequestGap)
	if err != nil {
		l.Error(err, "heartbeat request: store update failed", log.F("secret_id", sec.GetId()))
		return nil, status.Errorf(codes.Internal, "request heartbeat: %v", err)
	}
	if !exists {
		l.Info("heartbeat request refused: secret has no heartbeat schedule", log.F("secret_id", sec.GetId()))
		return nil, status.Error(codes.FailedPrecondition, "this secret has no heartbeat: it needs a heartbeat-capable type, heartbeat left on, and a target with a connection")
	}
	if !requested {
		l.Info("heartbeat request rate-limited", log.F("secret_id", sec.GetId()))
		return nil, status.Error(codes.ResourceExhausted, "the last check request was under a minute ago; read the status instead")
	}
	l.Info("heartbeat requested on demand", log.F("secret_id", sec.GetId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
	now := s.clock()
	s.emitAttrs(ctx, principalActorID(actor), "heartbeat.request.principal", sec.GetId(), false, principalAttrs(actor, nil))
	if paused {
		s.mu.Lock()
		if cur := s.findSecret(sec.GetId()); cur != nil {
			s.markHeartbeatResumed(ctx, cur, principalActorID(actor), principalAttrs(actor, map[string]string{"reason": "check_requested"}))
		}
		s.mu.Unlock()
	}
	return &vaultv1.RequestHeartbeatForPrincipalResponse{RequestedAtUnix: now.Unix()}, nil
}

func (s *Server) GetHeartbeatStatusForPrincipal(ctx context.Context, req *vaultv1.GetHeartbeatStatusForPrincipalRequest) (*vaultv1.GetHeartbeatStatusForPrincipalResponse, error) {
	sec, err := s.readableHeartbeatSecret(req.GetActor(), req.GetSecretId())
	if err != nil {
		return nil, err
	}
	l := s.lg(ctx)
	var pending bool
	if s.wid == nil {
		// A due row cannot be claimed without a verifier, so reporting it as
		// pending would keep the caller polling for a result that never comes.
		l.Debug("heartbeat status: no worker-identity verifier, reporting not pending", log.F("secret_id", sec.GetId()))
	} else {
		pending, err = s.hb.Pending(ctx, sec.GetId())
		if err != nil {
			l.Error(err, "heartbeat status: store read failed", log.F("secret_id", sec.GetId()))
			return nil, status.Errorf(codes.Internal, "heartbeat status: %v", err)
		}
	}
	s.mu.RLock()
	result, verified, detail := sec.GetLastHeartbeatResult(), sec.GetVerifiedAt(), sec.GetLastHeartbeatDetail()
	s.mu.RUnlock()
	var checked int64
	if t, err := time.Parse(time.RFC3339, verified); err == nil {
		checked = t.Unix()
	}
	return &vaultv1.GetHeartbeatStatusForPrincipalResponse{Result: result, CheckedAtUnix: checked, Detail: detail, Pending: pending}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
