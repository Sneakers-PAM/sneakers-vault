// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// One secret attached to many targets (#168): target_ids carries the full
// list; target_id (legacy, singular) stays the first/primary entry, kept in
// sync so a consumer that hasn't moved to the list still reads a sensible
// single value. UpdateSecret/SetSecretTargetForPrincipal keep meaning
// "replace the whole list with just this one"; AttachSecretTarget/
// DetachSecretTarget (and their ForPrincipal mirrors) are the only paths
// that add or remove one target without touching the others. Kept out of
// secrets.go/secrets_principal_mutate.go (already large).
package grpcsvc

import (
	"context"
	"slices"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// secretTargetIDs returns sec's full attached-target list: the stored list
// when set, or — for a secret saved before this field existed — a
// synthesized one-item list built from the legacy target_id. Read paths
// (heartbeat, rotation, host-key reachability) use this instead of
// sec.GetTargetIds() directly, so an old secret is never seen as having no
// target. Mirrors targetConnections' role for Target.connections.
func secretTargetIDs(sec *vaultv1.Secret) []string {
	if ids := sec.GetTargetIds(); len(ids) > 0 {
		return ids
	}
	if sec.GetTargetId() == "" {
		return nil
	}
	return []string{sec.GetTargetId()}
}

// primaryTargetID returns the secret's first/primary target id (the one
// target_id, the legacy alias, mirrors), or "" when it has none.
func primaryTargetID(sec *vaultv1.Secret) string {
	ids := secretTargetIDs(sec)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// hasTarget reports whether sec is already attached to targetID.
func hasTarget(sec *vaultv1.Secret, targetID string) bool {
	return slices.Contains(secretTargetIDs(sec), targetID)
}

// setSecretTargets stores ids on sec and keeps the legacy target_id alias in
// sync (the first entry, "" when the list is empty). Caller holds s.mu.
func setSecretTargets(sec *vaultv1.Secret, ids []string) {
	sec.TargetIds = ids
	if len(ids) > 0 {
		sec.TargetId = ids[0]
	} else {
		sec.TargetId = ""
	}
}

// attachTarget appends targetID to sec's list if it isn't already there
// (idempotent — attaching a target already attached is a no-op, not an
// error) and schedules rotation/heartbeat for it exactly as the single-
// target set path does. Caller holds s.mu (write lock).
func (s *Server) attachTarget(ctx context.Context, sec *vaultv1.Secret, targetID string) {
	if hasTarget(sec, targetID) {
		return
	}
	setSecretTargets(sec, append(secretTargetIDs(sec), targetID))
	s.ensureRotationScheduled(ctx, sec)
	s.ensureHeartbeatScheduled(ctx, sec)
}

// detachTarget removes targetID from sec's list if present (idempotent —
// detaching a target that isn't attached, or the secret's only target, is a
// no-op, not an error). Caller holds s.mu (write lock).
func (s *Server) detachTarget(sec *vaultv1.Secret, targetID string) {
	ids := secretTargetIDs(sec)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != targetID {
			out = append(out, id)
		}
	}
	setSecretTargets(sec, out)
}

// AttachSecretTarget attaches one target to a secret as a human, without
// touching its other targets. Gated like UpdateSecret (canManageOrOwnSecret).
func (s *Server) AttachSecretTarget(ctx context.Context, req *vaultv1.AttachSecretTargetRequest) (*vaultv1.AttachSecretTargetResponse, error) {
	if req.GetTargetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "target_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this secret")
	}
	if findByID(s.targets, req.GetTargetId()) == nil {
		return nil, errNotFound("target")
	}
	s.attachTarget(ctx, sec, req.GetTargetId())
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "secret.target.attach", sec.GetId(), false, map[string]string{"target_id": req.GetTargetId()})
	return &vaultv1.AttachSecretTargetResponse{Secret: sec}, nil
}

// DetachSecretTarget detaches one target from a secret as a human, without
// touching its other targets.
func (s *Server) DetachSecretTarget(ctx context.Context, req *vaultv1.DetachSecretTargetRequest) (*vaultv1.DetachSecretTargetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this secret")
	}
	s.detachTarget(sec, req.GetTargetId())
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "secret.target.detach", sec.GetId(), false, map[string]string{"target_id": req.GetTargetId()})
	return &vaultv1.DetachSecretTargetResponse{Secret: sec}, nil
}

// AttachSecretTargetForPrincipal attaches one target to a secret for a
// non-human principal with RACI-Author on the secret, without touching its
// other targets. The target must be one the principal can see: shared, or
// owned by the token's user (same gate as SetSecretTargetForPrincipal).
func (s *Server) AttachSecretTargetForPrincipal(ctx context.Context, req *vaultv1.AttachSecretTargetForPrincipalRequest) (*vaultv1.AttachSecretTargetForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal target change is for non-human principals")
	}
	if req.GetTargetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "target_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetSecretId(), "attach a target to")
	if err != nil {
		return nil, err
	}
	if err := s.principalUsableTarget(ctx, actor, req.GetTargetId()); err != nil {
		return nil, err
	}
	s.attachTarget(ctx, sec, req.GetTargetId())
	s.lg(ctx).Info("secret target attached by principal", log.F("secret_id", sec.GetId()), log.F("target_id", req.GetTargetId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
	s.emitAttrs(ctx, principalActorID(actor), "secret.target.attach.principal", sec.GetId(), false, principalAttrs(actor, map[string]string{"target_id": req.GetTargetId()}))
	return &vaultv1.AttachSecretTargetForPrincipalResponse{Secret: s.principalSecretView(sec)}, nil
}

// DetachSecretTargetForPrincipal detaches one target from a secret for a
// non-human principal with RACI-Author on the secret, without touching its
// other targets.
func (s *Server) DetachSecretTargetForPrincipal(ctx context.Context, req *vaultv1.DetachSecretTargetForPrincipalRequest) (*vaultv1.DetachSecretTargetForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal target change is for non-human principals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetSecretId(), "detach a target from")
	if err != nil {
		return nil, err
	}
	s.detachTarget(sec, req.GetTargetId())
	s.lg(ctx).Info("secret target detached by principal", log.F("secret_id", sec.GetId()), log.F("target_id", req.GetTargetId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
	s.emitAttrs(ctx, principalActorID(actor), "secret.target.detach.principal", sec.GetId(), false, principalAttrs(actor, map[string]string{"target_id": req.GetTargetId()}))
	return &vaultv1.DetachSecretTargetForPrincipalResponse{Secret: s.principalSecretView(sec)}, nil
}
