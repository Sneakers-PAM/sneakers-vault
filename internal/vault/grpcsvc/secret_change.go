// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// markValueChanged records that sec's stored values just changed. ledgerNo is
// the version_no the history write returned (0 without a ledger, or when the
// best-effort write failed). Taking the larger keeps value_version equal to
// the active ListSecretVersions entry normally, and still increasing when the
// ledger lagged. Caller holds s.mu for writing.
func (s *Server) markValueChanged(ctx context.Context, sec *vaultv1.Secret, ledgerNo int) {
	next := sec.GetValueVersion() + 1
	if lv := safeconv.Int32(ledgerNo); lv > next {
		next = lv
	}
	sec.ValueVersion = next
	sec.ValueChangedAt = time.Now().UTC().Format(time.RFC3339)
	l := s.lg(ctx)
	l.Debug("secret value version bumped", log.F("secret_id", sec.GetId()), log.F("value_version", next))
}

// principalSecretView is a copy of sec with the automation state a principal
// needs to tell whether a value it holds can go stale. The flags depend on the
// type, target and connection catalog, so they're worked out per response and
// never stored. Caller holds at least s.mu.RLock.
func (s *Server) principalSecretView(sec *vaultv1.Secret) *vaultv1.Secret {
	if sec == nil {
		return nil
	}
	out, _ := proto.Clone(sec).(*vaultv1.Secret)
	out.RotationEnabled = s.rotationEligible(sec)
	out.RotatesOnCheckin = out.GetRotationEnabled() && s.findType(sec.GetTypeId()).GetCheckout()
	out.HeartbeatEnabled = s.secretHeartbeatEnabled(sec)
	return out
}

// parseChangedSince reads the optional changed_since filter.
func parseChangedSince(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, status.Error(codes.InvalidArgument, "changed_since must be an RFC3339 time")
	}
	return t, nil
}

// changedSince reports whether sec's value changed at or after since. With a
// filter set, a secret with no recorded change never matches.
func changedSince(sec *vaultv1.Secret, since time.Time) bool {
	if since.IsZero() {
		return true
	}
	at, err := time.Parse(time.RFC3339, sec.GetValueChangedAt())
	return err == nil && !at.Before(since)
}

// GetSecretForPrincipal returns one secret's metadata to a non-human principal
// with RACI read on it, never a field value. Audited as secret.get.principal.
func (s *Server) GetSecretForPrincipal(ctx context.Context, req *vaultv1.GetSecretForPrincipalRequest) (*vaultv1.GetSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "get"); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canRead(actor, sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to read this secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.get.principal", sec.GetId(), false, principalAttrs(actor, map[string]string{
		"value_version": strconv.Itoa(int(sec.GetValueVersion())),
	}))
	return &vaultv1.GetSecretForPrincipalResponse{Secret: s.principalSecretView(sec)}, nil
}
