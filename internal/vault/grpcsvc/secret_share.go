// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/subtle"
	"regexp"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A one-time share is a person's reveal use that the creator hands to someone
// without an account, through a link. It follows the ordinary use rules, so the
// owner's approval, the step-up and the audit are the same as for any reveal;
// only its redeem differs: whoever holds the link's token redeems it once.

const (
	minShareLifetime     = time.Minute
	defaultShareLifetime = 24 * time.Hour
	maxShareLifetime     = 7 * 24 * time.Hour
)

var shareHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// shareLifetime is how long a share lives: a day when none is asked for.
func shareLifetime(seconds int64) time.Duration {
	if seconds == 0 {
		return defaultShareLifetime
	}
	return time.Duration(seconds) * time.Second
}

// checkShareRequest checks the share part of a prepare request. A share is a
// reveal, with a token hash and a lifetime in range.
func checkShareRequest(req *vaultv1.PrepareSecretUseRequest) error {
	if req.GetShareHash() == "" {
		if req.GetShareTtlSeconds() != 0 {
			return status.Error(codes.InvalidArgument, "share_ttl_seconds needs share_hash")
		}
		return nil
	}
	switch {
	case !req.GetReveal():
		return status.Error(codes.InvalidArgument, "a share is a reveal")
	case !shareHashPattern.MatchString(req.GetShareHash()):
		return status.Error(codes.InvalidArgument, "share_hash must be a lower-case hex SHA-256")
	}
	if req.GetShareTtlSeconds() != 0 {
		if l := shareLifetime(req.GetShareTtlSeconds()); l < minShareLifetime || l > maxShareLifetime {
			return status.Error(codes.InvalidArgument, "a share lives from 60 seconds to 7 days")
		}
	}
	return nil
}

// approvedUntil is when an approved use stops being redeemable: the approval
// lifetime after the approval, except for a share, which keeps the lifetime its
// creator chose.
func (s *Server) approvedUntil(use *vaultv1.SecretUse, now time.Time) int64 {
	if use.GetShareHash() != "" {
		return use.GetExpiresAtUnix()
	}
	return now.Add(s.approvalLifetime()).Unix()
}

// SetUseApprovalLifetime sets how long an approved use stays redeemable
// (SECRET_USE_APPROVAL_LIFETIME); a value of 0 or less keeps the default.
func (s *Server) SetUseApprovalLifetime(d time.Duration) { s.useApprovalLifetime = d }

func (s *Server) approvalLifetime() time.Duration {
	if s.useApprovalLifetime > 0 {
		return s.useApprovalLifetime
	}
	return config.DefaultUseApprovalLifetime
}

// shareRefusal says why a share can't be redeemed now.
func shareRefusal(use *vaultv1.SecretUse) error {
	switch use.GetState() {
	case vaultv1.SecretUseState_SECRET_USE_STATE_PENDING:
		return refuseCode(codes.FailedPrecondition, ReasonShareNotApproved, "the owner hasn't approved this share yet")
	case vaultv1.SecretUseState_SECRET_USE_STATE_DENIED:
		return refuseCode(codes.FailedPrecondition, ReasonShareDenied, "this share was denied")
	case vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED:
		return refuseCode(codes.FailedPrecondition, ReasonShareUsed, "this share was already opened")
	case vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED:
		return refuseCode(codes.FailedPrecondition, ReasonShareExpired, "this share has expired")
	}
	return nil
}

// RedeemSecretShare releases a share's value once to whoever presents the hash
// of its token. A use that isn't a share, or a hash that doesn't match, is
// NotFound, so the answer says nothing about which use ids exist.
func (s *Server) RedeemSecretShare(ctx context.Context, req *vaultv1.RedeemSecretShareRequest) (*vaultv1.RedeemSecretShareResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	if use.GetShareHash() == "" || subtle.ConstantTimeCompare([]byte(use.GetShareHash()), []byte(req.GetShareHash())) != 1 {
		s.lg(ctx).Warn("secret share redeem refused: unknown use or wrong token", log.F("use_id", req.GetUseId()))
		return nil, status.Error(codes.NotFound, "secret share not found")
	}
	creator := &vaultv1.ActorContext{UserId: use.GetUserId(), PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		refusal := shareRefusal(use)
		s.useRefused(ctx, creator, "secret.share.redeem", use.GetSecretId(), "failed", "share is "+use.GetState().String(), useAttrs(use, nil))
		return nil, refusal
	}
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	live := sec != nil && !sec.GetRetired()
	rec := s.records[use.GetSecretId()]
	s.mu.RUnlock()
	if !live {
		s.useRefused(ctx, creator, "secret.share.redeem", use.GetSecretId(), "failed", "secret gone", useAttrs(use, nil))
		return nil, refuseCode(codes.FailedPrecondition, ReasonShareExpired, "this share has expired")
	}
	value, err := s.crypt.Open(rec, use.GetFieldKey())
	if err != nil {
		s.useRefused(ctx, creator, "secret.share.redeem", use.GetSecretId(), "failed", "open secret field", useAttrs(use, nil))
		return nil, status.Errorf(codes.Internal, "open secret field: %v", err)
	}
	use.State = vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.lg(ctx).Info("secret share redeemed", log.F("use_id", use.GetId()), log.F("secret_id", use.GetSecretId()))
	// Reads as the creator revealing it, like any reveal, with the way it left.
	s.emitAttrs(ctx, use.GetUserId(), "secret.reveal", use.GetSecretId()+"#"+use.GetFieldKey(), true, map[string]string{
		"via": "share_link", "use_id": use.GetId(), "client_label": use.GetClientLabel(),
	})
	return &vaultv1.RedeemSecretShareResponse{Use: use, Value: value}, nil
}

// RevokeSecretShare ends a share that hasn't been opened. Only a person, and
// only the creator or a site admin.
func (s *Server) RevokeSecretShare(ctx context.Context, req *vaultv1.RevokeSecretShareRequest) (*vaultv1.RevokeSecretShareResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	if use.GetShareHash() == "" {
		return nil, status.Error(codes.NotFound, "secret share not found")
	}
	if !isHumanUser(actor) || (actor.GetUserId() != use.GetUserId() && !isHumanAdmin(actor)) {
		s.useRefused(ctx, actor, "secret.share.revoke", use.GetSecretId(), "denied", "not the creator", useAttrs(use, nil))
		return nil, status.Error(codes.PermissionDenied, "only the person who shared this, or a site admin, can revoke it")
	}
	switch use.GetState() {
	case vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED:
		use.State = vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED
		use.ExpiresAtUnix = s.clock().Unix()
		if err := st.PutUse(ctx, use); err != nil {
			return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
		}
		s.lg(ctx).Info("secret share revoked", log.F("use_id", use.GetId()), log.F("user_id", actor.GetUserId()))
		s.emitAttrs(ctx, actor.GetUserId(), "secret.share.revoke", use.GetSecretId(), true, useAttrs(use, map[string]string{"creator": use.GetUserId()}))
	}
	return &vaultv1.RevokeSecretShareResponse{Use: use}, nil
}
