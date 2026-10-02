// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListSecretVersions returns the secret's append-only version ledger (newest
// version_no first) as metadata + field keys — never any values. Gated by the
// SAME read/reveal access as RevealSecretField (RACI C on the secret): if you
// may reveal the secret you may see its history. Listing is metadata-only, so it
// is not itself an audited access (mirroring GetSecretFields, which also skips
// audit). A mem-only server with no version store returns an empty history.
func (s *Server) ListSecretVersions(ctx context.Context, req *vaultv1.ListSecretVersionsRequest) (*vaultv1.ListSecretVersionsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if req.GetActor().GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || !s.canRead(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to view this secret's history")
	}
	if s.vers == nil {
		return &vaultv1.ListSecretVersionsResponse{}, nil
	}
	metas, err := s.vers.List(ctx, sec.GetId(), s.crypt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list versions: %v", err)
	}
	out := make([]*vaultv1.SecretVersion, 0, len(metas))
	for _, m := range metas {
		out = append(out, &vaultv1.SecretVersion{
			VersionNo:        safeconv.Int32(m.VersionNo),
			CreatedBy:        m.CreatedBy,
			CreatedAt:        m.CreatedAt.UTC().Format(time.RFC3339),
			Active:           m.Active,
			FieldKeys:        m.FieldKeys,
			ChangedFieldKeys: m.ChangedFieldKeys,
		})
	}
	return &vaultv1.ListSecretVersionsResponse{Versions: out}, nil
}

// RevealSecretVersionField decrypts ONE field from a specific prior (or current)
// version. It needs the recovery role and a fresh MFA (requireRecovery) as well
// as RACI C on the secret, and is recorded at the audit tier as a sensitive
// reveal with action
// "secret.version.reveal" and subject "<secretId>#<fieldKey>@v<versionNo>".
func (s *Server) RevealSecretVersionField(ctx context.Context, req *vaultv1.RevealSecretVersionFieldRequest) (*vaultv1.RevealSecretVersionFieldResponse, error) {
	if err := s.requireRecovery(ctx, req.GetActor(), "RevealSecretVersionField", req.GetSecretId()); err != nil {
		return nil, err
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
	if !s.canRead(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to reveal this secret")
	}
	if s.vers == nil {
		return nil, errNotFound("secret version")
	}
	rec, ok, err := s.vers.LoadVersion(ctx, sec.GetId(), int(req.GetVersionNo()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load version: %v", err)
	}
	if !ok {
		return nil, errNotFound("secret version")
	}
	val, err := s.crypt.Open(rec, req.GetFieldKey())
	if err == crypto.ErrFieldNotFound {
		return nil, errNotFound("field")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	bumpView(sec)
	subject := fmt.Sprintf("%s#%s@v%d", sec.GetId(), req.GetFieldKey(), req.GetVersionNo())
	s.emitTier(ctx, audit.TierAudit, req.GetActor().GetUserId(), "secret.version.reveal", subject, true, map[string]string{"version_no": strconv.Itoa(int(req.GetVersionNo()))})
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.version.reveal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.RevealSecretVersionFieldResponse{Value: val}, nil
}
