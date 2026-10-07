// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"strconv"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxSealForImportItems caps one SealForImport batch, bounding the plaintext a
// single call holds in memory.
const maxSealForImportItems = 500

// SealForImport seals each item's fields under the active working KEK and
// returns the envelopes in request order, as JSON in the form secret_records
// and secret_versions store. Nothing is stored, so the importer writes the
// records itself; the root key and working keys never leave the vault.
//
// The caller policy admits only the migrate caller. The handler checks the
// grant too, so with workload authentication disabled the call is refused
// whatever actor it carries.
func (s *Server) SealForImport(ctx context.Context, req *vaultv1.SealForImportRequest) (*vaultv1.SealForImportResponse, error) {
	l := s.lg(ctx)
	g, ok := workloadauth.GrantFromContext(ctx)
	if !ok || g.Caller.Name != CallerMigrate || g.Access != workloadauth.Self {
		l.Warn("seal for import refused", log.F("caller", g.Caller.Name), log.F("claimed_actor", req.GetActor().GetUserId()))
		return nil, status.Error(codes.PermissionDenied, "seal for import is for the migrate caller only")
	}
	actor := req.GetActor().GetUserId()
	items := req.GetItems()
	if len(items) > maxSealForImportItems {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d items per call, got %d", maxSealForImportItems, len(items))
	}
	out := make([][]byte, 0, len(items))
	for i, it := range items {
		rec, err := s.crypt.Seal(it.GetFields())
		if err != nil {
			l.Error(err, "seal for import failed", log.F("actor", actor), log.F("item", i))
			return nil, status.Errorf(codes.Internal, "seal item %d: %v", i, err)
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encode item %d: %v", i, err)
		}
		out = append(out, raw)
	}
	s.emitTier(ctx, audit.TierAudit, actor, "vault.import.seal", "", false, map[string]string{"items": strconv.Itoa(len(items))})
	l.Info("sealed for import", log.F("actor", actor), log.F("items", len(items)))
	return &vaultv1.SealForImportResponse{Records: out}, nil
}
