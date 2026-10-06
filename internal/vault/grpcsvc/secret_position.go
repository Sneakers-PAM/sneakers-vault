// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A secret's position is its 1-based place among its folder's active secrets;
// a retired secret has none (0). Every helper here expects s.mu held for
// writing.

// nextPosition is the position a secret placed last in folderID gets.
func (s *Server) nextPosition(folderID string) int32 {
	var last int32
	for _, sec := range s.secrets {
		if sec.GetFolderId() == folderID && !sec.GetRetired() && sec.GetPosition() > last {
			last = sec.GetPosition()
		}
	}
	return last + 1
}

// activeInFolder returns folderID's active secrets in position order. A
// secret without a position sorts after the placed ones, by name.
func (s *Server) activeInFolder(folderID string) []*vaultv1.Secret {
	var out []*vaultv1.Secret
	for _, sec := range s.secrets {
		if sec.GetFolderId() == folderID && !sec.GetRetired() {
			out = append(out, sec)
		}
	}
	slices.SortStableFunc(out, comparePosition)
	return out
}

func comparePosition(a, b *vaultv1.Secret) int {
	pa, pb := a.GetPosition(), b.GetPosition()
	if (pa == 0) != (pb == 0) {
		if pa == 0 {
			return 1
		}
		return -1
	}
	if pa != pb {
		return int(pa - pb)
	}
	if c := strings.Compare(strings.ToLower(a.GetName()), strings.ToLower(b.GetName())); c != 0 {
		return c
	}
	return strings.Compare(a.GetId(), b.GetId())
}

// compactFolder renumbers folderID's active secrets 1..n in their current
// order, closing any gap a retire, delete or move left.
func (s *Server) compactFolder(folderID string) {
	for i, sec := range s.activeInFolder(folderID) {
		sec.Position = int32(i + 1) // #nosec G115 -- a folder holds far fewer than 2^31 secrets
	}
}

// moveSecretTo places sec last in dest and closes the gap in its old folder.
func (s *Server) moveSecretTo(sec *vaultv1.Secret, dest string) {
	from := sec.GetFolderId()
	if !sec.GetRetired() {
		sec.Position = s.nextPosition(dest)
	}
	sec.FolderId = dest
	s.compactFolder(from)
}

// sortForListing orders a folder listing: active secrets by position, then
// retired ones in their stored order.
func sortForListing(secs []*vaultv1.Secret) {
	slices.SortStableFunc(secs, func(a, b *vaultv1.Secret) int {
		if a.GetRetired() != b.GetRetired() {
			if a.GetRetired() {
				return 1
			}
			return -1
		}
		if a.GetRetired() {
			return 0
		}
		return comparePosition(a, b)
	})
}

// ReorderSecrets sets the manual order of a folder's active secrets. The
// caller needs RACI Author on the folder or must own it, and ordered_ids must
// name every active secret in the folder exactly once.
func (s *Server) ReorderSecrets(ctx context.Context, req *vaultv1.ReorderSecretsRequest) (*vaultv1.ReorderSecretsResponse, error) {
	l := s.lg(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if !s.canManage(req.GetActor(), f.GetId()) && !s.isFolderOwner(req.GetActor(), f) {
		l.Info("reorder secrets refused: no author rights", log.F("folder_id", f.GetId()))
		return nil, status.Error(codes.PermissionDenied, "not permitted to reorder this folder's secrets")
	}
	active := map[string]*vaultv1.Secret{}
	for _, sec := range s.activeInFolder(f.GetId()) {
		active[sec.GetId()] = sec
	}
	ids := req.GetOrderedIds()
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if active[id] == nil || seen[id] {
			return nil, status.Error(codes.InvalidArgument, "ordered_ids must name every active secret in the folder exactly once")
		}
		seen[id] = true
	}
	if len(seen) != len(active) {
		return nil, status.Error(codes.InvalidArgument, "ordered_ids must name every active secret in the folder exactly once")
	}
	out := make([]*vaultv1.Secret, 0, len(ids))
	for i, id := range ids {
		sec := active[id]
		sec.Position = int32(i + 1) // #nosec G115 -- bounded by the folder's secret count
		_, canRead := s.secretVisibility(req.GetActor(), sec)
		out = append(out, withCanRead(sec, canRead))
	}
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "secret.reorder", f.GetId(), false, map[string]string{
		"count": strconv.Itoa(len(ids)),
	})
	l.Info("secrets reordered", log.F("folder_id", f.GetId()), log.F("count", len(ids)))
	return &vaultv1.ReorderSecretsResponse{Secrets: out}, nil
}
