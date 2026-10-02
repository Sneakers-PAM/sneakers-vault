// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sort"
	"strings"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// readable returns the actor's readable secrets (folder RBAC via canRead).
func (s *Server) readable(actor *vaultv1.ActorContext) []*vaultv1.Secret {
	var out []*vaultv1.Secret
	for _, sec := range s.secrets {
		if s.canRead(actor, sec) {
			out = append(out, sec)
		}
	}
	return out
}

// GetSecretStats rolls up the actor's readable secrets for the dashboard.
func (s *Server) GetSecretStats(_ context.Context, req *vaultv1.GetSecretStatsRequest) (*vaultv1.GetSecretStatsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	soon := now.Add(30 * 24 * time.Hour)
	stats := &vaultv1.SecretStats{}
	for _, sec := range s.readable(req.GetActor()) {
		stats.Total++
		if e := sec.GetExpiresAt(); e != "" {
			if t, err := time.Parse(time.RFC3339, e); err == nil {
				switch {
				case t.Before(now):
					stats.Expired++
				case t.Before(soon):
					stats.ExpiringSoon++
				}
			}
		}
		if heartbeatFailed(sec.GetLastHeartbeatResult()) {
			stats.Drift++
		}
	}
	return &vaultv1.GetSecretStatsResponse{Stats: stats}, nil
}

// secretMatchesStatus applies the same status rules GetSecretStats rolls up:
// expired = expires_at parseable & before now; expiring = before now+30d & not
// expired; drift = last heartbeat failed (FAILED or a host-key refusal); all = every (readable) secret.
func secretMatchesStatus(sec *vaultv1.Secret, status string, now, soon time.Time) bool {
	switch status {
	case "all", "":
		return true
	case "drift":
		return heartbeatFailed(sec.GetLastHeartbeatResult())
	case "expired", "expiring":
		e := sec.GetExpiresAt()
		if e == "" {
			return false
		}
		t, err := time.Parse(time.RFC3339, e)
		if err != nil {
			return false
		}
		if status == "expired" {
			return t.Before(now)
		}
		return !t.Before(now) && t.Before(soon)
	default:
		return false
	}
}

// ListSecretsByStatus powers the dashboard tile drill-down: the actor's
// readable secrets (RACI-scoped via readable) filtered by status, sorted by
// name. status ∈ {"expiring","expired","drift","all"}.
func (s *Server) ListSecretsByStatus(_ context.Context, req *vaultv1.ListSecretsByStatusRequest) (*vaultv1.ListSecretsByStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	soon := now.Add(30 * 24 * time.Hour)
	var out []*vaultv1.Secret
	for _, sec := range s.readable(req.GetActor()) {
		if secretMatchesStatus(sec, req.GetStatus(), now, soon) {
			out = append(out, sec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return &vaultv1.ListSecretsByStatusResponse{Secrets: out}, nil
}

// GetTopAccessedSecrets returns the actor's most-accessed secrets (view_count > 0).
func (s *Server) GetTopAccessedSecrets(_ context.Context, req *vaultv1.GetTopAccessedSecretsRequest) (*vaultv1.GetTopAccessedSecretsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultv1.Secret
	for _, sec := range s.readable(req.GetActor()) {
		if sec.GetViewCount() > 0 {
			out = append(out, sec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].GetViewCount() > out[j].GetViewCount() })
	if lim := int(req.GetLimit()); lim > 0 && len(out) > lim {
		out = out[:lim]
	}
	return &vaultv1.GetTopAccessedSecretsResponse{Secrets: out}, nil
}

// FindSecretsByPublicKey returns readable secrets whose stored publicKey field
// contains the query (case-insensitive). Public keys are non-sensitive and
// searchable; the field set is unsealed to read it (dev-acceptable).
func (s *Server) FindSecretsByPublicKey(_ context.Context, req *vaultv1.FindSecretsByPublicKeyRequest) (*vaultv1.FindSecretsByPublicKeyResponse, error) {
	q := strings.ToLower(strings.TrimSpace(req.GetQuery()))
	if q == "" {
		return &vaultv1.FindSecretsByPublicKeyResponse{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultv1.Secret
	for _, sec := range s.readable(req.GetActor()) {
		rec, ok := s.records[sec.GetId()]
		if !ok {
			continue
		}
		all, err := s.crypt.OpenAll(rec)
		if err != nil {
			continue
		}
		if pk, ok := all["publicKey"]; ok && strings.Contains(strings.ToLower(pk), q) {
			out = append(out, sec)
		}
	}
	return &vaultv1.FindSecretsByPublicKeyResponse{Secrets: out}, nil
}
