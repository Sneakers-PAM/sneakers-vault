// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// DefaultRequestHistoryRetentionDays is the fallback retention window applied
// when the vault SecuritySettings can't be read (e.g. vault briefly down):
// resolved access requests are kept 90 days before being purged.
const DefaultRequestHistoryRetentionDays = 90

// RunHistoryPurge runs the resolved-access-request retention purge once on
// startup and then every interval (a day in production). Each pass reads the
// current retention window from the vault SecuritySettings, computes the
// cutoff, and deletes resolved requests older than it (comments cascade).
// Blocks until ctx is done. This makes retention enforcement work in local
// compose without needing a separate scheduled job.
func (s *Server) RunHistoryPurge(ctx context.Context, interval time.Duration, vault vaultv1.VaultServiceClient) {
	s.purgeHistoryOnce(ctx, vault)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.purgeHistoryOnce(ctx, vault)
		}
	}
}

// purgeHistoryOnce performs one retention sweep and returns the number of
// resolved access requests deleted.
func (s *Server) purgeHistoryOnce(ctx context.Context, vault vaultv1.VaultServiceClient) int {
	l := log.Ctx(ctx)
	days := s.retentionDays(ctx, vault)
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	n, err := s.store.PurgeResolvedRequestsOlderThan(ctx, cutoff)
	if err != nil {
		l.Warn().Err(err).Msg("history-purge: delete resolved requests")
		return 0
	}
	if n > 0 {
		l.Info().Int("count", n).Int("retention_days", days).Str("cutoff", cutoff).
			Msg("history-purge: purged resolved access requests")
	}
	return n
}

// retentionDays resolves the retention window from vault SecuritySettings,
// falling back to the default when vault is unreachable or returns 0.
func (s *Server) retentionDays(ctx context.Context, vault vaultv1.VaultServiceClient) int {
	if vault != nil {
		if resp, err := vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{}); err == nil {
			if d := int(resp.GetSettings().GetRequestHistoryRetentionDays()); d > 0 {
				return d
			}
		} else {
			l := log.Ctx(ctx)
			l.Warn().Err(err).Msg("history-purge: read security settings; using fallback retention")
		}
	}
	return DefaultRequestHistoryRetentionDays
}
