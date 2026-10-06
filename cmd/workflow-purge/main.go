// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command workflow-purge deletes resolved access requests (and their comment threads,
// via ON DELETE CASCADE) older than the configured retention window from the
// workflow database, then exits. It is the entrypoint a scheduled job
// (for example a Kubernetes CronJob) runs daily; the workflow service itself
// also runs the same sweep on an internal ticker (see grpcsvc.RunHistoryPurge)
// so retention is enforced in local compose without that job.
//
// Configuration:
//   - DATABASE_DSN     (required) workflow Postgres DSN.
//   - VAULT_ADDR       (optional) vault gRPC address; when reachable the
//     retention window is read from SecuritySettings.requestHistoryRetentionDays.
//   - RETENTION_DAYS   (optional) explicit override; used when > 0.
//   - MAINTENANCE_READONLY (optional) true skips the purge and exits 0, so a
//     scheduled run during read-only maintenance deletes nothing.
//
// Retention resolution order: RETENTION_DAYS env > vault SecuritySettings >
// the 90-day default.
package main

import (
	"context"
	"os"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workflow/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workflow/vaultclient"
	"github.com/rs/zerolog"
)

func main() {
	logger := log.New("workflow-history-purge")
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	maint, err := maintenance.FromEnv(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	if maint.On() {
		logger.Info().Msg("read-only maintenance is on: nothing purged")
		return
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()

	days := resolveRetentionDays(ctx, logger)
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)

	st := grpcsvc.NewPGStore(db.Querier())
	n, err := st.PurgeResolvedRequestsOlderThan(ctx, cutoff)
	if err != nil {
		logger.Fatal().Err(err).Msg("purge resolved requests")
	}
	logger.Info().Int("count", n).Int("retention_days", days).Str("cutoff", cutoff).
		Msg("purged resolved access requests")
}

// resolveRetentionDays picks the retention window: RETENTION_DAYS env override,
// else vault SecuritySettings, else the 90-day default.
func resolveRetentionDays(ctx context.Context, l zerolog.Logger) int {
	if v := os.Getenv("RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			return d
		}
	}
	if os.Getenv("VAULT_ADDR") != "" {
		if vault, err := vaultclient.Dial(); err == nil {
			defer func() { _ = vault.Close() }()
			if resp, err := vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{}); err == nil {
				if d := int(resp.GetSettings().GetRequestHistoryRetentionDays()); d > 0 {
					return d
				}
			} else {
				l.Warn().Err(err).Msg("read security settings; using fallback retention")
			}
		}
	}
	return grpcsvc.DefaultRequestHistoryRetentionDays
}
