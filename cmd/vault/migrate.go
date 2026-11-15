// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/telemetry"
)

// isMigrateCommand reports whether args (os.Args) ask for `vault migrate`.
func isMigrateCommand(args []string) bool {
	return len(args) > 1 && args[1] == "migrate"
}

// runMigrate is `vault migrate`: the same root KEK preflight and migrations
// the boot runs (so a missing or wrong VAULT_ROOT_KEK still stops it with the
// schema untouched), then it returns. The migration library takes the
// Postgres advisory lock, so several instances racing at start-up are safe.
func runMigrate(ctx context.Context, migrateDSN, migrationsDir, environment string) error {
	if _, _, err := migrateAfterPreflight(ctx, migrateDSN, migrationsDir, environment); err != nil {
		return fmt.Errorf("migrate command: %w", err)
	}
	return nil
}

// maybeMigrate runs `vault migrate` from the environment when args ask for it and
// reports true; the caller then returns, so the process exits 0 on success
// (a failure is fatal, non-zero). It starts no server, no telemetry exporter
// and no health port.
func maybeMigrate(ctx context.Context, args []string) bool {
	if !isMigrateCommand(args) {
		return false
	}
	_, logger := telemetry.NewLoggers(serviceName, os.Getenv)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	migrationsDir := env("MIGRATIONS_DIR", "migrations/vault")
	// Same DSN choice as the boot: a direct connection for the advisory lock.
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	environment := env("ENVIRONMENT", "dev")
	logger.Info().Str("dir", migrationsDir).Str("environment", environment).Msg("migrate: starting")
	if err := runMigrate(ctx, migrateDSN, migrationsDir, environment); err != nil {
		logger.Fatal().Err(err).Msg("migrate: failed")
	}
	logger.Info().Msg("migrate: done")
	return true
}
