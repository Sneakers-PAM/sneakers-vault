// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	postgres "github.com/Bugs5382/go-postgres"
	sagapg "github.com/Bugs5382/go-saga-orchestration/store/postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/telemetry"
)

// isMigrateCommand reports whether args (os.Args) ask for `workflow migrate`.
func isMigrateCommand(args []string) bool {
	return len(args) > 1 && args[1] == "migrate"
}

// runMigrate is `workflow migrate`: the service migrations and then the saga
// engine's own tables, as the boot applies them. The migration library takes
// the Postgres advisory lock, so several instances racing at start-up are
// safe.
func runMigrate(_ context.Context, migrateDSN, migrationsDir string) error {
	if err := postgres.MigrateWithTable(migrateDSN, migrationsDir, "workflow_schema_migrations"); err != nil {
		return fmt.Errorf("migrate command: service tables: %w", err)
	}
	if err := sagapg.Migrate(migrateDSN); err != nil {
		return fmt.Errorf("migrate command: saga tables: %w", err)
	}
	return nil
}

// maybeMigrate runs `workflow migrate` from the environment when args ask for it and
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
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations/workflow"
	}
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	logger.Info().Str("dir", migrationsDir).Msg("migrate: starting")
	if err := runMigrate(ctx, migrateDSN, migrationsDir); err != nil {
		logger.Fatal().Err(err).Msg("migrate: failed")
	}
	logger.Info().Msg("migrate: done")
	return true
}
