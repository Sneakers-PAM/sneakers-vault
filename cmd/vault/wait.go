// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/rs/zerolog"
)

// mustBootHealth starts the boot health service on port; failing to listen
// is fatal.
func mustBootHealth(logger zerolog.Logger, port string, lg log.Logger) *server.BootHealth {
	boot, err := server.StartBootHealth(port, lg, "postgres")
	if err != nil {
		logger.Fatal().Err(err).Msg("boot health")
	}
	return boot
}

// openPostgres runs the root KEK preflight and the migrations, then connects
// the pool, waiting with backoff while PostgreSQL (or its DNS name) isn't
// reachable yet, so a boot that comes up first never exits for it. Each
// failed attempt is logged and shown in the boot health report. A
// non-transient error is returned at once: a missing or wrong VAULT_ROOT_KEK
// still stops the boot with the schema untouched, as does a failing
// migration or bad credentials.
func openPostgres(ctx context.Context, boot *server.BootHealth, migrateDSN, migrationsDir, environment, dsn string, wait ...postgres.WaitOption) (crypto.KEKProvider, string, *postgres.DB, error) {
	wait = append([]postgres.WaitOption{postgres.WithRetryHook(boot.RetryHook("postgres"))}, wait...)
	var root crypto.KEKProvider
	var rootRef string
	if err := postgres.WaitFor(ctx, func(ctx context.Context) error {
		var err error
		root, rootRef, err = migrateAfterPreflight(ctx, migrateDSN, migrationsDir, environment)
		return err
	}, wait...); err != nil {
		return nil, "", nil, err
	}
	var db *postgres.DB
	if err := postgres.WaitFor(ctx, func(ctx context.Context) error {
		var err error
		db, err = postgres.New(ctx, dsn, otelpg.WithTracing())
		return err
	}, wait...); err != nil {
		return nil, "", nil, err
	}
	boot.Up("postgres")
	return root, rootRef, db, nil
}
