// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command seed-catalog is a minimal, PROD-SAFE seeder: it upserts the vault's
// built-in secret-type catalogue (secret_types + extension_catalog +
// connections, via internal/vault/catalogseed) and does nothing else. Unlike
// cmd/seed (the DEV/QA-only consolidated tool with bulk/per-type/requests
// subcommands, which must NEVER ship in a prod-reachable image), this binary
// imports ONLY internal/vault/catalogseed — it cannot generate bulk/fake data or
// exercise the gRPC API, so it is safe to run against prod on every deploy
// (e.g. a post-deploy job) to keep the catalogue current.
//
// Config: the same DATABASE_DSN convention as cmd/seed's `catalog` subcommand,
// connected via the app's proven go-postgres pool. Any job wiring this binary
// needs the same database DSN as cmd/seed's catalog subcommand.
package main

import (
	"context"
	"fmt"
	"os"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/catalogseed"
)

func main() {
	logger := log.New("vault-seed-catalog")
	ctx := context.Background()

	if err := run(ctx); err != nil {
		logger.Fatal().Err(err).Msg("seed-catalog failed")
	}
	logger.Info().Msg("seed-catalog complete")
}

// run connects to DATABASE_DSN and upserts the built-in catalogue, then
// publishes a live-reload invalidation so already-running vault replicas pick
// up the change now instead of on their next restart. The
// publish reuses the same REDIS_URL and Redis pub/sub channel the vault's own
// HA cache-invalidation subscriber listens on (see internal/vault/catalogseed's
// DialRedis/PublishReload) — Redis being unset or unreachable never fails
// this seed, since the upsert above is already durable in Postgres. Split out
// from main so the error path is a single, testable return.
func run(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		return fmt.Errorf("DATABASE_DSN is required")
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer db.Close()

	if err := catalogseed.Run(ctx, db.Pool()); err != nil {
		return err
	}

	rc := catalogseed.DialRedis(ctx, os.Getenv("REDIS_URL"))
	if rc != nil {
		defer func() { _ = rc.Close() }()
	}
	catalogseed.PublishReload(ctx, rc, os.Getenv("VAULT_INVALIDATE_CHANNEL"))
	return nil
}
