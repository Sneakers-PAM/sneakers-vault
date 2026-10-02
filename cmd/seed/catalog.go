// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/catalogseed"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedCatalog upserts the vault's full built-in secret-type catalogue. The
// actual implementation lives in internal/vault/catalogseed so it can be shared
// with cmd/seed-catalog (the separate, prod-safe, catalog-only binary/image)
// without pulling this command's bulk/per-type/requests code along with it.
// After the upsert, it also publishes a live-reload invalidation
// so a manual dev/qa reseed converges on already-running vault replicas
// without a restart, same as cmd/seed-catalog's post-deploy path. Best-effort:
// no REDIS_URL, or an unreachable Redis, only logs a warning.
func seedCatalog(ctx context.Context, pool *pgxpool.Pool) error {
	if err := catalogseed.Run(ctx, pool); err != nil {
		return err
	}
	rc := catalogseed.DialRedis(ctx, os.Getenv("REDIS_URL"))
	if rc != nil {
		defer func() { _ = rc.Close() }()
	}
	catalogseed.PublishReload(ctx, rc, os.Getenv("VAULT_INVALIDATE_CHANNEL"))
	return nil
}
