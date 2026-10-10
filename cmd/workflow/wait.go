// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	sagapg "github.com/Bugs5382/go-saga-orchestration/store/postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
)

// openPostgres runs the service and saga-store migrations and opens the pool
// and the saga store, waiting with backoff while PostgreSQL (or its DNS name)
// isn't reachable yet, so a boot that comes up first never exits for it.
// Each failed attempt is logged and shown in the boot health report. A
// non-transient error (bad credentials, a failing migration) and ctx ending
// are returned.
func openPostgres(ctx context.Context, boot *server.BootHealth, migrateDSN, migrationsDir, dsn string, wait ...postgres.WaitOption) (*postgres.DB, *sagapg.Store, error) {
	wait = append([]postgres.WaitOption{postgres.WithRetryHook(boot.RetryHook("postgres"))}, wait...)
	// Service tables use a DISTINCT migration-version table so they don't
	// collide with the saga engine's own migrations in the same database.
	if err := postgres.WaitFor(ctx, func(context.Context) error {
		return postgres.MigrateWithTable(migrateDSN, migrationsDir, "workflow_schema_migrations")
	}, wait...); err != nil {
		return nil, nil, err
	}
	// The go-saga engine manages its own run/step/signal tables.
	if err := postgres.WaitFor(ctx, func(context.Context) error { return sagapg.Migrate(migrateDSN) }, wait...); err != nil {
		return nil, nil, err
	}
	var db *postgres.DB
	if err := postgres.WaitFor(ctx, func(ctx context.Context) error {
		var err error
		db, err = postgres.New(ctx, dsn, otelpg.WithTracing())
		return err
	}, wait...); err != nil {
		return nil, nil, err
	}
	var store *sagapg.Store
	if err := postgres.WaitFor(ctx, func(ctx context.Context) error {
		var err error
		store, err = sagapg.Open(ctx, dsn)
		return err
	}, wait...); err != nil {
		db.Close()
		return nil, nil, err
	}
	boot.Up("postgres")
	return db, store, nil
}
