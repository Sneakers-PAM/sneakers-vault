// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command seed is the vault's consolidated DEV/QA seeding tool. It dispatches on
// its first CLI argument to one of four subcommands, each moved verbatim from a
// formerly separate command so their idempotent go-seed Apply+Assert behavior is
// preserved:
//
//	catalog   (default) — upsert the full built-in secret-type catalogue
//	                       (secret_types + extension_catalog + connections) over
//	                       the app's go-postgres pool. Requires DATABASE_DSN.
//	per-type            — create one sample secret of every SYSTEM type via the
//	                       vault gRPC API. Env: VAULT_ADDR, SEED_FOLDER, SEED_USER.
//	bulk               — create a large randomized secret population (folders,
//	                       targets, secrets) and randomize output-only status in
//	                       Postgres. Env: VAULT_ADDR, DATABASE_DSN, SECRET_TARGET.
//	requests           — build the access-request scenario (Production Servers
//	                       folder + 2 secrets + pending requests). Env: VAULT_ADDR,
//	                       WORKFLOW_ADDR.
//
// With no argument it defaults to `catalog`, so existing invocations (running
// `seed` with just DATABASE_DSN) keep working. DEV/QA-ONLY; re-running is safe.
package main

import (
	"context"
	"fmt"
	"os"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// env returns the environment variable k, or def when it is unset/empty.
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// dial opens an insecure gRPC client connection (the seeders talk to in-cluster
// services over the internal network).
func dial(addr string) *grpc.ClientConn {
	c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	return c
}

// openPool connects to DATABASE_DSN via the app's proven go-postgres pool and
// returns it plus a close func. Shared by the catalog and
// bulk subcommands, which both write directly to Postgres.
func openPool(ctx context.Context) (*postgres.DB, func(), error) {
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		return nil, nil, fmt.Errorf("DATABASE_DSN is required")
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("db connect: %w", err)
	}
	return db, db.Close, nil
}

func main() {
	cmd := "catalog"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	logger := log.New("vault-seed")
	ctx := context.Background()

	var err error
	switch cmd {
	case "catalog":
		var pool *postgres.DB
		var closeFn func()
		if pool, closeFn, err = openPool(ctx); err == nil {
			defer closeFn()
			err = seedCatalog(ctx, pool)
		}
	case "per-type":
		err = seedPerType(ctx)
	case "bulk":
		var pool *postgres.DB
		var closeFn func()
		if pool, closeFn, err = openPool(ctx); err == nil {
			defer closeFn()
			err = seedBulk(ctx, pool)
		}
	case "requests":
		err = seedRequests(ctx)
	default:
		fmt.Fprintf(os.Stderr, "usage: seed [catalog|per-type|bulk|requests]  (default: catalog)\n")
		os.Exit(2)
	}
	if err != nil {
		logger.Fatal().Err(err).Str("subcommand", cmd).Msg("seed failed")
	}
}
