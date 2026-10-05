// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	sagapg "github.com/Bugs5382/go-saga-orchestration/store/postgres"
	auditv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/health"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/auditclient"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workflow/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workflow/vaultclient"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// reaperInterval is how often the lease-expiry reaper sweeps for leases past
// expires_at that were never explicitly checked in.
const reaperInterval = 60 * time.Second

// historyPurgeInterval is how often the resolved-access-request retention purge
// sweeps (daily). It also runs once immediately on startup.
const historyPurgeInterval = 24 * time.Hour

const serviceName = "workflow"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}

	otelShutdown, err := otel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	// Service-to-service authentication fails closed: check it before the
	// migrations run.
	mustWorkloadAuthConfig(logger)

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations/workflow"
	}
	// Migrations need a direct/session Postgres connection (advisory locks,
	// CURRENT_SCHEMA, prepared statements) which break through the
	// transaction-pooling connection pooler used at runtime. Use MIGRATE_DSN when set,
	// otherwise fall back to the pooled runtime DSN.
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	// Service tables use a DISTINCT migration-version table so they don't collide
	// with the saga engine's own migrations in the same database.
	if err := postgres.MigrateWithTable(migrateDSN, migrationsDir, "workflow_schema_migrations"); err != nil {
		logger.Fatal().Err(err).Msg("migrate service")
	}
	// The go-saga engine manages its own run/step/signal tables.
	if err := sagapg.Migrate(migrateDSN); err != nil {
		logger.Fatal().Err(err).Msg("migrate saga store")
	}

	db, err := postgres.New(ctx, cfg.DatabaseDSN, otelpg.WithTracing())
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()
	recordDBVersion(ctx, logger, db)

	sagaStore, err := sagapg.Open(ctx, cfg.DatabaseDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("open saga store")
	}

	vault, err := vaultclient.Dial()
	if err != nil {
		logger.Fatal().Err(err).Msg("vault dial")
	}
	defer func() {
		if err := vault.Close(); err != nil {
			logger.Warn().Err(err).Msg("vault client close")
		}
	}()

	st := grpcsvc.NewPGStore(db.Querier())
	engine, err := grpcsvc.BuildEngine(sagaStore, st, vault)
	if err != nil {
		logger.Fatal().Err(err).Msg("build saga engine")
	}
	svcLog := log.NewLogger(serviceName)
	svc := grpcsvc.New(st, engine, vault)
	svc.SetLogger(svcLog)
	svc.SetMFAMaxAge(mustMFAMaxAge(logger))
	auditConn := mustDialAudit(logger)
	defer func() { _ = auditConn.Close() }()
	svc.SetAuditor(auditclient.New(auditv1.NewAuditServiceClient(auditConn)))
	if err := svc.SeedIfEmpty(ctx); err != nil {
		logger.Fatal().Err(err).Msg("seed")
	}

	go svc.RunReaper(ctx, reaperInterval)
	go svc.RunHistoryPurge(ctx, historyPurgeInterval, vault)

	authOpts := mustCallerAuth(ctx, logger, svcLog)
	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	checker := health.New(svcLog, dependencies(db, vault.Conn(), auditConn)...)
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, svcLog, checker, func(gs *grpc.Server) {
		grpcsvc.Register(gs, svc)
	}, authOpts...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}

// dependencies are what readiness follows. Only the database is required: the
// leases, requests and saga runs all live there. The vault is optional, so a
// vault outage (already shown by the vault's own readiness) doesn't also pull
// the workflow; the calls that need it fail on their own and the saga steps
// retry. Audit is optional: a failed emit is logged and the call goes on.
func dependencies(db health.Pinger, vault, audit grpc.ClientConnInterface) []health.Dep {
	return []health.Dep{
		health.Postgres(db),
		health.GRPCPeer("vault", vault, false),
		health.GRPCPeer("audit", audit, false),
	}
}

// recordDBVersion reads the database version once for the health check
// headers. A failure only costs the diagnostics that one value.
func recordDBVersion(ctx context.Context, logger zerolog.Logger, db *postgres.DB) {
	if err := server.RecordPostgresVersion(ctx, db.Querier()); err != nil {
		logger.Warn().Err(err).Msg("database version not read; diagnostics will not show it")
		return
	}
	logger.Info().Str("postgresql_version", server.DependencyVersion(server.DependencyPostgres)).Msg("database version read")
}
