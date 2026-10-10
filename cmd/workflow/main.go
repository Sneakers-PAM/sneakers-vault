// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	auditv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
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

	maint := mustMaintenance(logger)

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

	svcLog := log.NewLogger(serviceName)
	// The port answers health from here on, while the boot waits for
	// Postgres and runs the migrations: liveness SERVING, so the startup probe
	// passes on a slow boot, and readiness NOT_SERVING with postgres listed
	// down until it is reached.
	boot, err := server.StartBootHealth(cfg.GRPCPort, svcLog, "postgres")
	if err != nil {
		logger.Fatal().Err(err).Msg("boot health")
	}

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
	db, sagaStore, err := openPostgres(ctx, boot, migrateDSN, migrationsDir, cfg.DatabaseDSN)
	if err != nil {
		if ctx.Err() != nil {
			boot.Stop()
			logger.Info().Msg("stopped while waiting for postgres")
			return
		}
		logger.Fatal().Err(err).Msg("migrate / db connect / open saga store")
	}
	defer db.Close()
	recordDBVersion(ctx, logger, db)

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
	svc := grpcsvc.New(st, engine, vault)
	svc.SetLogger(svcLog)
	svc.SetMaintenance(maint)
	svc.SetMFAMaxAge(mustMFAMaxAge(logger))
	auditConn := mustDialAudit(logger)
	defer func() { _ = auditConn.Close() }()
	svc.SetAuditor(auditclient.New(auditv1.NewAuditServiceClient(auditConn)))
	if err := svc.SeedIfEmpty(ctx); err != nil {
		logger.Fatal().Err(err).Msg("seed")
	}

	go svc.RunReaper(ctx, reaperInterval)
	go svc.RunHistoryPurge(ctx, historyPurgeInterval, vault)

	workloadVerifier, authOpts := mustCallerAuth(ctx, logger, svcLog)
	maintUnary, maintStream := grpcsvc.MaintenanceInterceptors(maint, svcLog)
	authOpts = append(authOpts, grpc.ChainUnaryInterceptor(maintUnary), grpc.ChainStreamInterceptor(maintStream))
	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	checker := mustChecker(logger, svcLog, dependencies(db, vault.Conn(), auditConn, workloadVerifier))
	boot.Stop()
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
// retry. Audit is optional: a failed emit is logged and the call goes on. The
// workload-identity verifier is required once service-to-service
// authentication is on; it's left out when authentication is disabled
// (verifier nil).
func dependencies(db server.Database, vault, audit grpc.ClientConnInterface, verifier *workloadauth.Verifier) []health.Dependency {
	deps := []health.Dependency{
		server.Postgres(db),
		server.GRPCPeer("vault", vault, false),
		server.GRPCPeer("audit", audit, false),
	}
	if verifier != nil {
		deps = append(deps, server.WorkloadIdentity(verifier))
	}
	return deps
}

// mustChecker builds readiness over deps. A dependency list it refuses is a
// programming error, so the process stops.
func mustChecker(logger zerolog.Logger, lg log.Logger, deps []health.Dependency) *health.Checker {
	c, err := server.NewChecker(lg, deps)
	if err != nil {
		logger.Fatal().Err(err).Msg("health checker")
	}
	return c
}

// recordDBVersion reads the database version once for the health check
// headers. A failure only costs the diagnostics that one value.
func recordDBVersion(ctx context.Context, logger zerolog.Logger, db *postgres.DB) {
	v, err := server.PostgresVersion(db.Querier())(ctx)
	if err != nil {
		logger.Warn().Err(err).Msg("database version not read; the health check reports it as unknown until it is")
		return
	}
	logger.Info().Str("postgresql_version", v).Msg("database version read")
}

// mustMaintenance reads MAINTENANCE_READONLY; a value that isn't a bool stops
// the boot.
func mustMaintenance(logger zerolog.Logger) *maintenance.Mode {
	m, err := maintenance.FromEnv(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	if m.On() {
		logger.Info().Msg("read-only maintenance is on: mutating calls are refused and the lease reaper and history purge are paused")
	}
	return m
}
