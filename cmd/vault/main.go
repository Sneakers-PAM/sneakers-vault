// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	bredis "github.com/Bugs5382/go-redis"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	auditv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/thirdparty/audit/v1"
	notifyv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/thirdparty/notify/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/auditclient"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/notifyclient"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

const serviceName = "vault"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// kekSchedulerCheckInterval resolves how often RunKekScheduler evaluates
// whether the active KEK is due for auto-rotation, from
// KEK_SCHEDULER_CHECK_MINUTES (falling back to 60 minutes when unset or not a
// valid positive integer). This is just the poll cadence — the rotation
// interval itself is SecuritySettings.kek_rotation_days.
// breakGlassExpiryInterval is how often expired break-glass sessions are closed.
const breakGlassExpiryInterval = 30 * time.Second

func kekSchedulerCheckInterval() time.Duration {
	v := env("KEK_SCHEDULER_CHECK_MINUTES", "60")
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		n = 60
	}
	return time.Duration(n) * time.Minute
}

// resolveRootKEK selects the root KEK that wraps the working KEKs in
// kek_keyring (never a secret's DEK directly). VAULT_ROOT_KEK (base64, 32
// bytes) selects a real root in any environment; in dev only, an unset
// VAULT_ROOT_KEK falls back to a DETERMINISTIC seed-derived root so the
// working keyring stays openable across restarts without operator setup.
// Outside dev, an unset VAULT_ROOT_KEK is an error — never run prod on the
// dev root.
func resolveRootKEK(environment string) (crypto.KEKProvider, string, error) {
	if b64 := env("VAULT_ROOT_KEK", ""); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, "", fmt.Errorf("VAULT_ROOT_KEK: invalid base64: %w", err)
		}
		rootKEK, err := crypto.NewStaticKEK(raw)
		if err != nil {
			return nil, "", fmt.Errorf("VAULT_ROOT_KEK: %w", err)
		}
		return rootKEK, "root-v1", nil
	}
	if environment == "dev" {
		rootKEK, err := crypto.NewStaticKEKFromSeed(env("DEV_KEK_SEED", "sneakers-pam-dev-kek-seed-v1"))
		if err != nil {
			return nil, "", fmt.Errorf("dev root KEK init: %w", err)
		}
		return rootKEK, "dev-root-v1", nil
	}
	return nil, "", errors.New("VAULT_ROOT_KEK required in non-dev environments")
}

// buildEnvelope takes the root KEK already resolved and validated by
// migrateAfterPreflight (before any migration ran), builds/loads the
// working-KEK keyring (seeding the first "kek-v1" generation on first boot)
// via BuildKeyring, and returns the envelope vault uses for all secret field
// encryption, plus the keyring and its store that RotateKek needs — the
// caller wires those (with the root KEK + ref) into the Server via SetKeyring
// right after NewWithStore.
func buildEnvelope(ctx context.Context, db *postgres.DB, root crypto.KEKProvider, rootRef string, withDevStatic bool) (*crypto.Envelope, *crypto.KeyringKEK, grpcsvc.KeyringAdmin, error) {
	// The static dev key (sha256 of DEV_KEK_SEED), kept recognized-but-inactive
	// so data sealed with the static dev key keeps unwrapping — until
	// VAULT_DISABLE_DEV_STATIC_KEK drops it (withDevStatic=false).
	var legacy []crypto.WorkingKey
	if withDevStatic {
		legacyKey := sha256.Sum256([]byte(env("DEV_KEK_SEED", "sneakers-pam-dev-kek-seed-v1")))
		legacy = append(legacy, crypto.WorkingKey{Ref: grpcsvc.DevStaticKeyRef, Key: legacyKey[:]})
	}

	ks := grpcsvc.NewKeyringStore(db)
	keyring, err := grpcsvc.BuildKeyring(ctx, ks, root, rootRef, legacy...)
	if err != nil {
		return nil, nil, nil, err
	}
	return crypto.New(keyring), keyring, ks, nil
}

// mustBootKeyring runs bootKeyring with VAULT_DISABLE_DEV_STATIC_KEK, logs
// the KeyRef report (the verification record for the dev-static retirement
// procedure: rows per KeyRef in every table that stores a wrapped DEK — refs
// and counts only, never key material), and exits on any failure.
func mustBootKeyring(ctx context.Context, logger zerolog.Logger, db *postgres.DB, root crypto.KEKProvider, rootRef string) keyringBoot {
	disableDevStatic, err := devStaticDisabled()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	kb, err := bootKeyring(ctx, db, root, rootRef, disableDevStatic)
	if kb.report != nil {
		logger.Info().Str("key_refs", kb.report.String()).
			Int64("dev_static_rows", kb.report.Count(grpcsvc.DevStaticKeyRef)).
			Bool("dev_static_kek_disabled", disableDevStatic).
			Msg("KEK KeyRef report")
	}
	if err != nil {
		logger.Fatal().Err(err).Msg("envelope/keyring init")
	}
	if len(kb.unreadable) > 0 {
		logger.Error().Strs("unreadable_key_refs", kb.unreadable).
			Msg("stored rows reference KeyRefs this keyring cannot unwrap; those secrets cannot be opened")
	}
	logger.Info().Str("active_ref", kb.keyring.ActiveRef()).Bool("dev_static_kek_loaded", kb.keyring.Has(grpcsvc.DevStaticKeyRef)).
		Msg("KEK keyring ready")
	return kb
}

// dialRedis connects to Redis for cache invalidation. It is best-effort: an
// empty url disables pub/sub, and a dial/ping failure logs a warning and returns
// nil so vault still boots (degrading to single-replica reads) rather than
// hard-failing on a Redis outage. Mirrors the notify service's REDIS_URL idiom.
func dialRedis(ctx context.Context, l zerolog.Logger, url string) *bredis.Client {
	if url == "" {
		l.Warn().Msg("REDIS_URL empty: cache invalidation disabled (safe only with replicas=1)")
		return nil
	}
	opt, err := goredis.ParseURL(url)
	if err != nil {
		l.Warn().Err(err).Msg("REDIS_URL invalid: cache invalidation disabled")
		return nil
	}
	ropts := []bredis.Option{bredis.WithAddr(opt.Addr), bredis.WithDB(opt.DB)}
	if opt.Password != "" {
		ropts = append(ropts, bredis.WithPassword(opt.Password))
	}
	rc, err := bredis.Connect(ctx, ropts...)
	if err != nil {
		l.Warn().Err(err).Msg("redis connect failed: cache invalidation disabled (degrading to single-replica reads)")
		return nil
	}
	return rc
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	cfg, err := config.Load()
	if err == nil {
		err = refuseRemovedSettings(os.Getenv)
	}
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

	// Service-to-service authentication fails closed: check it before anything
	// else so a missing issuer stops the boot with the schema untouched.
	mustWorkloadAuthConfig(logger)
	dialOpts := mustDialOptions(logger)

	// Direct (no-broker) audit: every mutation records to the append-only chain.
	auditAddr := env("AUDIT_ADDR", "localhost:9194")
	auditConn, err := grpc.NewClient(auditAddr, dialOpts...)
	if err != nil {
		logger.Fatal().Err(err).Str("audit", auditAddr).Msg("dial audit")
	}
	defer func() { _ = auditConn.Close() }()
	auditor := auditclient.New(auditv1.NewAuditServiceClient(auditConn))

	notifyAddr := env("NOTIFY_ADDR", "localhost:9195")
	notifyConn, err := grpc.NewClient(notifyAddr, dialOpts...)
	if err != nil {
		logger.Fatal().Err(err).Str("notify", notifyAddr).Msg("dial notify")
	}
	defer func() { _ = notifyConn.Close() }()

	migrationsDir := env("MIGRATIONS_DIR", "migrations/vault")
	// Migrations need a direct/session Postgres connection (advisory locks,
	// CURRENT_SCHEMA, prepared statements) which break through the
	// transaction-pooling connection pooler used at runtime. Use MIGRATE_DSN when set,
	// otherwise fall back to the pooled runtime DSN.
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	environment := env("ENVIRONMENT", "dev")
	// Resolve + validate the root KEK BEFORE migrating: a missing/bad
	// VAULT_ROOT_KEK must exit with the schema untouched, because once
	// a new migration is applied the previous image may no longer start.
	rootKEK, rootRef, err := migrateAfterPreflight(ctx, migrateDSN, migrationsDir, environment)
	if err != nil {
		logger.Fatal().Err(err).Msg("root KEK preflight / migrate")
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN, otelpg.WithTracing())
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()
	recordDBVersion(ctx, logger, db)

	kb := mustBootKeyring(ctx, logger, db, rootKEK, rootRef)
	envelope, keyring, keyringStore := kb.envelope, kb.keyring, kb.store

	srv, err := grpcsvc.NewWithStore(ctx, grpcsvc.NewPGStore(db), envelope, auditor, environment)
	if err != nil {
		logger.Fatal().Err(err).Msg("vault init")
	}
	svcLog := log.NewLogger(serviceName)
	srv.SetLogger(svcLog)
	srv.SetMaintenance(maint)
	srv.SetMFAMaxAge(mustMFAMaxAge(logger))
	srv.SetNotifier(notifyclient.New(notifyv1.NewNotifyServiceClient(notifyConn)))
	// RotateKek needs the keyring, its durable store, and the root KEK +
	// ref to mint and persist new working-KEK generations.
	srv.SetKeyring(keyring, keyringStore, rootKEK, rootRef)
	// Automatic KEK rotation: a background scheduler polls every
	// KEK_SCHEDULER_CHECK_MINUTES (default 60) and rotates once the active
	// generation ages past SecuritySettings.kek_rotation_days (0 = off). Runs
	// for the server's lifetime, stopping on ctx cancellation (SIGINT/SIGTERM).
	go srv.RunKekScheduler(ctx, kekSchedulerCheckInterval())

	workerVerifier, err := connectorVerifier(ctx, environment, os.Getenv, svcLog)
	if err != nil {
		logger.Fatal().Err(err).Msg("connector worker identity config")
	}
	srv.SetHeartbeat(db, workerVerifier)
	// Rotation shares the connector identity verifier (a nil verifier, prod
	// without WORKLOAD_OIDC_ISSUER, makes the rotation pull-API fail closed).
	// SetRotation is idempotent for the version store, so ordering vs
	// SetHeartbeat is irrelevant.
	srv.SetRotation(db, workerVerifier)
	srv.SetSecretUses(db)
	// Break-glass browse sessions end on their own at expiry; the sweep writes
	// each one's left event (exactly once across replicas).
	go srv.RunBreakGlassExpiry(ctx, breakGlassExpiryInterval)

	// HA read-consistency: wire Redis pub/sub cache invalidation so every replica
	// re-hydrates from Postgres after any pod's write (fixes stale reads when
	// running >1 replica). Redis is OPTIONAL — an empty REDIS_URL or an
	// unreachable server degrades to single-replica behaviour rather than
	// failing the boot. When wired, a background subscriber reloads on each peer
	// invalidation and reconnects on Redis errors.
	var valkeyPing func(context.Context) error
	if rc := dialRedis(ctx, logger, env("REDIS_URL", "")); rc != nil {
		defer func() { _ = rc.Close() }()
		valkeyPing = func(ctx context.Context) error { return rc.Redis().Ping(ctx).Err() }
		srv.SetInvalidation(rc, env("VAULT_INVALIDATE_CHANNEL", grpcsvc.DefaultInvalidateChannel))
		go srv.RunInvalidationSubscriber(ctx)
	} else {
		srv.SetInvalidation(nil, "") // explicit: subscriber/publisher are no-ops
	}

	workloadVerifier, authOpts, err := callerAuth(ctx, os.Getenv, svcLog, srv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload auth")
	}
	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	checker := mustChecker(logger, svcLog, dependencies(db, auditConn, notifyConn, valkeyPing, workloadVerifier))
	maintUnary, maintStream := grpcsvc.MaintenanceInterceptors(maint, svcLog)
	opts := append(authOpts, grpc.ChainUnaryInterceptor(maintUnary, srv.PersistUnary), grpc.ChainStreamInterceptor(maintStream))
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, svcLog, checker, srv.RegisterInto, opts...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}

// dependencies are what readiness follows. Only the database is required:
// without it the vault can serve nothing. Audit and notify are optional, so an
// outage there doesn't pull every vault replica out of service; calls that must
// record to audit (break-glass) still fail closed on their own. Valkey, when
// configured, only carries cache invalidation between replicas, so it's
// optional too; a nil valkey leaves it out. The workload-identity verifier is
// required once service-to-service authentication is on: no caller can be
// checked before its key set loads; it's left out when authentication is
// disabled (verifier nil).
func dependencies(db server.Database, audit, notify grpc.ClientConnInterface, valkey func(context.Context) error, verifier *workloadauth.Verifier) []health.Dependency {
	deps := []health.Dependency{
		server.Postgres(db),
		server.GRPCPeer("audit", audit, false),
		server.GRPCPeer("notify", notify, false),
	}
	if valkey != nil {
		deps = append(deps, health.Dependency{Name: "valkey", Check: valkey})
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
		logger.Info().Msg("read-only maintenance is on: mutating calls are refused, the connector is handed no jobs and the KEK schedule is paused")
	}
	return m
}
