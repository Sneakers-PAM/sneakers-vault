// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package catalogseed

import (
	"context"
	"encoding/json"
	"time"

	log "github.com/Bugs5382/go-log"
	bredis "github.com/Bugs5382/go-redis"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	goredis "github.com/redis/go-redis/v9"
)

// invalidation mirrors the payload shape grpcsvc's own publisher writes
// (internal/vault/grpcsvc/invalidate.go). The subscriber reloads the FULL state on
// any message regardless of these fields, so keeping the shapes in exact sync
// is not required for correctness — Origin/Kind are observability-only — but
// matching them keeps the wire format predictable for anyone tailing the
// channel by hand.
type invalidation struct {
	Origin string `json:"origin"`
	Kind   string `json:"kind,omitempty"`
	TS     int64  `json:"ts"`
}

// DialRedis connects to Redis for the post-seed live-reload publish. It is
// best-effort and mirrors cmd/vault's dialRedis: an empty url, an invalid
// URL, or an unreachable server logs a warning and returns nil rather than
// failing the caller — the catalogue upsert this runs after is already
// durable in Postgres, so a vault restart (or the next successful publish)
// still converges. A non-nil Client is verified reachable (Connect pings).
func DialRedis(ctx context.Context, url string) *bredis.Client {
	logger := log.New("vault-seed")
	if url == "" {
		logger.Warn().Msg("REDIS_URL empty: live catalog reload skipped (running vaults need a restart to pick up the change)")
		return nil
	}
	opt, err := goredis.ParseURL(url)
	if err != nil {
		logger.Warn().Err(err).Msg("REDIS_URL invalid: live catalog reload skipped")
		return nil
	}
	ropts := []bredis.Option{bredis.WithAddr(opt.Addr), bredis.WithDB(opt.DB)}
	if opt.Password != "" {
		ropts = append(ropts, bredis.WithPassword(opt.Password))
	}
	rc, err := bredis.Connect(ctx, ropts...)
	if err != nil {
		logger.Warn().Err(err).Msg("redis connect failed: live catalog reload skipped (running vaults need a restart)")
		return nil
	}
	return rc
}

// PublishReload broadcasts a catalog-changed invalidation on channel (default
// grpcsvc.DefaultInvalidateChannel when empty) — the SAME Redis pub/sub
// cache-invalidation channel every running vault replica already subscribes
// to for secret-cache HA (internal/vault/grpcsvc/invalidate.go). A
// replica's subscriber reloads its FULL in-memory state — including
// secret_types/extension_catalog/connections — from Postgres on receipt, so
// no vault-side change is needed: publishing here is the only missing piece
// since this seed writes to Postgres directly, bypassing the
// gRPC PersistUnary interceptor that publishes for in-process mutations.
//
// Best-effort like the vault's own publishInvalidate: a nil client (Redis not
// wired) or a publish error only logs a warning. The DB upsert this is called
// after already succeeded and is durable — a lost publish just means running
// vaults pick up the change on their own next restart or the next successful
// invalidation, never a failed seed.
func PublishReload(ctx context.Context, rc *bredis.Client, channel string) {
	logger := log.New("vault-seed")
	if rc == nil {
		return // DialRedis already warned why.
	}
	if channel == "" {
		channel = grpcsvc.DefaultInvalidateChannel
	}
	payload, err := json.Marshal(invalidation{Origin: "seed-catalog", Kind: "CatalogSeed", TS: time.Now().UnixNano()})
	if err != nil { // unreachable for these fields, but never let this fail the seed
		logger.Warn().Err(err).Msg("marshal catalog invalidation failed: live reload skipped")
		return
	}
	if err := rc.Redis().Publish(ctx, channel, payload).Err(); err != nil {
		logger.Warn().Err(err).Str("channel", channel).Msg("catalog invalidation publish failed: live reload skipped (running vaults need a restart)")
		return
	}
	logger.Info().Str("channel", channel).Msg("published catalog live-reload invalidation")
}
