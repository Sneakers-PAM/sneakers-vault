// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package catalogseed

import (
	"context"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/alicebob/miniredis/v2"
)

// TestDialRedisNoURLIsNoop confirms an empty REDIS_URL (Redis not wired for
// this seed run) returns a nil client rather than erroring — the DB upsert
// this runs after must never be failed by a missing/unreachable Redis.
func TestDialRedisNoURLIsNoop(t *testing.T) {
	if rc := DialRedis(context.Background(), ""); rc != nil {
		t.Fatal("expected nil client for empty REDIS_URL")
	}
}

// TestDialRedisInvalidURLIsNoop confirms a malformed REDIS_URL degrades the
// same way — no panic, no error returned to the caller, just a nil client.
func TestDialRedisInvalidURLIsNoop(t *testing.T) {
	if rc := DialRedis(context.Background(), "not-a-redis-url::::"); rc != nil {
		t.Fatal("expected nil client for invalid REDIS_URL")
	}
}

// TestPublishReloadNilClientIsNoop confirms PublishReload never panics or
// blocks when Redis isn't wired (rc == nil, the DialRedis-failed path).
func TestPublishReloadNilClientIsNoop(t *testing.T) {
	PublishReload(context.Background(), nil, "")
}

// TestPublishReloadReachesVaultChannel is the seed-side half of the
// fix: DialRedis + PublishReload, using a REDIS_URL exactly like the
// seed job would provide it, actually publishes on the SAME channel
// (grpcsvc.DefaultInvalidateChannel) the running vault's HA cache-invalidation
// subscriber listens on (internal/vault/grpcsvc/invalidate.go) — proving
// the seed's publish and the vault's subscribe are wired to the same channel,
// with no channel-name drift between the two packages.
func TestPublishReloadReachesVaultChannel(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	sub, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Close() }()
	psub := sub.Redis().Subscribe(context.Background(), grpcsvc.DefaultInvalidateChannel)
	defer func() { _ = psub.Close() }()
	// Drain the subscribe-confirmation before publishing, mirroring how
	// grpcsvc's subscribeLoop only starts forwarding after ReceiveMessage.
	if _, err := psub.Receive(context.Background()); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	rc := DialRedis(context.Background(), "redis://"+mr.Addr()+"/0")
	if rc == nil {
		t.Fatal("DialRedis returned nil for a reachable miniredis")
	}
	defer func() { _ = rc.Close() }()

	PublishReload(context.Background(), rc, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, err := psub.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("expected a message on %s, got err: %v", grpcsvc.DefaultInvalidateChannel, err)
	}
	if msg.Channel != grpcsvc.DefaultInvalidateChannel {
		t.Fatalf("channel = %q, want %q", msg.Channel, grpcsvc.DefaultInvalidateChannel)
	}
}
