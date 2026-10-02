// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// heartbeatScheduleDDL mirrors the heartbeat_schedule table in
// migrations/vault/0001_baseline.up.sql (idempotent), applied here directly so
// this test runs standalone against any Postgres named by TEST_DATABASE_DSN.
const heartbeatScheduleDDL = `
CREATE TABLE IF NOT EXISTS heartbeat_schedule (
  secret_id               TEXT PRIMARY KEY,
  next_heartbeat_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  interval_seconds        INT NOT NULL DEFAULT 300,
  consecutive_unreachable INT NOT NULL DEFAULT 0,
  claimed_until           TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS heartbeat_schedule_due ON heartbeat_schedule (next_heartbeat_at);
`

func hbTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err := p.Exec(context.Background(), heartbeatScheduleDDL); err != nil {
		t.Fatalf("bootstrap heartbeat_schedule: %v", err)
	}
	// ClaimDue's rotation-coordination guard references rotation_schedule, so it
	// must exist even for heartbeat-only tests (in production migration 0004
	// always runs on boot).
	if _, err := p.Exec(context.Background(), rotationScheduleDDL); err != nil {
		t.Fatalf("bootstrap rotation_schedule: %v", err)
	}
	_, _ = p.Exec(context.Background(), "TRUNCATE heartbeat_schedule")
	return p
}

func TestClaimDueSkipsLockedAndReschedules(t *testing.T) {
	ctx := context.Background()
	hs := newHeartbeatStore(hbTestPool(t))
	if err := hs.Ensure(ctx, "sec-1", 300); err != nil {
		t.Fatal(err)
	}
	got, err := hs.ClaimDue(ctx, 10, time.Minute)
	if err != nil || len(got) != 1 || got[0] != "sec-1" {
		t.Fatalf("claim: %v %v", got, err)
	}
	// already claimed (claimed_until in future) → not returned again
	again, _ := hs.ClaimDue(ctx, 10, time.Minute)
	if len(again) != 0 {
		t.Fatalf("claimed row re-returned: %v", again)
	}
	if err := hs.Reschedule(ctx, "sec-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	future, _ := hs.ClaimDue(ctx, 10, time.Minute)
	if len(future) != 0 {
		t.Fatalf("future row claimed early: %v", future)
	}
}
