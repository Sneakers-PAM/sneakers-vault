// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// rotationScheduleDDL mirrors migrations/0004_rotation.up.sql (idempotent).
const rotationScheduleDDL = `
CREATE TABLE IF NOT EXISTS rotation_schedule (
  secret_id            TEXT        PRIMARY KEY,
  next_rotation_at     TIMESTAMPTZ,
  interval_days        INT         NOT NULL DEFAULT 0,
  claimed_until        TIMESTAMPTZ,
  state                INT         NOT NULL DEFAULT 0,
  reason               TEXT        NOT NULL DEFAULT '',
  consecutive_failures INT         NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS rotation_schedule_due ON rotation_schedule (next_rotation_at);
`

func rotTestPool(t *testing.T) *pgxpool.Pool {
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
	if _, err := p.Exec(context.Background(), rotationScheduleDDL); err != nil {
		t.Fatalf("bootstrap rotation_schedule: %v", err)
	}
	_, _ = p.Exec(context.Background(), "TRUNCATE rotation_schedule")
	return p
}

const stROTATING = 4 // vaultv1.RotationState_ROTATION_STATE_ROTATING

func TestRotationStoreEnqueueClaimReschedule(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	if err := r.Enqueue(ctx, "sec-1", "manual", 30); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	got, err := r.ClaimDue(ctx, 10, time.Minute)
	if err != nil || len(got) != 1 || got[0] != "sec-1" {
		t.Fatalf("ClaimDue: %v %v", got, err)
	}
	// state stamped ROTATING and claimed_until in the future.
	var state int
	var claimedFuture bool
	if err := r.db.QueryRow(ctx, `SELECT state, claimed_until > now() FROM rotation_schedule WHERE secret_id='sec-1'`).Scan(&state, &claimedFuture); err != nil {
		t.Fatal(err)
	}
	if state != stROTATING {
		t.Fatalf("state = %d, want ROTATING(%d)", state, stROTATING)
	}
	if !claimedFuture {
		t.Fatal("claimed_until should be in the future after claim")
	}
	// Second immediate claim returns nothing (still claimed).
	again, _ := r.ClaimDue(ctx, 10, time.Minute)
	if len(again) != 0 {
		t.Fatalf("claimed row re-returned: %v", again)
	}
	// Reschedule to the future clears the claim and removes from due.
	if err := r.Reschedule(ctx, "sec-1", time.Now().Add(time.Hour), 1); err != nil {
		t.Fatalf("Reschedule: %v", err)
	}
	future, _ := r.ClaimDue(ctx, 10, time.Minute)
	if len(future) != 0 {
		t.Fatalf("future row claimed early: %v", future)
	}
	var claimNull bool
	if err := r.db.QueryRow(ctx, `SELECT claimed_until IS NULL FROM rotation_schedule WHERE secret_id='sec-1'`).Scan(&claimNull); err != nil {
		t.Fatal(err)
	}
	if !claimNull {
		t.Fatal("Reschedule should clear claimed_until")
	}
}

func TestRotationStoreConcurrentClaimNoCollision(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	const n = 40
	for i := 0; i < n; i++ {
		if err := r.Enqueue(ctx, fmt.Sprintf("sec-%d", i), "manual", 0); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]int{}
	claim := func() {
		defer wg.Done()
		for {
			got, err := r.ClaimDue(ctx, 5, time.Minute)
			if err != nil {
				t.Errorf("ClaimDue: %v", err)
				return
			}
			if len(got) == 0 {
				return
			}
			mu.Lock()
			for _, id := range got {
				seen[id]++
			}
			mu.Unlock()
		}
	}
	wg.Add(2)
	go claim()
	go claim()
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("claimed %d distinct, want %d", len(seen), n)
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("%s claimed %d times (SKIP LOCKED collision)", id, c)
		}
	}
}

func TestRotationStoreEnsureScheduledIntervalGate(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	// interval 0 → row exists but not due (next_rotation_at NULL).
	if err := r.EnsureScheduled(ctx, "sec-0", 0); err != nil {
		t.Fatal(err)
	}
	due, _ := r.ClaimDue(ctx, 10, time.Minute)
	if len(due) != 0 {
		t.Fatalf("interval-0 secret should not be due: %v", due)
	}
	ok, err := r.Exists(ctx, "sec-0")
	if err != nil || !ok {
		t.Fatalf("Exists: %v %v", ok, err)
	}
	// interval >0 → next scheduled in the future (not due now).
	if err := r.EnsureScheduled(ctx, "sec-1", 30); err != nil {
		t.Fatal(err)
	}
	due2, _ := r.ClaimDue(ctx, 10, time.Minute)
	if len(due2) != 0 {
		t.Fatalf("future-scheduled secret should not be due now: %v", due2)
	}
}

func TestRotationStoreFailureCounters(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	if err := r.Enqueue(ctx, "sec-1", "manual", 0); err != nil {
		t.Fatal(err)
	}
	n1, err := r.BumpFailure(ctx, "sec-1")
	if err != nil || n1 != 1 {
		t.Fatalf("BumpFailure#1: %d %v", n1, err)
	}
	n2, _ := r.BumpFailure(ctx, "sec-1")
	if n2 != 2 {
		t.Fatalf("BumpFailure#2: %d", n2)
	}
	if err := r.ClearFailure(ctx, "sec-1"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := r.db.QueryRow(ctx, `SELECT consecutive_failures FROM rotation_schedule WHERE secret_id='sec-1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failures = %d, want 0 after clear", n)
	}
}

func TestRotationStoreInFlightOnConnection(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	if err := r.Enqueue(ctx, "sec-a", "manual", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.Enqueue(ctx, "sec-b", "manual", 0); err != nil {
		t.Fatal(err)
	}
	// Nothing claimed yet → not in flight.
	inflight, err := r.InFlightOnConnection(ctx, []string{"sec-a", "sec-b"})
	if err != nil || inflight {
		t.Fatalf("InFlight before claim: %v %v", inflight, err)
	}
	// Claim sec-a → it's now in flight on the connection set.
	if _, err := r.ClaimDue(ctx, 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	inflight, err = r.InFlightOnConnection(ctx, []string{"sec-a", "sec-b"})
	if err != nil {
		t.Fatal(err)
	}
	if !inflight {
		t.Fatal("expected in-flight after claiming a peer on the connection")
	}
	// A disjoint connection set is not in flight.
	other, _ := r.InFlightOnConnection(ctx, []string{"sec-z"})
	if other {
		t.Fatal("disjoint set should not be in flight")
	}
}

// TestHeartbeatClaimSkipsInFlightRotation proves the coordination guard: while a
// secret's rotation is claimed (claimed_until > now), heartbeat ClaimDue must not
// return it — rotation wins so heartbeat never binds mid-swap.
func TestHeartbeatClaimSkipsInFlightRotation(t *testing.T) {
	ctx := context.Background()
	pool := rotTestPool(t) // bootstraps + truncates rotation_schedule
	if _, err := pool.Exec(ctx, heartbeatScheduleDDL); err != nil {
		t.Fatalf("bootstrap heartbeat_schedule: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE heartbeat_schedule"); err != nil {
		t.Fatal(err)
	}
	hs := newHeartbeatStore(pool)
	rs := newRotationStore(pool)

	if err := hs.Ensure(ctx, "sec-1", 300); err != nil {
		t.Fatal(err)
	}
	if err := rs.Enqueue(ctx, "sec-1", "manual", 0); err != nil {
		t.Fatal(err)
	}
	// Nothing claimed yet: heartbeat sees the due secret.
	pre, _ := hs.ClaimDue(ctx, 10, time.Minute)
	if len(pre) != 1 || pre[0] != "sec-1" {
		t.Fatalf("pre-rotation heartbeat claim: %v", pre)
	}
	_ = hs.Reschedule(ctx, "sec-1", time.Now().Add(-time.Second)) // due again, claim cleared

	// Claim the rotation → now in flight.
	if _, err := rs.ClaimDue(ctx, 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := hs.ClaimDue(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("heartbeat claimed a secret with an in-flight rotation: %v", got)
	}
}

func TestRotationStoreRemoveAndClearClaim(t *testing.T) {
	ctx := context.Background()
	r := newRotationStore(rotTestPool(t))
	if err := r.Enqueue(ctx, "sec-1", "manual", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ClaimDue(ctx, 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := r.ClearClaim(ctx, "sec-1", 2); err != nil {
		t.Fatalf("ClearClaim: %v", err)
	}
	var claimNull bool
	var state int
	if err := r.db.QueryRow(ctx, `SELECT claimed_until IS NULL, state FROM rotation_schedule WHERE secret_id='sec-1'`).Scan(&claimNull, &state); err != nil {
		t.Fatal(err)
	}
	if !claimNull || state != 2 {
		t.Fatalf("ClearClaim: claimNull=%v state=%d", claimNull, state)
	}
	if err := r.Remove(ctx, "sec-1"); err != nil {
		t.Fatal(err)
	}
	ok, _ := r.Exists(ctx, "sec-1")
	if ok {
		t.Fatal("row should be gone after Remove")
	}
}
