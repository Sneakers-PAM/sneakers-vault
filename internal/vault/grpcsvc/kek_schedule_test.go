// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
)

// recordingStore wraps memStore's no-op Load and counts Persist calls, so
// scheduler tests can assert kekSchedulerTick persisted the rewrapped records
// itself (it runs outside PersistUnary, unlike the RotateKek RPC).
type recordingStore struct {
	memStore
	mu    sync.Mutex
	calls int
}

func (r *recordingStore) Persist(ctx context.Context, st *state) error {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return r.memStore.Persist(ctx, st)
}

func (r *recordingStore) persistCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestKekRotationDue(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name         string
		age          time.Duration
		rotationDays int32
		want         bool
	}{
		{"off-any-age", 365 * 24 * time.Hour, 0, false},
		{"off-zero-age", 0, 0, false},
		{"31d-due-at-30d-policy", 31 * 24 * time.Hour, 30, true},
		{"29d-not-due-at-30d-policy", 29 * 24 * time.Hour, 30, false},
		{"exactly-30d-is-due", 30 * 24 * time.Hour, 30, true},
		{"negative-days-off", 365 * 24 * time.Hour, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created := now.Add(-tc.age)
			if got := kekRotationDue(created, tc.rotationDays, now); got != tc.want {
				t.Fatalf("kekRotationDue(age=%v, rotationDays=%d) = %v, want %v", tc.age, tc.rotationDays, got, tc.want)
			}
		})
	}
}

// TestKekSchedulerTick_RotatesWhenDue verifies that a single kekSchedulerTick
// evaluation, with kek_rotation_days=30 and an active generation aged 40
// days, rotates exactly once (the active ref advances) and persists the
// outcome itself (the scheduler runs outside PersistUnary).
func TestKekSchedulerTick_RotatesWhenDue(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	rs := &recordingStore{}
	s.store = rs

	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()

	// Back-date kek-v1's created_at on the fake keyring store to 40 days ago —
	// past the 30-day policy.
	fx.ks.mu.Lock()
	for i := range fx.ks.rows {
		if fx.ks.rows[i].Ref == "kek-v1" {
			fx.ks.rows[i].CreatedAt = time.Now().Add(-40 * 24 * time.Hour)
		}
	}
	fx.ks.mu.Unlock()

	if err := s.kekSchedulerTick(ctx); err != nil {
		t.Fatalf("kekSchedulerTick: %v", err)
	}

	if got := s.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef after due tick = %q, want kek-v2", got)
	}
	if got := rs.persistCalls(); got != 1 {
		t.Fatalf("Persist calls after due tick = %d, want 1", got)
	}

	// A second tick: kek-v2 is fresh (just rotated), so nothing further happens.
	if err := s.kekSchedulerTick(ctx); err != nil {
		t.Fatalf("kekSchedulerTick (second): %v", err)
	}
	if got := s.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef after second tick = %q, want unchanged kek-v2", got)
	}
	if got := rs.persistCalls(); got != 1 {
		t.Fatalf("Persist calls after second (not-due) tick = %d, want still 1", got)
	}
}

// TestKekSchedulerTick_AutoRotationOff verifies several evaluations with
// kek_rotation_days=0 trigger no rotation and no persist, even though the
// active generation is very old.
func TestKekSchedulerTick_AutoRotationOff(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	rs := &recordingStore{}
	s.store = rs

	s.mu.Lock()
	s.settings.KekRotationDays = 0
	s.mu.Unlock()

	fx.ks.mu.Lock()
	for i := range fx.ks.rows {
		if fx.ks.rows[i].Ref == "kek-v1" {
			fx.ks.rows[i].CreatedAt = time.Now().Add(-365 * 24 * time.Hour)
		}
	}
	fx.ks.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := s.kekSchedulerTick(ctx); err != nil {
			t.Fatalf("kekSchedulerTick[%d]: %v", i, err)
		}
	}

	if got := s.keyring.ActiveRef(); got != "kek-v1" {
		t.Fatalf("ActiveRef with auto-rotation off = %q, want unchanged kek-v1", got)
	}
	if got := rs.persistCalls(); got != 0 {
		t.Fatalf("Persist calls with auto-rotation off = %d, want 0", got)
	}
}

// TestKekSchedulerTick_PublishesInvalidateOnRotation checks the scheduler
// side: the scheduler runs outside the gRPC interceptor chain entirely, so a scheduled
// rotation would never tell peers to reload+reconcile — they'd only pick up
// the new KEK generation on their own next restart. This proves
// kekSchedulerTick now publishes an invalidation itself once a due rotation
// is persisted, mirroring the RPC path (see TestPublishTriggersReloadViaRedis
// for the equivalent RPC-path proof).
func TestKekSchedulerTick_PublishesInvalidateOnRotation(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	rc, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()

	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	s.store = &recordingStore{}
	s.SetInvalidation(rc, DefaultInvalidateChannel)

	sub := rc.Redis().Subscribe(ctx, DefaultInvalidateChannel)
	defer func() { _ = sub.Close() }()
	if _, err := sub.Receive(ctx); err != nil { // wait for subscription confirmation
		t.Fatalf("subscribe: %v", err)
	}

	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()
	fx.ks.mu.Lock()
	for i := range fx.ks.rows {
		if fx.ks.rows[i].Ref == "kek-v1" {
			fx.ks.rows[i].CreatedAt = time.Now().Add(-40 * 24 * time.Hour)
		}
	}
	fx.ks.mu.Unlock()

	if err := s.kekSchedulerTick(ctx); err != nil {
		t.Fatalf("kekSchedulerTick: %v", err)
	}

	select {
	case msg := <-sub.Channel():
		if msg.Channel != DefaultInvalidateChannel {
			t.Fatalf("published channel = %q, want %q", msg.Channel, DefaultInvalidateChannel)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kekSchedulerTick did not publish an invalidation after a due rotation")
	}
}

// TestKekSchedulerTick_NotDue_NoPublish verifies an evaluation that finds no
// rotation due does not publish anything (only a completed, persisted
// rotation should tell peers to reload).
func TestKekSchedulerTick_NotDue_NoPublish(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	rc, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()

	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	s.store = &recordingStore{}
	s.SetInvalidation(rc, DefaultInvalidateChannel)

	sub := rc.Redis().Subscribe(ctx, DefaultInvalidateChannel)
	defer func() { _ = sub.Close() }()
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()
	fx.ks.mu.Lock()
	for i := range fx.ks.rows {
		if fx.ks.rows[i].Ref == "kek-v1" {
			fx.ks.rows[i].CreatedAt = time.Now() // fresh → not due
		}
	}
	fx.ks.mu.Unlock()

	if err := s.kekSchedulerTick(ctx); err != nil {
		t.Fatalf("kekSchedulerTick: %v", err)
	}

	select {
	case msg := <-sub.Channel():
		t.Fatalf("unexpected publish on channel %q for a not-due tick", msg.Channel)
	case <-time.After(200 * time.Millisecond):
		// expected: no publish
	}
}

// TestRunKekScheduler_CancelStopsLoop verifies the ticker loop returns
// promptly once ctx is cancelled, honoring ctx.Done() (no real rotation
// interval elapses — kek_rotation_days stays at its seeded default, so any
// ticks that do fire are no-ops).
func TestRunKekScheduler_CancelStopsLoop(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	s.store = &recordingStore{}

	s.mu.Lock()
	s.settings.KekRotationDays = 0
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunKekScheduler(ctx, time.Millisecond)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let a few ticks fire (all no-ops, rotation off)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunKekScheduler did not return after ctx cancel")
	}
}
