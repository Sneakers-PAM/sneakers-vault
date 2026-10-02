// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type fakePub struct {
	routingKey string
	body       []byte
}

func (f *fakePub) Publish(_ context.Context, rk string, body []byte) error {
	f.routingKey = rk
	f.body = body
	return nil
}

func TestEmitSetsRoutingKeyByTier(t *testing.T) {
	f := &fakePub{}
	em := New(f)
	if err := em.Emit(context.Background(), Event{Tier: TierAudit, Action: "secret.published"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if f.routingKey != "audit.audit" {
		t.Fatalf("got routing key %q", f.routingKey)
	}
	if len(f.body) == 0 {
		t.Fatal("empty body")
	}
}

// A caller that leaves OccurredAt zero must still produce a real event time —
// otherwise the consumer persists the Go zero value (0001-01-01), which renders
// as a nonsense "year 1" date and buries recent events. Emit stamps now().
func TestEmitStampsOccurredAtWhenZero(t *testing.T) {
	f := &fakePub{}
	em := New(f)
	before := time.Now().UTC().Add(-time.Second)
	if err := em.Emit(context.Background(), Event{Tier: TierAudit, Action: "group.defaults_set"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var got Event
	if err := json.Unmarshal(f.body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.OccurredAt.IsZero() {
		t.Fatal("OccurredAt was not stamped")
	}
	if got.OccurredAt.Before(before) {
		t.Fatalf("OccurredAt %v is not a recent time", got.OccurredAt)
	}
}

// A caller that sets OccurredAt (e.g. backfilling a historical event) keeps it.
func TestEmitPreservesCallerOccurredAt(t *testing.T) {
	f := &fakePub{}
	em := New(f)
	want := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	if err := em.Emit(context.Background(), Event{Tier: TierAudit, Action: "x", OccurredAt: want}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var got Event
	if err := json.Unmarshal(f.body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt: got %v want %v", got.OccurredAt, want)
	}
}
