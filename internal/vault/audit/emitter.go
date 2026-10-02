// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Tier string

const (
	TierAudit    Tier = "audit"
	TierActivity Tier = "activity"
)

type Event struct {
	Tier        Tier              `json:"tier"`
	Action      string            `json:"action"`
	ActorUserID string            `json:"actor_user_id,omitempty"`
	Subject     string            `json:"subject,omitempty"`
	GroupID     string            `json:"group_id,omitempty"`
	Sensitive   bool              `json:"sensitive,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	// OccurredAt is the event time. Callers normally leave it zero and Emit
	// stamps now(); set it explicitly only to backfill a historical event.
	OccurredAt time.Time `json:"occurred_at"`
}

type Publisher interface {
	Publish(ctx context.Context, routingKey string, body []byte) error
}

type Emitter struct{ pub Publisher }

func New(p Publisher) *Emitter { return &Emitter{pub: p} }

func (e *Emitter) Emit(ctx context.Context, ev Event) error {
	// Stamp the event time at emit (≈ when the action happened). Without this
	// the consumer persists the Go zero value, which surfaces as a year-1 date.
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return e.pub.Publish(ctx, fmt.Sprintf("audit.%s", ev.Tier), body)
}
