// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// heartbeatSummary is one secret's pending daily rollup of routine (unchanged
// -result) heartbeat checks: how many ran, the window they span, and the
// result/detail/actor they all shared. It is flushed into a single audit
// record at the first state change or when the day closes, whichever comes
// first (see foldHeartbeatResult in heartbeat.go), instead of auditing every
// routine check.
type heartbeatSummary struct {
	Day       time.Time
	StartedAt time.Time
	LastAt    time.Time
	Checks    int
	Result    string
	Detail    string
	Actor     string
}

// heartbeatSummaryStore is the pending-rollup accumulator over its own table
// (one row per secret with a rollup in progress — a secret with none has no
// row). Mirrors heartbeatStore's shape: a thin wrapper over postgres.Querier.
type heartbeatSummaryStore struct{ db postgres.Querier }

func newHeartbeatSummaryStore(db postgres.Querier) *heartbeatSummaryStore {
	return &heartbeatSummaryStore{db: db}
}

// Get returns the secret's pending rollup, if any.
func (h *heartbeatSummaryStore) Get(ctx context.Context, secretID string) (heartbeatSummary, bool, error) {
	var s heartbeatSummary
	var detail, actor *string
	err := h.db.QueryRow(ctx,
		`SELECT day, started_at, last_at, checks, result, detail, actor
		 FROM heartbeat_audit_summary WHERE secret_id = $1`, secretID,
	).Scan(&s.Day, &s.StartedAt, &s.LastAt, &s.Checks, &s.Result, &detail, &actor)
	if errors.Is(err, postgres.ErrNoRows) {
		return heartbeatSummary{}, false, nil
	}
	if err != nil {
		return heartbeatSummary{}, false, err
	}
	if detail != nil {
		s.Detail = *detail
	}
	if actor != nil {
		s.Actor = *actor
	}
	return s, true, nil
}

// Start replaces any pending rollup for secretID with a fresh one of a single
// check (used both to open a brand-new rollup and to start the next one right
// after a flush).
func (h *heartbeatSummaryStore) Start(ctx context.Context, secretID string, day time.Time, at time.Time, result, detail, actor string) error {
	_, err := h.db.Exec(ctx,
		`INSERT INTO heartbeat_audit_summary (secret_id, day, started_at, last_at, checks, result, detail, actor)
		 VALUES ($1,$2,$3,$3,1,$4,$5,$6)
		 ON CONFLICT (secret_id) DO UPDATE SET
		   day = EXCLUDED.day, started_at = EXCLUDED.started_at, last_at = EXCLUDED.last_at,
		   checks = 1, result = EXCLUDED.result, detail = EXCLUDED.detail, actor = EXCLUDED.actor`,
		secretID, day, at, result, nullableString(detail), nullableString(actor))
	return err
}

// Bump folds one more routine check into the secret's existing rollup.
func (h *heartbeatSummaryStore) Bump(ctx context.Context, secretID string, at time.Time, detail string) error {
	_, err := h.db.Exec(ctx,
		`UPDATE heartbeat_audit_summary SET last_at = $2, checks = checks + 1, detail = $3
		 WHERE secret_id = $1`, secretID, at, nullableString(detail))
	return err
}

// Clear removes the secret's pending rollup once it has been flushed.
func (h *heartbeatSummaryStore) Clear(ctx context.Context, secretID string) error {
	_, err := h.db.Exec(ctx, `DELETE FROM heartbeat_audit_summary WHERE secret_id = $1`, secretID)
	return err
}

// nullableString returns nil for an empty string, so an absent detail/actor
// is stored as SQL NULL rather than "".
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
