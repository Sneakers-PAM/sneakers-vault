// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// heartbeatStore is the leaderless heartbeat work queue over its own
// row-queryable table (NOT the JSONB snapshot store). Claims use SKIP LOCKED.
type heartbeatStore struct{ db postgres.Querier }

func newHeartbeatStore(db postgres.Querier) *heartbeatStore { return &heartbeatStore{db: db} }

// Ensure upserts a schedule row for a heartbeat-capable secret (due now).
func (h *heartbeatStore) Ensure(ctx context.Context, secretID string, intervalSeconds int) error {
	if intervalSeconds <= 0 {
		intervalSeconds = 300
	}
	_, err := h.db.Exec(ctx,
		`INSERT INTO heartbeat_schedule (secret_id, interval_seconds)
		 VALUES ($1,$2) ON CONFLICT (secret_id) DO UPDATE SET interval_seconds = EXCLUDED.interval_seconds`,
		secretID, intervalSeconds)
	return err
}

// ClaimDue atomically claims up to limit due rows (competing-consumer safe via
// FOR UPDATE SKIP LOCKED) and stamps claimed_until = now()+ttl so a crashed
// worker's rows become reclaimable. It also pushes next_heartbeat_at forward
// by the same TTL, so a claimed-but-not-yet-reported row isn't also picked up
// as "due" a second time (e.g. by another replica racing the same poll
// window) while the worker is still processing it — ReportHeartbeat's
// Reschedule then overwrites this with the real next-due time.
func (h *heartbeatStore) ClaimDue(ctx context.Context, limit int, claimTTL time.Duration) ([]string, error) {
	rows, err := h.db.Query(ctx,
		`UPDATE heartbeat_schedule SET
		   claimed_until = now() + $2::interval,
		   next_heartbeat_at = GREATEST(next_heartbeat_at, now()) + $2::interval
		 WHERE secret_id IN (
		   SELECT secret_id FROM heartbeat_schedule
		   WHERE next_heartbeat_at <= now()
		     AND (claimed_until IS NULL OR claimed_until <= now())
		     -- Rotation wins: skip a secret while its rotation is in flight so
		     -- heartbeat doesn't bind with a credential that's mid-swap.
		     AND secret_id NOT IN (
		       SELECT secret_id FROM rotation_schedule
		       WHERE claimed_until IS NOT NULL AND claimed_until > now()
		     )
		   ORDER BY next_heartbeat_at
		   FOR UPDATE SKIP LOCKED
		   LIMIT $1
		 )
		 RETURNING secret_id`,
		limit, claimTTL.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Reschedule sets the next due time and clears the claim.
func (h *heartbeatStore) Reschedule(ctx context.Context, secretID string, next time.Time) error {
	_, err := h.db.Exec(ctx,
		`UPDATE heartbeat_schedule SET next_heartbeat_at = $2, claimed_until = NULL WHERE secret_id = $1`,
		secretID, next)
	return err
}

func (h *heartbeatStore) Remove(ctx context.Context, secretID string) error {
	_, err := h.db.Exec(ctx, `DELETE FROM heartbeat_schedule WHERE secret_id = $1`, secretID)
	return err
}

// Exists reports whether secretID currently has a heartbeat_schedule row —
// i.e. is actually scheduled for heartbeat validation, not merely of a
// heartbeat-capable secret type. Used to scope the connector pull-API
// (RevealForHeartbeat/ReportHeartbeat) to legitimate targets.
func (h *heartbeatStore) Exists(ctx context.Context, secretID string) (bool, error) {
	var one int
	err := h.db.QueryRow(ctx, `SELECT 1 FROM heartbeat_schedule WHERE secret_id = $1`, secretID).Scan(&one)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RequestNow makes a scheduled heartbeat due now unless the last request came
// within minGap. requested is false when the row exists but is rate-limited;
// exists is false when the secret has no schedule row at all.
func (h *heartbeatStore) RequestNow(ctx context.Context, secretID string, minGap time.Duration) (requested, exists bool, err error) {
	var one int
	err = h.db.QueryRow(ctx,
		`UPDATE heartbeat_schedule SET next_heartbeat_at = now(), last_manual_at = now()
		 WHERE secret_id = $1 AND (last_manual_at IS NULL OR last_manual_at <= now() - $2::interval)
		 RETURNING 1`, secretID, minGap.String()).Scan(&one)
	if err == nil {
		return true, true, nil
	}
	if !errors.Is(err, postgres.ErrNoRows) {
		return false, false, err
	}
	exists, err = h.Exists(ctx, secretID)
	return false, exists, err
}

// Pending reports whether a check is due or claimed but not yet reported.
func (h *heartbeatStore) Pending(ctx context.Context, secretID string) (bool, error) {
	var pending bool
	err := h.db.QueryRow(ctx,
		`SELECT next_heartbeat_at <= now() OR (claimed_until IS NOT NULL AND claimed_until > now())
		 FROM heartbeat_schedule WHERE secret_id = $1`, secretID).Scan(&pending)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	return pending, err
}

// Pause stops automatic claims of a secret's heartbeat by moving its due time
// to infinity, and clears the claim. Resume or RequestNow make it due again.
func (h *heartbeatStore) Pause(ctx context.Context, secretID string) error {
	_, err := h.db.Exec(ctx,
		`UPDATE heartbeat_schedule SET next_heartbeat_at = 'infinity', claimed_until = NULL WHERE secret_id = $1`,
		secretID)
	return err
}

// Resume makes a paused heartbeat due now. resumed is false when the row was
// not paused (or does not exist), which leaves it untouched.
func (h *heartbeatStore) Resume(ctx context.Context, secretID string) (resumed bool, err error) {
	var one int
	err = h.db.QueryRow(ctx,
		`UPDATE heartbeat_schedule SET next_heartbeat_at = now()
		 WHERE secret_id = $1 AND next_heartbeat_at = 'infinity' RETURNING 1`, secretID).Scan(&one)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Paused reports whether a secret's heartbeat is paused.
func (h *heartbeatStore) Paused(ctx context.Context, secretID string) (bool, error) {
	var paused bool
	err := h.db.QueryRow(ctx,
		`SELECT next_heartbeat_at = 'infinity' FROM heartbeat_schedule WHERE secret_id = $1`, secretID).Scan(&paused)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	return paused, err
}
