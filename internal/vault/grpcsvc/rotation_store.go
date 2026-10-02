// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// rotationStore is the leaderless rotation work queue over rotation_schedule
// (one row per rotation-capable secret). It mirrors heartbeatStore: due rows are
// claimed with SELECT ... FOR UPDATE SKIP LOCKED so competing connector replicas
// never process the same secret. `state` mirrors the RotationState enum as an int.
type rotationStore struct{ db postgres.Querier }

func newRotationStore(db postgres.Querier) *rotationStore { return &rotationStore{db: db} }

// Enqueue makes a secret due for rotation now (all trigger paths). Upsert: an
// existing row is pulled forward to now() with the new reason. claimed_until is
// left untouched so an in-flight rotation still blocks re-claim until it lapses.
func (r *rotationStore) Enqueue(ctx context.Context, secretID, reason string, intervalDays int) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO rotation_schedule (secret_id, next_rotation_at, interval_days, reason, state)
		 VALUES ($1, now(), $2, $3, 0)
		 ON CONFLICT (secret_id) DO UPDATE SET
		   next_rotation_at = now(),
		   interval_days    = EXCLUDED.interval_days,
		   reason           = EXCLUDED.reason,
		   state            = 0`,
		secretID, intervalDays, reason)
	return err
}

// EnsureScheduled makes sure a rotation-capable secret has a schedule row. When
// intervalDays>0 the next rotation is set that far out; interval 0 means the row
// exists but is not auto-due (on-demand only). Upsert keeps any existing due time
// and only refreshes interval_days.
func (r *rotationStore) EnsureScheduled(ctx context.Context, secretID string, intervalDays int) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO rotation_schedule (secret_id, interval_days, next_rotation_at, state)
		 VALUES ($1, $2, CASE WHEN $2 > 0 THEN now() + make_interval(days => $2) ELSE NULL END, 0)
		 ON CONFLICT (secret_id) DO UPDATE SET interval_days = EXCLUDED.interval_days`,
		secretID, intervalDays)
	return err
}

// ClaimDue atomically claims up to limit due rows, stamping claimed_until =
// now()+ttl and state = ROTATING, and pushing next_rotation_at forward by the TTL
// so a claimed-but-unreported row isn't re-claimed by a racing poll window
// (Reschedule later overwrites it with the real next-due time). Mirrors
// heartbeatStore.ClaimDue. Only rows with a non-null, due next_rotation_at are
// eligible (interval-0 rows stay dormant until Enqueue makes them due).
func (r *rotationStore) ClaimDue(ctx context.Context, limit int, ttl time.Duration) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`UPDATE rotation_schedule SET
		   claimed_until = now() + $2::interval,
		   next_rotation_at = GREATEST(next_rotation_at, now()) + $2::interval,
		   state = 4
		 WHERE secret_id IN (
		   SELECT secret_id FROM rotation_schedule
		   WHERE next_rotation_at IS NOT NULL AND next_rotation_at <= now()
		     AND (claimed_until IS NULL OR claimed_until <= now())
		   ORDER BY next_rotation_at
		   FOR UPDATE SKIP LOCKED
		   LIMIT $1
		 )
		 RETURNING secret_id`,
		limit, ttl.String())
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

// Reschedule sets the next due time and result state, clearing the claim. A zero
// `next` stores NULL (dormant: on-demand only until the next Enqueue).
func (r *rotationStore) Reschedule(ctx context.Context, secretID string, next time.Time, state int) error {
	var nextArg any
	if !next.IsZero() {
		nextArg = next
	}
	_, err := r.db.Exec(ctx,
		`UPDATE rotation_schedule SET next_rotation_at = $2, claimed_until = NULL, state = $3 WHERE secret_id = $1`,
		secretID, nextArg, state)
	return err
}

// ClearClaim releases the claim and sets the state without changing the due time
// (used when a report leaves the schedule otherwise unchanged).
func (r *rotationStore) ClearClaim(ctx context.Context, secretID string, state int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE rotation_schedule SET claimed_until = NULL, state = $2 WHERE secret_id = $1`,
		secretID, state)
	return err
}

func (r *rotationStore) Remove(ctx context.Context, secretID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM rotation_schedule WHERE secret_id = $1`, secretID)
	return err
}

// Exists reports whether secretID has a rotation_schedule row — i.e. is a
// legitimate, currently-scheduled rotation target. Used to scope the connector
// pull-API (RevealForRotation/ReportRotation).
func (r *rotationStore) Exists(ctx context.Context, secretID string) (bool, error) {
	var one int
	err := r.db.QueryRow(ctx, `SELECT 1 FROM rotation_schedule WHERE secret_id = $1`, secretID).Scan(&one)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// InFlightOnConnection reports whether any of the given secrets currently has an
// in-flight rotation claim (claimed_until > now()). It's the rotate-the-rotator
// guard: a connection's privileged secret must not be claimed while any secret
// on the same connection is mid-rotation (and vice-versa).
func (r *rotationStore) InFlightOnConnection(ctx context.Context, connSecretIDs []string) (bool, error) {
	if len(connSecretIDs) == 0 {
		return false, nil
	}
	var inflight bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM rotation_schedule
		   WHERE secret_id = ANY($1) AND claimed_until IS NOT NULL AND claimed_until > now()
		 )`, connSecretIDs).Scan(&inflight)
	return inflight, err
}

// Claimed reports whether secretID currently holds a live rotation claim
// (claimed_until IS NOT NULL AND claimed_until > now()). RevealForRotation
// gates on this: a secret's replacement credential must only be generated and
// staged while its rotation job is actually claimed by a worker, never for a
// merely-due-but-unclaimed schedule row.
func (r *rotationStore) Claimed(ctx context.Context, secretID string) (bool, error) {
	var claimed bool
	err := r.db.QueryRow(ctx,
		`SELECT claimed_until IS NOT NULL AND claimed_until > now() FROM rotation_schedule WHERE secret_id = $1`,
		secretID).Scan(&claimed)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return claimed, nil
}

// BumpFailure increments and returns the consecutive-failure counter (gates
// backoff/alerting). Best-effort at the call site: a nil store yields 0.
func (r *rotationStore) BumpFailure(ctx context.Context, secretID string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`UPDATE rotation_schedule SET consecutive_failures = consecutive_failures + 1
		 WHERE secret_id = $1 RETURNING consecutive_failures`, secretID).Scan(&n)
	return n, err
}

// ClearFailure resets the consecutive-failure counter after a success.
func (r *rotationStore) ClearFailure(ctx context.Context, secretID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE rotation_schedule SET consecutive_failures = 0 WHERE secret_id = $1`, secretID)
	return err
}
