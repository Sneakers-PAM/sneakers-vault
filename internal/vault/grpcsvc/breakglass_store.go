// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// breakGlassStore is the append-only ledger of emergency (break-glass) reveals.
// One row per BreakGlassSecret call: who broke glass on which secret, why, in
// which browse session (if any), and whether the forced post-use rotation was
// scheduled / the owner notified. It
// never stores field values — the reveal is recorded as a high-severity audit
// event; this table is the operational record of the break-glass action itself.
// The same store keeps the break-glass browse sessions (break_glass_sessions).
type breakGlassStore struct{ db postgres.Querier }

func newBreakGlassStore(db postgres.Querier) *breakGlassStore { return &breakGlassStore{db: db} }

// Insert appends one break-glass event. Caller supplies the id (generated under
// the server lock) so the row is deterministic and never collides.
// sessionID is "" for a reveal outside a browse session.
func (b *breakGlassStore) Insert(ctx context.Context, id, secretID, actorUserID, reason, sessionID string, postRotationScheduled, notified bool) error {
	_, err := b.db.Exec(ctx,
		`INSERT INTO break_glass_events
		   (id, secret_id, actor_user_id, reason, session_id, post_rotation_scheduled, notified)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, secretID, actorUserID, reason, sessionID, postRotationScheduled, notified)
	return err
}

// btgSession is one break-glass browse session row.
type btgSession struct {
	ID         string
	Actor      string
	SessionRef string
	Reason     string
	OpenedAt   time.Time
	ExpiresAt  time.Time
	EndedAt    time.Time // zero while open
	EndReason  string
}

func (b btgSession) open() bool { return b.EndedAt.IsZero() }

// btgRevealRow is one ledger row made inside a session.
type btgRevealRow struct {
	EventID               string
	SessionID             string
	SecretID              string
	OccurredAt            time.Time
	PostRotationScheduled bool
	Notified              bool
}

const btgSessionCols = `id, actor_user_id, session_ref, reason, opened_at, expires_at, ended_at, end_reason`

func scanBTGSession(row interface{ Scan(...any) error }) (btgSession, error) {
	var (
		s     btgSession
		ended *time.Time
	)
	if err := row.Scan(&s.ID, &s.Actor, &s.SessionRef, &s.Reason, &s.OpenedAt, &s.ExpiresAt, &ended, &s.EndReason); err != nil {
		return btgSession{}, err
	}
	if ended != nil {
		s.EndedAt = *ended
	}
	return s, nil
}

// OpenSession records a new open session.
func (b *breakGlassStore) OpenSession(ctx context.Context, s btgSession) error {
	_, err := b.db.Exec(ctx,
		`INSERT INTO break_glass_sessions (id, actor_user_id, session_ref, reason, opened_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		s.ID, s.Actor, s.SessionRef, s.Reason, s.OpenedAt, s.ExpiresAt)
	return err
}

// DeleteSession removes a session whose entered event could not be recorded.
func (b *breakGlassStore) DeleteSession(ctx context.Context, id string) error {
	_, err := b.db.Exec(ctx, `DELETE FROM break_glass_sessions WHERE id = $1`, id)
	return err
}

// GetSession returns the session with id; ok is false when there is none.
func (b *breakGlassStore) GetSession(ctx context.Context, id string) (btgSession, bool, error) {
	s, err := scanBTGSession(b.db.QueryRow(ctx, `SELECT `+btgSessionCols+` FROM break_glass_sessions WHERE id = $1`, id))
	if errors.Is(err, postgres.ErrNoRows) {
		return btgSession{}, false, nil
	}
	return s, err == nil, err
}

// OpenSessionsFor lists actor's sessions that have not ended, newest first.
func (b *breakGlassStore) OpenSessionsFor(ctx context.Context, actor string) ([]btgSession, error) {
	return b.querySessions(ctx,
		`SELECT `+btgSessionCols+` FROM break_glass_sessions
		 WHERE actor_user_id = $1 AND ended_at IS NULL ORDER BY opened_at DESC, id DESC`, actor)
}

// ExpiredSessions lists the sessions that have not ended but expired by now.
func (b *breakGlassStore) ExpiredSessions(ctx context.Context, now time.Time) ([]btgSession, error) {
	return b.querySessions(ctx,
		`SELECT `+btgSessionCols+` FROM break_glass_sessions
		 WHERE ended_at IS NULL AND expires_at <= $1 ORDER BY expires_at`, now)
}

// ListSessions lists the newest limit sessions.
func (b *breakGlassStore) ListSessions(ctx context.Context, limit int) ([]btgSession, error) {
	return b.querySessions(ctx,
		`SELECT `+btgSessionCols+` FROM break_glass_sessions ORDER BY opened_at DESC, id DESC LIMIT $1`, limit)
}

func (b *breakGlassStore) querySessions(ctx context.Context, q string, args ...any) ([]btgSession, error) {
	rows, err := b.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []btgSession
	for rows.Next() {
		s, err := scanBTGSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// EndSession ends an open session. It reports whether this call ended it, so
// across replicas exactly one caller records the session's left event.
func (b *breakGlassStore) EndSession(ctx context.Context, id, reason string, at time.Time) (bool, error) {
	tag, err := b.db.Exec(ctx,
		`UPDATE break_glass_sessions SET ended_at = $2, end_reason = $3 WHERE id = $1 AND ended_at IS NULL`,
		id, at, reason)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RevealsIn returns the ledger rows of the given sessions, oldest first.
func (b *breakGlassStore) RevealsIn(ctx context.Context, sessionIDs []string) ([]btgRevealRow, error) {
	if len(sessionIDs) == 0 {
		return nil, nil
	}
	rows, err := b.db.Query(ctx,
		`SELECT id, session_id, secret_id, occurred_at, post_rotation_scheduled, notified
		 FROM break_glass_events WHERE session_id = ANY($1) ORDER BY occurred_at, id`, sessionIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []btgRevealRow
	for rows.Next() {
		var r btgRevealRow
		if err := rows.Scan(&r.EventID, &r.SessionID, &r.SecretID, &r.OccurredAt, &r.PostRotationScheduled, &r.Notified); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
