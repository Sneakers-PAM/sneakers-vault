// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/Bugs5382/go-postgres"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
)

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// future reports whether an RFC3339 timestamp is still in the future.
func future(ts string) bool {
	t, err := time.Parse(time.RFC3339, ts)
	return err == nil && t.After(time.Now())
}

// Store persists the service-owned lease + approval-request rows. The go-saga
// engine persists its own run/step/signal state separately (store/postgres).
// A lease carries the checkout saga run that owns it (runID) so check-in can
// find and signal the run.
// ErrLeaseHeld is returned by InsertLease when the secret already has an
// active lease: a secret has at most one at a time.
var ErrLeaseHeld = errors.New("workflow: the secret already has an active lease")

// ErrRequestNotPending is returned by ResolveRequest when the request is
// already approved or denied.
var ErrRequestNotPending = errors.New("workflow: the approval request is not pending")

type Store interface {
	InsertLease(ctx context.Context, l *workflowv1.Lease, runID string) error
	CloseLeaseByRun(ctx context.Context, runID string) error
	LeaseByRun(ctx context.Context, runID string) (*workflowv1.Lease, error)
	ActiveLeasesForUser(ctx context.Context, userID string) ([]*workflowv1.Lease, error)
	ActiveLeaseForSecret(ctx context.Context, secretID string) (*workflowv1.Lease, error)
	// ActiveLeaseRunForSecretUser returns the run id of the active lease a user
	// holds on a secret (for check-in), or "" if none.
	ActiveLeaseRunForSecretUser(ctx context.Context, secretID, userID string) (string, error)
	// DueLeases returns leases that are not yet returned and whose expiry is
	// at or before asOf (an RFC3339 timestamp) — the reaper's sweep query.
	DueLeases(ctx context.Context, asOf string) ([]DueLease, error)

	InsertRequest(ctx context.Context, r *workflowv1.ApprovalRequest) error
	ListRequests(ctx context.Context) ([]*workflowv1.ApprovalRequest, error)
	// ResolveRequest approves or denies a pending request. It returns nil if
	// the request doesn't exist, and ErrRequestNotPending if it's already
	// resolved, leaving it unchanged.
	ResolveRequest(ctx context.Context, id, resolvedBy, resolvedAt string, approve bool) (*workflowv1.ApprovalRequest, error)
	// GetRequest returns a single approval request (with its comment thread
	// loaded), or nil if not found.
	GetRequest(ctx context.Context, id string) (*workflowv1.ApprovalRequest, error)
	// AddComment appends a comment to an access request's discussion thread.
	AddComment(ctx context.Context, requestID string, c *workflowv1.ApprovalComment) error
	// PurgeResolvedRequestsOlderThan deletes resolved (non-pending) access
	// requests whose resolved_at is strictly before cutoff (an RFC3339 UTC
	// timestamp), cascading their comment threads. Returns the number of
	// requests deleted — the retention purge job's sweep query.
	PurgeResolvedRequestsOlderThan(ctx context.Context, cutoff string) (int, error)

	CountLeases(ctx context.Context) (int, error)
}

// DueLease is the minimal projection the reaper needs off a lease row: its
// id (for logging) and the saga run that owns it (to signal check-in).
type DueLease struct {
	ID    string
	RunID string
}

// ---- in-memory store (tests) ------------------------------------------------

type memLease struct {
	l     *workflowv1.Lease
	runID string
}

type memStore struct {
	mu       sync.Mutex
	leases   []*memLease
	requests []*workflowv1.ApprovalRequest
	comments map[string][]*workflowv1.ApprovalComment // request id -> thread
}

func newMemStore() *memStore {
	return &memStore{comments: make(map[string][]*workflowv1.ApprovalComment)}
}

func (m *memStore) InsertLease(_ context.Context, l *workflowv1.Lease, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ml := range m.leases {
		if !l.GetReturned() && !ml.l.GetReturned() && ml.l.GetSecretId() == l.GetSecretId() {
			return ErrLeaseHeld
		}
	}
	m.leases = append(m.leases, &memLease{l: l, runID: runID})
	return nil
}
func (m *memStore) CloseLeaseByRun(_ context.Context, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ml := range m.leases {
		if ml.runID == runID {
			ml.l.Returned = true
		}
	}
	return nil
}
func (m *memStore) LeaseByRun(_ context.Context, runID string) (*workflowv1.Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ml := range m.leases {
		if ml.runID == runID {
			return ml.l, nil
		}
	}
	return nil, nil
}
func (m *memStore) ActiveLeasesForUser(_ context.Context, userID string) ([]*workflowv1.Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*workflowv1.Lease
	for _, ml := range m.leases {
		if ml.l.GetUserId() == userID && !ml.l.GetReturned() && future(ml.l.GetExpiresAt()) {
			out = append(out, ml.l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetIssuedAt() > out[j].GetIssuedAt() })
	return out, nil
}
func (m *memStore) ActiveLeaseForSecret(_ context.Context, secretID string) (*workflowv1.Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ml := range m.leases {
		if ml.l.GetSecretId() == secretID && !ml.l.GetReturned() && future(ml.l.GetExpiresAt()) {
			return ml.l, nil
		}
	}
	return nil, nil
}
func (m *memStore) ActiveLeaseRunForSecretUser(_ context.Context, secretID, userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ml := range m.leases {
		if ml.l.GetSecretId() == secretID && ml.l.GetUserId() == userID && !ml.l.GetReturned() && future(ml.l.GetExpiresAt()) {
			return ml.runID, nil
		}
	}
	return "", nil
}
func (m *memStore) DueLeases(_ context.Context, asOf string) ([]DueLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff, err := time.Parse(time.RFC3339, asOf)
	if err != nil {
		cutoff = time.Now().UTC()
	}
	var out []DueLease
	for _, ml := range m.leases {
		if ml.l.GetReturned() {
			continue
		}
		expires, err := time.Parse(time.RFC3339, ml.l.GetExpiresAt())
		if err != nil || !expires.After(cutoff) {
			out = append(out, DueLease{ID: ml.l.GetId(), RunID: ml.runID})
		}
	}
	return out, nil
}
func (m *memStore) InsertRequest(_ context.Context, r *workflowv1.ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, r)
	return nil
}
func (m *memStore) ListRequests(_ context.Context) ([]*workflowv1.ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*workflowv1.ApprovalRequest, 0, len(m.requests))
	for _, r := range m.requests {
		r.Comments = append([]*workflowv1.ApprovalComment(nil), m.comments[r.GetId()]...)
		out = append(out, r)
	}
	return out, nil
}
func (m *memStore) GetRequest(_ context.Context, id string) (*workflowv1.ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.requests {
		if r.GetId() == id {
			r.Comments = append([]*workflowv1.ApprovalComment(nil), m.comments[id]...)
			return r, nil
		}
	}
	return nil, nil
}
func (m *memStore) AddComment(_ context.Context, requestID string, c *workflowv1.ApprovalComment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.comments[requestID] = append(m.comments[requestID], c)
	return nil
}
func (m *memStore) ResolveRequest(_ context.Context, id, by, at string, approve bool) (*workflowv1.ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.requests {
		if r.GetId() == id {
			if r.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
				return nil, ErrRequestNotPending
			}
			if approve {
				r.Status = workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED
			} else {
				r.Status = workflowv1.ApprovalStatus_APPROVAL_STATUS_DENIED
			}
			r.ResolvedByUserId, r.ResolvedAt = by, at
			return r, nil
		}
	}
	return nil, nil
}
func (m *memStore) PurgeResolvedRequestsOlderThan(_ context.Context, cutoff string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.requests[:0:0]
	n := 0
	for _, r := range m.requests {
		resolved := r.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING
		if resolved && r.GetResolvedAt() != "" && r.GetResolvedAt() < cutoff {
			delete(m.comments, r.GetId())
			n++
			continue
		}
		kept = append(kept, r)
	}
	m.requests = kept
	return n, nil
}
func (m *memStore) CountLeases(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.leases), nil
}

// ---- Postgres store ---------------------------------------------------------

type pgStore struct{ db postgres.Querier }

// NewPGStore returns a Postgres-backed Store.
func NewPGStore(db postgres.Querier) Store { return &pgStore{db: db} }

const leaseCols = `id, secret_id, user_id, issued_at, expires_at, returned, run_id`

func scanLease(row interface{ Scan(...any) error }) (*workflowv1.Lease, error) {
	l := &workflowv1.Lease{}
	var runID string
	if err := row.Scan(&l.Id, &l.SecretId, &l.UserId, &l.IssuedAt, &l.ExpiresAt, &l.Returned, &runID); err != nil {
		return nil, err
	}
	return l, nil
}

func (p *pgStore) InsertLease(ctx context.Context, l *workflowv1.Lease, runID string) error {
	_, err := p.db.Exec(ctx,
		`INSERT INTO leases (`+leaseCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		l.GetId(), l.GetSecretId(), l.GetUserId(), l.GetIssuedAt(), l.GetExpiresAt(), l.GetReturned(), runID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "leases_one_active_per_secret" {
		return ErrLeaseHeld
	}
	return err
}
func (p *pgStore) CloseLeaseByRun(ctx context.Context, runID string) error {
	_, err := p.db.Exec(ctx, `UPDATE leases SET returned=true WHERE run_id=$1`, runID)
	return err
}
func (p *pgStore) LeaseByRun(ctx context.Context, runID string) (*workflowv1.Lease, error) {
	l, err := scanLease(p.db.QueryRow(ctx, `SELECT `+leaseCols+` FROM leases WHERE run_id=$1`, runID))
	if err != nil {
		return nil, nil
	}
	return l, nil
}
func (p *pgStore) ActiveLeasesForUser(ctx context.Context, userID string) ([]*workflowv1.Lease, error) {
	rows, err := p.db.Query(ctx, `SELECT `+leaseCols+` FROM leases
		WHERE user_id=$1 AND returned=false AND expires_at > $2 ORDER BY issued_at DESC`, userID, nowRFC3339())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*workflowv1.Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
func (p *pgStore) ActiveLeaseForSecret(ctx context.Context, secretID string) (*workflowv1.Lease, error) {
	l, err := scanLease(p.db.QueryRow(ctx, `SELECT `+leaseCols+` FROM leases
		WHERE secret_id=$1 AND returned=false AND expires_at > $2 ORDER BY issued_at DESC LIMIT 1`, secretID, nowRFC3339()))
	if err != nil {
		return nil, nil
	}
	return l, nil
}
func (p *pgStore) ActiveLeaseRunForSecretUser(ctx context.Context, secretID, userID string) (string, error) {
	var runID string
	err := p.db.QueryRow(ctx, `SELECT run_id FROM leases
		WHERE secret_id=$1 AND user_id=$2 AND returned=false AND expires_at > $3 ORDER BY issued_at DESC LIMIT 1`,
		secretID, userID, nowRFC3339()).Scan(&runID)
	if err != nil {
		return "", nil
	}
	return runID, nil
}

func (p *pgStore) DueLeases(ctx context.Context, asOf string) ([]DueLease, error) {
	rows, err := p.db.Query(ctx, `SELECT id, run_id FROM leases WHERE returned=false AND expires_at <= $1`, asOf)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DueLease
	for rows.Next() {
		var d DueLease
		if err := rows.Scan(&d.ID, &d.RunID); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

const reqCols = `id, secret_id, requested_by_user_id, status, requested_at, resolved_at, resolved_by_user_id, reason, kind, folder_id, dest_parent_id, folder_name, dest_parent_name`

func scanRequest(row interface{ Scan(...any) error }) (*workflowv1.ApprovalRequest, error) {
	r := &workflowv1.ApprovalRequest{}
	var status, kind int32
	if err := row.Scan(&r.Id, &r.SecretId, &r.RequestedByUserId, &status, &r.RequestedAt, &r.ResolvedAt, &r.ResolvedByUserId, &r.Reason,
		&kind, &r.FolderId, &r.DestParentId, &r.FolderName, &r.DestParentName); err != nil {
		return nil, err
	}
	r.Status = workflowv1.ApprovalStatus(status)
	r.Kind = workflowv1.RequestKind(kind)
	return r, nil
}

func (p *pgStore) InsertRequest(ctx context.Context, r *workflowv1.ApprovalRequest) error {
	_, err := p.db.Exec(ctx, `INSERT INTO approval_requests (`+reqCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.GetId(), r.GetSecretId(), r.GetRequestedByUserId(), int32(r.GetStatus()), r.GetRequestedAt(), r.GetResolvedAt(), r.GetResolvedByUserId(), r.GetReason(),
		int32(r.GetKind()), r.GetFolderId(), r.GetDestParentId(), r.GetFolderName(), r.GetDestParentName())
	return err
}
func (p *pgStore) ListRequests(ctx context.Context) ([]*workflowv1.ApprovalRequest, error) {
	rows, err := p.db.Query(ctx, `SELECT `+reqCols+` FROM approval_requests ORDER BY requested_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*workflowv1.ApprovalRequest
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		if r.Comments, err = p.commentsFor(ctx, r.GetId()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

const commentCols = `id, author_user_id, body, created_at`

// commentsFor loads an access request's discussion thread, oldest first.
func (p *pgStore) commentsFor(ctx context.Context, requestID string) ([]*workflowv1.ApprovalComment, error) {
	rows, err := p.db.Query(ctx, `SELECT `+commentCols+` FROM approval_comments WHERE request_id=$1 ORDER BY created_at, id`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*workflowv1.ApprovalComment
	for rows.Next() {
		c := &workflowv1.ApprovalComment{}
		if err := rows.Scan(&c.Id, &c.AuthorUserId, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *pgStore) GetRequest(ctx context.Context, id string) (*workflowv1.ApprovalRequest, error) {
	r, err := scanRequest(p.db.QueryRow(ctx, `SELECT `+reqCols+` FROM approval_requests WHERE id=$1`, id))
	if err != nil {
		return nil, nil
	}
	if r.Comments, err = p.commentsFor(ctx, id); err != nil {
		return nil, err
	}
	return r, nil
}

func (p *pgStore) AddComment(ctx context.Context, requestID string, c *workflowv1.ApprovalComment) error {
	_, err := p.db.Exec(ctx,
		`INSERT INTO approval_comments (id, request_id, author_user_id, body, created_at) VALUES ($1,$2,$3,$4,$5)`,
		c.GetId(), requestID, c.GetAuthorUserId(), c.GetBody(), c.GetCreatedAt())
	return err
}
func (p *pgStore) ResolveRequest(ctx context.Context, id, by, at string, approve bool) (*workflowv1.ApprovalRequest, error) {
	status := workflowv1.ApprovalStatus_APPROVAL_STATUS_DENIED
	if approve {
		status = workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED
	}
	tag, err := p.db.Exec(ctx, `UPDATE approval_requests SET status=$2, resolved_by_user_id=$3, resolved_at=$4 WHERE id=$1 AND status=$5`,
		id, int32(status), by, at, int32(workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING))
	if err != nil {
		return nil, err
	}
	r, err := scanRequest(p.db.QueryRow(ctx, `SELECT `+reqCols+` FROM approval_requests WHERE id=$1`, id))
	if err != nil {
		return nil, nil
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrRequestNotPending
	}
	return r, nil
}
func (p *pgStore) PurgeResolvedRequestsOlderThan(ctx context.Context, cutoff string) (int, error) {
	// status <> pending (1) AND a real resolved_at strictly before the cutoff.
	// approval_comments FK is ON DELETE CASCADE, so threads go with the row.
	tag, err := p.db.Exec(ctx,
		`DELETE FROM approval_requests WHERE status <> $1 AND resolved_at <> '' AND resolved_at < $2`,
		int32(workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING), cutoff)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
func (p *pgStore) CountLeases(ctx context.Context) (int, error) {
	var n int
	err := p.db.QueryRow(ctx, `SELECT count(*) FROM leases`).Scan(&n)
	return n, err
}
