// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcsvc implements sneakers.workflow.v1.WorkflowService. Checkout
// runs as a go-saga run (issue lease -> wait for check-in -> rotate-on-checkin
// -> close lease, with a compensation that releases the lease if the run
// fails). Leases + access-request approvals persist to Postgres; the engine
// persists its own run/step/signal state (store/postgres). Approvals are plain
// persisted records, not a saga — checkout is the saga.
package grpcsvc

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	sagasdk "github.com/Bugs5382/go-saga-orchestration/saga"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type Server struct {
	workflowv1.UnimplementedWorkflowServiceServer
	store Store
	saga  *sagasdk.Saga
	// vault is the outbound client used to add/remove the temporary secret-level
	// read grant that backs a lease (see raci.go). ResolveApproval grants on
	// approve; the saga's close_lease step revokes when the lease ends.
	vault vaultv1.VaultServiceClient
	// log is the service logger; nil discards (tests that build a bare Server).
	log log.Logger
}

func New(store Store, saga *sagasdk.Saga, vault vaultv1.VaultServiceClient) *Server {
	return &Server{store: store, saga: saga, vault: vault}
}

// SetLogger sets the logger the workflow service writes through.
func (s *Server) SetLogger(l log.Logger) { s.log = l }

// lg returns the service logger correlated with the span in ctx.
func (s *Server) lg(ctx context.Context) log.Logger {
	if s.log == nil {
		return log.Nop()
	}
	return s.log.Ctx(ctx)
}

func Register(gs *grpc.Server, s *Server) { workflowv1.RegisterWorkflowServiceServer(gs, s) }

func (s *Server) ListActiveLeasesForUser(ctx context.Context, req *workflowv1.ListActiveLeasesForUserRequest) (*workflowv1.ListActiveLeasesForUserResponse, error) {
	leases, err := s.store.ActiveLeasesForUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	return &workflowv1.ListActiveLeasesForUserResponse{Leases: leases}, nil
}

func (s *Server) GetActiveLease(ctx context.Context, req *workflowv1.GetActiveLeaseRequest) (*workflowv1.GetActiveLeaseResponse, error) {
	l, err := s.store.ActiveLeaseForSecret(ctx, req.GetSecretId())
	if err != nil {
		return nil, err
	}
	return &workflowv1.GetActiveLeaseResponse{Lease: l}, nil
}

// CheckoutSecret starts the checkout saga. Start advances the run through
// issue_lease (which persists the lease) and parks it at the wait-for-checkin
// step; we then return the lease the run created.
func (s *Server) CheckoutSecret(ctx context.Context, req *workflowv1.CheckoutSecretRequest) (*workflowv1.CheckoutSecretResponse, error) {
	runID, err := s.saga.Start(ctx, wfCheckout, map[string]any{
		"secret_id": req.GetSecretId(),
		"user_id":   req.GetActor().GetUserId(),
		"hours":     int(req.GetHours()),
	})
	if err != nil {
		return nil, fmt.Errorf("start checkout saga: %w", err)
	}
	lease, err := s.store.LeaseByRun(ctx, runID.String())
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, fmt.Errorf("checkout saga did not issue a lease")
	}
	return &workflowv1.CheckoutSecretResponse{Lease: lease}, nil
}

// CheckinSecret signals the checkout run to advance through rotate-on-checkin
// and close the lease.
func (s *Server) CheckinSecret(ctx context.Context, req *workflowv1.CheckinSecretRequest) (*workflowv1.CheckinSecretResponse, error) {
	runID, err := s.store.ActiveLeaseRunForSecretUser(ctx, req.GetSecretId(), req.GetActor().GetUserId())
	if err != nil {
		return nil, err
	}
	if runID == "" {
		return &workflowv1.CheckinSecretResponse{}, nil // nothing checked out
	}
	rid, err := uuid.Parse(runID)
	if err != nil {
		return nil, fmt.Errorf("parse run id: %w", err)
	}
	if err := s.saga.Signal(ctx, rid, "checkin", nil); err != nil {
		return nil, fmt.Errorf("signal checkin: %w", err)
	}
	return &workflowv1.CheckinSecretResponse{}, nil
}

// RotateSecret starts the rotation saga for a manual (operator-triggered)
// rotation. The saga's single rotate step runs synchronously to completion
// (no wait step), so by the time Start returns, vault.EnqueueRotation has
// already been called with reason="manual".
func (s *Server) RotateSecret(ctx context.Context, req *workflowv1.RotateSecretRequest) (*workflowv1.RotateSecretResponse, error) {
	if _, err := s.saga.Start(ctx, wfRotation, map[string]any{
		"secret_id": req.GetSecretId(),
		"user_id":   req.GetActor().GetUserId(),
		"reason":    "manual",
	}); err != nil {
		return nil, fmt.Errorf("start rotation saga: %w", err)
	}
	return &workflowv1.RotateSecretResponse{Ok: true}, nil
}

func (s *Server) ListApprovalRequests(ctx context.Context, _ *workflowv1.ListApprovalRequestsRequest) (*workflowv1.ListApprovalRequestsResponse, error) {
	reqs, err := s.store.ListRequests(ctx)
	if err != nil {
		return nil, err
	}
	return &workflowv1.ListApprovalRequestsResponse{Requests: reqs}, nil
}

func (s *Server) CreateAccessRequest(ctx context.Context, req *workflowv1.CreateAccessRequestRequest) (*workflowv1.CreateAccessRequestResponse, error) {
	r := &workflowv1.ApprovalRequest{
		Id:                uuid.NewString(),
		SecretId:          req.GetSecretId(),
		RequestedByUserId: req.GetActor().GetUserId(),
		Status:            workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING,
		RequestedAt:       time.Now().UTC().Format(time.RFC3339),
		Reason:            req.GetReason(),
	}
	if err := s.store.InsertRequest(ctx, r); err != nil {
		return nil, err
	}
	return &workflowv1.CreateAccessRequestResponse{Request: r}, nil
}

// CreateFolderMoveRequest records a non-admin's request to move a folder
// shared -> personal. It carries no secret; the folder ids + display names
// drive the approver's view, and ResolveApproval performs the move on approve.
func (s *Server) CreateFolderMoveRequest(ctx context.Context, req *workflowv1.CreateFolderMoveRequestRequest) (*workflowv1.CreateFolderMoveRequestResponse, error) {
	r := &workflowv1.ApprovalRequest{
		Id:                uuid.NewString(),
		RequestedByUserId: req.GetActor().GetUserId(),
		Status:            workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING,
		RequestedAt:       time.Now().UTC().Format(time.RFC3339),
		Reason:            req.GetReason(),
		Kind:              workflowv1.RequestKind_REQUEST_KIND_FOLDER_MOVE,
		FolderId:          req.GetFolderId(),
		DestParentId:      req.GetDestParentId(),
		FolderName:        req.GetFolderName(),
		DestParentName:    req.GetDestParentName(),
	}
	if err := s.store.InsertRequest(ctx, r); err != nil {
		return nil, err
	}
	return &workflowv1.CreateFolderMoveRequestResponse{Request: r}, nil
}

// CreateSecretMoveRequest records a non-admin's request to move a SECRET
// shared -> personal. Reuses secret_id + dest_parent_id (the destination
// folder); folder_name/dest_parent_name carry the display labels.
func (s *Server) CreateSecretMoveRequest(ctx context.Context, req *workflowv1.CreateSecretMoveRequestRequest) (*workflowv1.CreateSecretMoveRequestResponse, error) {
	r := &workflowv1.ApprovalRequest{
		Id:                uuid.NewString(),
		SecretId:          req.GetSecretId(),
		RequestedByUserId: req.GetActor().GetUserId(),
		Status:            workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING,
		RequestedAt:       time.Now().UTC().Format(time.RFC3339),
		Reason:            req.GetReason(),
		Kind:              workflowv1.RequestKind_REQUEST_KIND_SECRET_MOVE,
		DestParentId:      req.GetDestFolderId(),
		FolderName:        req.GetSecretName(),
		DestParentName:    req.GetDestFolderName(),
	}
	if err := s.store.InsertRequest(ctx, r); err != nil {
		return nil, err
	}
	return &workflowv1.CreateSecretMoveRequestResponse{Request: r}, nil
}

// Grant-window bounds. On approval the requester is granted time-boxed access
// by issuing a lease through the SAME checkout saga the CheckoutSecret RPC uses
// (so the reaper + rotate-on-return apply). The window is the approver's
// grant_hours, clamped to [1, maxGrantHours]; an unset/zero value defaults to
// defaultGrantHours. Sneakers has no per-tenant grant-duration setting today
// (vault SecuritySettings carries no such field), so the default lives here as
// a documented constant.
const (
	defaultGrantHours = 8
	maxGrantHours     = 24
)

func clampGrantHours(h int32) int {
	n := int(h)
	if n <= 0 {
		n = defaultGrantHours
	}
	if n > maxGrantHours {
		n = maxGrantHours
	}
	return n
}

func (s *Server) ResolveApproval(ctx context.Context, req *workflowv1.ResolveApprovalRequest) (*workflowv1.ResolveApprovalResponse, error) {
	r, err := s.store.ResolveRequest(ctx, req.GetId(), req.GetActor().GetUserId(), time.Now().UTC().Format(time.RFC3339), req.GetApprove())
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("approval request %q not found", req.GetId())
	}
	// On approval, grant the requester time-boxed access by running the checkout
	// saga on their behalf: it issues (and persists) the lease, then parks at
	// wait-for-checkin — so the reaper and rotate-on-return handle it exactly
	// like a self-service checkout. Denials just record the decision.
	//
	// Idempotent-safe: if the requester already holds an active lease on the
	// secret (e.g. a double-approve), don't issue a second one.
	// A folder-move approval has a different effect: perform the move as the
	// system (site-admin) actor — no lease, no grant. The vault re-scopes the
	// subtree to the destination personal owner.
	if req.GetApprove() && r.GetKind() == workflowv1.RequestKind_REQUEST_KIND_FOLDER_MOVE {
		if _, err := s.vault.MoveFolder(ctx, &vaultv1.MoveFolderRequest{
			Actor:       systemAdminActor(),
			Id:          r.GetFolderId(),
			NewParentId: r.GetDestParentId(),
		}); err != nil {
			return nil, fmt.Errorf("perform folder move: %w", err)
		}
		return &workflowv1.ResolveApprovalResponse{Request: r}, nil
	}
	// A secret-move approval performs the move (reassign the secret's folder) as
	// the system actor — no lease, no grant.
	if req.GetApprove() && r.GetKind() == workflowv1.RequestKind_REQUEST_KIND_SECRET_MOVE {
		if _, err := s.vault.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
			Actor:        systemAdminActor(),
			Id:           r.GetSecretId(),
			DestFolderId: r.GetDestParentId(),
		}); err != nil {
			return nil, fmt.Errorf("perform secret move: %w", err)
		}
		return &workflowv1.ResolveApprovalResponse{Request: r}, nil
	}
	if req.GetApprove() {
		existing, err := s.store.ActiveLeaseRunForSecretUser(ctx, r.GetSecretId(), r.GetRequestedByUserId())
		if err != nil {
			return nil, err
		}
		if existing == "" {
			if _, err := s.saga.Start(ctx, wfCheckout, map[string]any{
				"secret_id": r.GetSecretId(),
				"user_id":   r.GetRequestedByUserId(),
				"hours":     clampGrantHours(req.GetGrantHours()),
			}); err != nil {
				return nil, fmt.Errorf("issue grant lease: %w", err)
			}
		}
		// A lease alone doesn't confer reveal access: the vault's access check is
		// firewall-RACI, and the requester has no read grant on this secret. Add a
		// temporary secret-level read grant for the requester so they can actually
		// reveal/copy and load history for the lease window; the checkout saga's
		// close_lease step revokes it when the lease ends. Idempotent, so a
		// double-approve (existing lease) still ensures the grant is present.
		if err := grantSecretRead(ctx, s.vault, r.GetSecretId(), r.GetRequestedByUserId()); err != nil {
			return nil, fmt.Errorf("grant temp read access: %w", err)
		}
	}
	return &workflowv1.ResolveApprovalResponse{Request: r}, nil
}

// AddApprovalComment appends a message to an access request's discussion
// thread (so a requester and approver can chat on the request) and returns the
// updated request with its full thread loaded.
func (s *Server) AddApprovalComment(ctx context.Context, req *workflowv1.AddApprovalCommentRequest) (*workflowv1.AddApprovalCommentResponse, error) {
	c := &workflowv1.ApprovalComment{
		Id:           uuid.NewString(),
		AuthorUserId: req.GetActor().GetUserId(),
		Body:         req.GetBody(),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.store.AddComment(ctx, req.GetRequestId(), c); err != nil {
		return nil, err
	}
	r, err := s.store.GetRequest(ctx, req.GetRequestId())
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("approval request %q not found", req.GetRequestId())
	}
	return &workflowv1.AddApprovalCommentResponse{Request: r}, nil
}

// SeedIfEmpty is a no-op: the workflow service seeds no demo data. Leases and
// access-request approvals are all user-generated, so a fresh database starts
// empty and the dashboard reflects only real activity.
func (s *Server) SeedIfEmpty(_ context.Context) error { return nil }
