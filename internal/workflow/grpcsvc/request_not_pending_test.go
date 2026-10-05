// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"google.golang.org/grpc/codes"
)

// A request is resolved once. Resolving it again, either way, is refused
// with REQUEST_NOT_PENDING and changes nothing.

func resolve(s *Server, actor *workflowv1.ActorContext, id string, approve bool) (*workflowv1.ResolveApprovalResponse, error) {
	return s.ResolveApproval(context.Background(), &workflowv1.ResolveApprovalRequest{Actor: actor, Id: id, Approve: approve})
}

func erin() *workflowv1.ActorContext {
	return &workflowv1.ActorContext{UserId: "user-erin", MfaVerifiedAtUnix: 1700000000}
}

func TestResolvingAResolvedRequestIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second bool
	}{
		{"approve twice", true, true},
		{"approve after deny", false, true},
		{"deny after approve", true, false},
		{"deny twice", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, ca := newAuditedTestServer(t)
			id := accessRequest(t, s, "user-dave")
			if _, err := resolve(s, carol(), id, tc.first); err != nil {
				t.Fatalf("first resolve: %v", err)
			}
			before, _ := s.store.GetRequest(context.Background(), id)
			wantStatus, wantBy, wantAt := before.GetStatus(), before.GetResolvedByUserId(), before.GetResolvedAt()

			_, err := resolve(s, erin(), id, tc.second)
			wantRefusal(t, err, codes.FailedPrecondition, ReasonRequestNotPending)

			after, _ := s.store.GetRequest(context.Background(), id)
			if after.GetStatus() != wantStatus || after.GetResolvedByUserId() != wantBy || after.GetResolvedAt() != wantAt {
				t.Fatalf("request changed: %v by %q at %q, want %v by %q at %q",
					after.GetStatus(), after.GetResolvedByUserId(), after.GetResolvedAt(), wantStatus, wantBy, wantAt)
			}
			if ev := ca.find("approval.denied"); ev == nil || ev.ActorUserID != "user-erin" || ev.Subject != id || ev.Attributes["reason"] != ReasonRequestNotPending {
				t.Fatalf("audit = %+v", ev)
			}
			if !tc.first {
				run, err := s.store.ActiveLeaseRunForSecretUser(context.Background(), "secret-seed-1", "user-dave")
				if err != nil || run != "" {
					t.Fatalf("a denied request granted a lease: run %q, err %v", run, err)
				}
			}
		})
	}
}

func TestResolvingAResolvedMoveRequestIsRefused(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newAuditedTestServer(t)
	r, err := s.CreateFolderMoveRequest(ctx, &workflowv1.CreateFolderMoveRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-dave"}, FolderId: "folder-a", DestParentId: "folder-b"})
	if err != nil {
		t.Fatal(err)
	}
	admin := &workflowv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := resolve(s, admin, r.GetRequest().GetId(), false); err != nil {
		t.Fatalf("deny: %v", err)
	}
	_, err = resolve(s, admin, r.GetRequest().GetId(), true)
	wantRefusal(t, err, codes.FailedPrecondition, ReasonRequestNotPending)
}

func TestMemStoreResolvesOnlyAPendingRequest(t *testing.T) {
	testStoreResolvesOnlyAPendingRequest(t, newMemStore())
}

// testStoreResolvesOnlyAPendingRequest checks the store's own guard, which
// stops two approvers racing past the server's check from both resolving.
func testStoreResolvesOnlyAPendingRequest(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	r := &workflowv1.ApprovalRequest{
		Id: "req-store-guard", SecretId: "secret-seed-1", RequestedByUserId: "user-dave",
		Status: workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING, RequestedAt: nowRFC3339(),
	}
	if err := st.InsertRequest(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := st.ResolveRequest(ctx, r.GetId(), "user-carol", "2026-01-01T00:00:00Z", false)
	if err != nil || got.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_DENIED {
		t.Fatalf("first resolve: %v %v", got, err)
	}
	if _, err := st.ResolveRequest(ctx, r.GetId(), "user-erin", "2026-01-02T00:00:00Z", true); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("second resolve: err %v, want ErrRequestNotPending", err)
	}
	got, _ = st.GetRequest(ctx, r.GetId())
	if got.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_DENIED || got.GetResolvedByUserId() != "user-carol" || got.GetResolvedAt() != "2026-01-01T00:00:00Z" {
		t.Fatalf("request changed: %v", got)
	}
	if got, err := st.ResolveRequest(ctx, "req-missing", "user-carol", nowRFC3339(), true); err != nil || got != nil {
		t.Fatalf("unknown request: %v %v, want nil, nil", got, err)
	}
}
