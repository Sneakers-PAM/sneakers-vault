// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"google.golang.org/grpc/codes"
)

// Resolving a request needs an eligible approver: RACI A on the secret for
// an access request, a site admin for a move. Nobody resolves their own.

func accessRequest(t *testing.T, s *Server, requester string) string {
	t.Helper()
	r, err := s.CreateAccessRequest(context.Background(), &workflowv1.CreateAccessRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: requester}, SecretId: "secret-seed-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.GetRequest().GetId()
}

func stillPending(t *testing.T, s *Server, id string) {
	t.Helper()
	got, _ := s.store.GetRequest(context.Background(), id)
	if got.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		t.Fatalf("request resolved anyway: %v", got.GetStatus())
	}
}

func TestRequesterCannotResolveTheirOwnRequest(t *testing.T) {
	for _, approve := range []bool{true, false} {
		s, _, ca := newAuditedTestServer(t)
		id := accessRequest(t, s, "user-dave")
		_, err := s.ResolveApproval(context.Background(), &workflowv1.ResolveApprovalRequest{
			Actor: &workflowv1.ActorContext{UserId: "user-dave", IsSiteAdmin: true}, Id: id, Approve: approve,
		})
		wantRefusal(t, err, codes.PermissionDenied, ReasonSelfApproval)
		stillPending(t, s, id)
		if ev := ca.find("approval.denied"); ev == nil || ev.ActorUserID != "user-dave" || ev.Subject != id || ev.Attributes["reason"] != ReasonSelfApproval {
			t.Fatalf("audit = %+v", ev)
		}
	}
}

func TestResolvingAnAccessRequestNeedsRaciA(t *testing.T) {
	s, vc, ca := newAuditedTestServer(t)
	vc.denyApprove("secret-seed-1", "user-bob")
	id := accessRequest(t, s, "user-dave")
	_, err := s.ResolveApproval(context.Background(), &workflowv1.ResolveApprovalRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-bob"}, Id: id, Approve: false,
	})
	wantRefusal(t, err, codes.PermissionDenied, ReasonNotApprover)
	stillPending(t, s, id)
	if ev := ca.find("approval.denied"); ev == nil || ev.Attributes["reason"] != ReasonNotApprover {
		t.Fatalf("audit = %+v", ev)
	}
	r, err := s.ResolveApproval(context.Background(), &workflowv1.ResolveApprovalRequest{Actor: carol(), Id: id, Approve: true})
	if err != nil || r.GetRequest().GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
		t.Fatalf("approver: %v %v", r, err)
	}
}

func TestResolvingAMoveRequestNeedsASiteAdmin(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"folder", "secret"} {
		s, _, _ := newAuditedTestServer(t)
		var id string
		if kind == "folder" {
			r, err := s.CreateFolderMoveRequest(ctx, &workflowv1.CreateFolderMoveRequestRequest{
				Actor: &workflowv1.ActorContext{UserId: "user-dave"}, FolderId: "folder-a", DestParentId: "folder-b"})
			if err != nil {
				t.Fatal(err)
			}
			id = r.GetRequest().GetId()
		} else {
			r, err := s.CreateSecretMoveRequest(ctx, &workflowv1.CreateSecretMoveRequestRequest{
				Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-seed-1", DestFolderId: "folder-b"})
			if err != nil {
				t.Fatal(err)
			}
			id = r.GetRequest().GetId()
		}
		for _, who := range []*workflowv1.ActorContext{
			{UserId: "user-carol"},                // has RACI A, but isn't an admin
			{IsSiteAdmin: true},                   // admin flag without a user id
			{UserId: "system", IsSiteAdmin: true}, // a system id never passes as an admin
		} {
			_, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{Actor: who, Id: id, Approve: true})
			wantRefusal(t, err, codes.PermissionDenied, ReasonNotApprover)
			stillPending(t, s, id)
		}
		if _, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{
			Actor: &workflowv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}, Id: id, Approve: true}); err != nil {
			t.Fatalf("%s move by a site admin: %v", kind, err)
		}
	}
}
