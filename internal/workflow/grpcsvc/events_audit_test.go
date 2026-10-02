// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
)

// The workflow records requests, decisions, comments and lease expiry in the
// audit service, by id: never a comment body, a reason or any value.

const freeText = "s3cret-in-free-text"

func noFreeText(t *testing.T, ev *audit.Event) {
	t.Helper()
	for k, v := range ev.Attributes {
		if strings.Contains(v, freeText) {
			t.Fatalf("%s carries free text in %s", ev.Action, k)
		}
	}
	if strings.Contains(ev.Subject, freeText) {
		t.Fatalf("%s carries free text in its subject", ev.Action)
	}
}

func TestAccessRequestsAreAudited(t *testing.T) {
	s, _, ca := newAuditedTestServer(t)
	ctx := context.Background()
	r, err := s.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-seed-1", Reason: freeText})
	if err != nil {
		t.Fatal(err)
	}
	ev := ca.find("request.create")
	if ev == nil || ev.ActorUserID != "user-dave" || ev.Subject != r.GetRequest().GetId() ||
		ev.Attributes["secret_id"] != "secret-seed-1" || ev.Attributes["kind"] != "REQUEST_KIND_UNSPECIFIED" {
		t.Fatalf("request.create = %+v", ev)
	}
	noFreeText(t, ev)
}

func TestMoveRequestsAreAudited(t *testing.T) {
	s, _, ca := newAuditedTestServer(t)
	ctx := context.Background()
	f, err := s.CreateFolderMoveRequest(ctx, &workflowv1.CreateFolderMoveRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-dave"}, FolderId: "folder-a", DestParentId: "folder-b", Reason: freeText})
	if err != nil {
		t.Fatal(err)
	}
	if ev := ca.find("request.create"); ev == nil || ev.Subject != f.GetRequest().GetId() || ev.Attributes["folder_id"] != "folder-a" ||
		ev.Attributes["dest_parent_id"] != "folder-b" || ev.Attributes["kind"] != "REQUEST_KIND_FOLDER_MOVE" {
		t.Fatalf("folder move = %+v", ev)
	}
	sm, err := s.CreateSecretMoveRequest(ctx, &workflowv1.CreateSecretMoveRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-seed-1", DestFolderId: "folder-b"})
	if err != nil {
		t.Fatal(err)
	}
	if ev := ca.find("request.create"); ev == nil || ev.Subject != sm.GetRequest().GetId() || ev.Attributes["kind"] != "REQUEST_KIND_SECRET_MOVE" {
		t.Fatalf("secret move = %+v", ev)
	}
}

func TestApprovalsAndDenialsAreAudited(t *testing.T) {
	for _, approve := range []bool{true, false} {
		s, _, ca := newAuditedTestServer(t)
		ctx := context.Background()
		id := accessRequest(t, s, "user-dave")
		hours := int32(3)
		if _, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{Actor: carol(), Id: id, Approve: approve, GrantHours: &hours}); err != nil {
			t.Fatal(err)
		}
		action := "request.deny"
		if approve {
			action = "request.approve"
		}
		ev := ca.find(action)
		if ev == nil || ev.ActorUserID != "user-carol" || ev.Subject != id || ev.Attributes["requested_by"] != "user-dave" || ev.Attributes["secret_id"] != "secret-seed-1" {
			t.Fatalf("%s = %+v", action, ev)
		}
		if approve && ev.Attributes["grant_hours"] != "3" {
			t.Fatalf("grant_hours = %q", ev.Attributes["grant_hours"])
		}
	}
}

func TestCommentsAreAuditedWithoutTheirBody(t *testing.T) {
	s, _, ca := newAuditedTestServer(t)
	id := accessRequest(t, s, "user-dave")
	if _, err := s.AddApprovalComment(context.Background(), &workflowv1.AddApprovalCommentRequest{
		Actor: carol(), RequestId: id, Body: freeText}); err != nil {
		t.Fatal(err)
	}
	ev := ca.find("request.comment")
	if ev == nil || ev.ActorUserID != "user-carol" || ev.Subject != id || ev.Attributes["comment_id"] == "" {
		t.Fatalf("request.comment = %+v", ev)
	}
	noFreeText(t, ev)
}

func TestLeaseExpiryIsAudited(t *testing.T) {
	s, _, ca := newAuditedTestServer(t)
	ctx := context.Background()
	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-old", Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	backdateLease(t, s, resp.GetLease().GetId(), time.Now().UTC().Add(-time.Hour))
	if n := s.reapOnce(ctx); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	ev := ca.find("lease.expire")
	if ev == nil || ev.ActorUserID != "system:workflow" || ev.Subject != "secret-old" ||
		ev.Attributes["lease_id"] != resp.GetLease().GetId() || ev.Attributes["user_id"] != "user-dave" {
		t.Fatalf("lease.expire = %+v", ev)
	}
}
