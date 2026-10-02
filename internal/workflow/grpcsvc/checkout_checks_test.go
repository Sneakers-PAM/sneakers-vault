// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Check-out needs read on the secret (the vault's RACI decision), a type
// with check-out on, and no lease held by someone else. Check-in, and the
// rotation it starts, are for the lease holder only.

type capAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *capAudit) Emit(_ context.Context, ev audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *capAudit) find(action string) *audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].Action == action {
			return &c.events[i]
		}
	}
	return nil
}

func newAuditedTestServer(t *testing.T) (*Server, *fakeVaultClient, *capAudit) {
	t.Helper()
	s, vc := newTestServerWithVault(t)
	ca := &capAudit{}
	s.SetAuditor(ca)
	return s, vc, ca
}

func carol() *workflowv1.ActorContext {
	return &workflowv1.ActorContext{UserId: "user-carol", GroupNames: []string{"ops"}, GroupIds: []string{"g-ops"}, MfaVerifiedAtUnix: 1700000000}
}

func wantRefusal(t *testing.T, err error, code codes.Code, reason string) *errdetails.ErrorInfo {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != code {
		t.Fatalf("code %v (%v), want %v", st.Code(), err, code)
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			if info.GetDomain() != "sneakers.workflow" || info.GetReason() != reason {
				t.Fatalf("error info %v, want sneakers.workflow/%s", info, reason)
			}
			return info
		}
	}
	t.Fatalf("no ErrorInfo on %v", err)
	return nil
}

func TestCheckoutWithoutReadIsRefused(t *testing.T) {
	s, vc, ca := newAuditedTestServer(t)
	vc.denyRead("secret-seed-1", "user-nobody")
	_, err := s.CheckoutSecret(context.Background(), &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-nobody"}, SecretId: "secret-seed-1", Hours: 1,
	})
	wantRefusal(t, err, codes.PermissionDenied, ReasonCheckoutNoAccess)
	if l, _ := s.store.ActiveLeaseForSecret(context.Background(), "secret-seed-1"); l != nil {
		t.Fatalf("a refused check-out issued lease %v", l)
	}
	if ev := ca.find("checkout.denied"); ev == nil || ev.ActorUserID != "user-nobody" || ev.Subject != "secret-seed-1" || ev.Attributes["reason"] != ReasonCheckoutNoAccess {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestCheckoutAsksTheVaultWithTheUsersFullContext(t *testing.T) {
	s, vc, _ := newAuditedTestServer(t)
	if _, err := s.CheckoutSecret(context.Background(), &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-seed-1", Hours: 1}); err != nil {
		t.Fatal(err)
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if len(vc.accessActors) != 1 {
		t.Fatalf("%d access checks", len(vc.accessActors))
	}
	a := vc.accessActors[0]
	if a.GetUserId() != "user-carol" || len(a.GetGroupNames()) != 1 || a.GetGroupIds()[0] != "g-ops" || a.GetMfaVerifiedAtUnix() != 1700000000 {
		t.Fatalf("vault actor %v", a)
	}
}

func TestCheckoutOfATypeWithCheckoutOffIsRefused(t *testing.T) {
	s, vc, _ := newAuditedTestServer(t)
	vc.disableCheckout("secret-pw")
	_, err := s.CheckoutSecret(context.Background(), &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-pw", Hours: 1})
	wantRefusal(t, err, codes.FailedPrecondition, ReasonCheckoutTypeDisabled)
}

func TestSecondCheckoutWhileALeaseIsHeldIsRefused(t *testing.T) {
	s, _, _ := newAuditedTestServer(t)
	ctx := context.Background()
	if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-seed-1", Hours: 1}); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"user-dave", "user-carol"} {
		_, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: &workflowv1.ActorContext{UserId: who}, SecretId: "secret-seed-1", Hours: 1})
		info := wantRefusal(t, err, codes.FailedPrecondition, ReasonCheckoutLeaseHeld)
		if info.GetMetadata()["holder_user_id"] != "user-carol" {
			t.Fatalf("%s: metadata %v", who, info.GetMetadata())
		}
	}
}

func TestCheckinByANonHolderIsRefusedAndRotatesNothing(t *testing.T) {
	s, vc, _ := newAuditedTestServer(t)
	ctx := context.Background()
	if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-seed-1", Hours: 1}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-seed-1"})
	wantRefusal(t, err, codes.PermissionDenied, ReasonCheckinNotHolder)
	if vc.callCount() != 0 {
		t.Fatalf("a refused check-in enqueued %d rotations", vc.callCount())
	}
	if l, _ := s.store.ActiveLeaseForSecret(ctx, "secret-seed-1"); l == nil || l.GetUserId() != "user-carol" {
		t.Fatalf("the holder's lease changed: %v", l)
	}
}

func TestCheckoutAndCheckinAreAudited(t *testing.T) {
	s, _, ca := newAuditedTestServer(t)
	ctx := context.Background()
	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-seed-1", Hours: 2})
	if err != nil {
		t.Fatal(err)
	}
	ev := ca.find("checkout")
	if ev == nil || ev.ActorUserID != "user-carol" || ev.Subject != "secret-seed-1" || ev.Attributes["lease_id"] != resp.GetLease().GetId() || ev.Attributes["expires_at"] == "" {
		t.Fatalf("checkout audit = %+v", ev)
	}
	if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{Actor: carol(), SecretId: "secret-seed-1"}); err != nil {
		t.Fatal(err)
	}
	if ev := ca.find("checkin"); ev == nil || ev.ActorUserID != "user-carol" || ev.Attributes["lease_id"] != resp.GetLease().GetId() {
		t.Fatalf("checkin audit = %+v", ev)
	}
}

func TestApprovalWhileSomeoneElseHoldsALeaseIsRefused(t *testing.T) {
	s, _, _ := newAuditedTestServer(t)
	ctx := context.Background()
	if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: carol(), SecretId: "secret-seed-1", Hours: 1}); err != nil {
		t.Fatal(err)
	}
	req, err := s.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{Actor: &workflowv1.ActorContext{UserId: "user-dave"}, SecretId: "secret-seed-1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{Actor: &workflowv1.ActorContext{UserId: "user-owner"}, Id: req.GetRequest().GetId(), Approve: true})
	wantRefusal(t, err, codes.FailedPrecondition, ReasonCheckoutLeaseHeld)
	got, _ := s.store.GetRequest(ctx, req.GetRequest().GetId())
	if got.GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		t.Fatalf("the request was resolved anyway: %v", got.GetStatus())
	}
}

func TestCheckoutWithoutAnActorIsRefused(t *testing.T) {
	s, _, _ := newAuditedTestServer(t)
	_, err := s.CheckoutSecret(context.Background(), &workflowv1.CheckoutSecretRequest{SecretId: "secret-seed-1", Hours: 1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err %v, want InvalidArgument", err)
	}
}

func TestConcurrentCheckoutsIssueOneLease(t *testing.T) {
	s, _, _ := newAuditedTestServer(t)
	ctx := context.Background()
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
				Actor: &workflowv1.ActorContext{UserId: "user-" + string(rune('a'+i))}, SecretId: "secret-race", Hours: 1,
			})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		wantRefusal(t, err, codes.FailedPrecondition, ReasonCheckoutLeaseHeld)
	}
	if ok != 1 {
		t.Fatalf("%d check-outs succeeded, want exactly 1", ok)
	}
}
