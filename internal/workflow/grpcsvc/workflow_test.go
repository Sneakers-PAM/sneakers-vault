// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// newTestServer wires an in-memory store + in-memory saga engine over a
// no-op fake vault client (tests that don't care about rotation dispatch).
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, _ := newTestServerWithVault(t)
	return s
}

// newTestServerWithVault is newTestServer but also returns the fake vault
// client so callers can assert on EnqueueRotation calls.
func newTestServerWithVault(t *testing.T) (*Server, *fakeVaultClient) {
	t.Helper()
	st := newMemStore()
	vc := newFakeVaultClient()
	eng, err := BuildInMemoryEngine(st, vc)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return New(st, eng, vc), vc
}

func waitLeaseReturned(t *testing.T, s *Server, runID string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		l, _ := s.store.LeaseByRun(context.Background(), runID)
		if l != nil && l.GetReturned() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("lease was not returned after check-in within timeout")
}

func TestCheckoutSagaIssuesLease(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-1", Hours: 2,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	lease := resp.GetLease()
	if lease.GetSecretId() != "secret-seed-1" || lease.GetUserId() != "user-carol" || lease.GetReturned() {
		t.Fatalf("bad lease: %+v", lease)
	}

	// The lease is active for the user and for the secret.
	active, _ := s.ListActiveLeasesForUser(ctx, &workflowv1.ListActiveLeasesForUserRequest{UserId: "user-carol"})
	if len(active.GetLeases()) != 1 {
		t.Fatalf("active leases = %d, want 1", len(active.GetLeases()))
	}
	got, _ := s.GetActiveLease(ctx, &workflowv1.GetActiveLeaseRequest{SecretId: "secret-seed-1"})
	if got.GetLease() == nil {
		t.Fatal("expected an active lease on the secret")
	}
}

func TestCheckinRunsRotateAndClosesLease(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-1", Hours: 4,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	// Find the run that owns the lease via the check-in path.
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-seed-1", "user-carol")
	if runID == "" {
		t.Fatal("no active lease run for secret/user")
	}
	_ = resp

	if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-1",
	}); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	// The checkout saga advances through rotate-on-checkin -> close_lease.
	waitLeaseReturned(t, s, runID)

	// No active leases remain.
	active, _ := s.ListActiveLeasesForUser(ctx, &workflowv1.ListActiveLeasesForUserRequest{UserId: "user-carol"})
	if len(active.GetLeases()) != 0 {
		t.Fatalf("active leases after check-in = %d, want 0", len(active.GetLeases()))
	}
}

func TestAccessRequestCreateAndResolve(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	created, err := s.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-clarke"}, SecretId: "secret-seed-1",
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if created.GetRequest().GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
		t.Fatal("new request should be pending")
	}

	resolved, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, Id: created.GetRequest().GetId(), Approve: true,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.GetRequest().GetStatus() != workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
		t.Fatalf("status = %v, want approved", resolved.GetRequest().GetStatus())
	}
	if resolved.GetRequest().GetResolvedByUserId() != "user-carol" {
		t.Fatal("resolvedBy not recorded")
	}
}

// hasUserReadGrant reports whether the ruleset carries the temporary
// USER/read=allow grant for userID that the lease flow adds.
func hasUserReadGrant(rules []*vaultv1.RaciRule, userID string) bool {
	for _, r := range rules {
		if isTempReadGrant(r, userID) {
			return true
		}
	}
	return false
}

// TestApprovalGrantsThenCheckinRevokesReadAccess proves that an
// approved access request adds a temporary secret-level read grant for the
// requester, and checking the lease back in removes exactly that grant.
func TestApprovalGrantsThenCheckinRevokesReadAccess(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()
	const (
		secretID = "secret-seed-1"
		reqUser  = "user-jobs"
	)

	// A pre-existing broader admin rule for the same user must survive revoke.
	if _, err := vc.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor:    &vaultv1.ActorContext{UserId: "system", IsRoot: true},
		SecretId: secretID,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-admin",
			Grants: map[string]string{"C": "allow", "R": "allow"},
		}},
	}); err != nil {
		t.Fatalf("seed ruleset: %v", err)
	}

	created, err := s.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: reqUser}, SecretId: secretID,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if _, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-turing"}, Id: created.GetRequest().GetId(), Approve: true,
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if !hasUserReadGrant(vc.secretRuleset(secretID), reqUser) {
		t.Fatal("expected a temporary read grant for the requester after approval")
	}

	// Check the lease back in -> saga close_lease revokes the temp grant.
	if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: reqUser}, SecretId: secretID,
	}); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, secretID, reqUser)
	_ = runID
	// Wait for the async close to remove the temp grant.
	revoked := false
	for i := 0; i < 200; i++ {
		if !hasUserReadGrant(vc.secretRuleset(secretID), reqUser) {
			revoked = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !revoked {
		t.Fatal("temporary read grant was not revoked after check-in")
	}

	// The pre-existing broader admin rule must remain untouched.
	kept := false
	for _, r := range vc.secretRuleset(secretID) {
		if r.GetSubjectName() == "user-admin" {
			kept = true
		}
	}
	if !kept {
		t.Fatal("revoke removed a pre-existing broader rule it should not have")
	}
}
