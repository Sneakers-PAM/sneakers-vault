// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// TestReaperSignalsExpiredLease proves that a lease whose expiry has passed
// without an explicit check-in is picked up by one reaper pass, which
// signals the owning saga run's "checkin" — driving the existing checkout
// saga's rotate+close, so an expired lease still rotates and closes.
func TestReaperSignalsExpiredLease(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()

	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-expired", Hours: 1,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	leaseID := resp.GetLease().GetId()
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-expired", "user-carol")
	if runID == "" {
		t.Fatal("no active lease run for secret/user")
	}

	// Force the lease into the past directly (CheckoutSecret only ever
	// issues future-dated leases).
	backdateLease(t, s, leaseID, time.Now().UTC().Add(-1*time.Hour))

	n := s.reapOnce(ctx)
	if n != 1 {
		t.Fatalf("reaped = %d, want 1", n)
	}
	waitLeaseReturned(t, s, runID)
	waitForCalls(t, vc, 1)
}

// TestReaperIgnoresFutureLease covers the negative case: a lease not yet
// due is left untouched by a reaper pass.
func TestReaperIgnoresFutureLease(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()

	if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-future", Hours: 4,
	}); err != nil {
		t.Fatalf("checkout: %v", err)
	}

	n := s.reapOnce(ctx)
	if n != 0 {
		t.Fatalf("reaped = %d, want 0 (future lease should be untouched)", n)
	}
	if vc.callCount() != 0 {
		t.Fatalf("EnqueueRotation calls = %d, want 0", vc.callCount())
	}
}

// backdateLease reaches into the in-memory store to set a lease's ExpiresAt,
// simulating time passing without an explicit check-in.
func backdateLease(t *testing.T, s *Server, leaseID string, at time.Time) {
	t.Helper()
	ms, ok := s.store.(*memStore)
	if !ok {
		t.Fatal("backdateLease requires the in-memory store")
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	for _, ml := range ms.leases {
		if ml.l.GetId() == leaseID {
			ml.l.ExpiresAt = at.Format(time.RFC3339)
			return
		}
	}
	t.Fatalf("lease %s not found", leaseID)
}
