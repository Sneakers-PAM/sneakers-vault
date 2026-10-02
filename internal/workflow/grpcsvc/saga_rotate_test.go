// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// waitForCalls polls until the fake vault client has recorded at least n
// EnqueueRotation calls (the saga engine advances actions synchronously to
// the next pause/terminal, but poll anyway rather than assume timing).
func waitForCalls(t *testing.T, vc *fakeVaultClient, n int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if vc.callCount() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("vault.EnqueueRotation calls = %d, want >= %d", vc.callCount(), n)
}

// TestCheckinEnqueuesRotationWithCheckinReason proves the checkout
// saga's check-in signal routes to wf.rotate and enqueues a
// real rotation with reason="checkin" — unconditionally (workflow has no
// visibility into the secret type's rotate-on-checkin flag, so it always
// enqueues and lets vault's typeHasRotation gate it).
func TestCheckinEnqueuesRotationWithCheckinReason(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()

	if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-2", Hours: 2,
	}); err != nil {
		t.Fatalf("checkout: %v", err)
	}
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-seed-2", "user-carol")
	if runID == "" {
		t.Fatal("no active lease run for secret/user")
	}

	if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-2",
	}); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	waitLeaseReturned(t, s, runID)

	waitForCalls(t, vc, 1)
	got := vc.lastCall()
	if got.GetSecretId() != "secret-seed-2" {
		t.Fatalf("secret id = %q, want secret-seed-2", got.GetSecretId())
	}
	if got.GetReason() != "checkin" {
		t.Fatalf("reason = %q, want checkin", got.GetReason())
	}
	if !got.GetActor().GetIsRoot() {
		t.Fatalf("actor.is_root = %v, want true (system-triggered rotation must present a root actor)", got.GetActor().GetIsRoot())
	}
}
