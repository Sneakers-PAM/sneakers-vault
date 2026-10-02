// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"google.golang.org/grpc/codes"
)

// With "require MFA for sensitive checkout" on, checking out a secret whose
// type has a super-sensitive field needs an MFA within MFA_MAX_AGE.

var checkoutNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func mfaActor(age time.Duration) *workflowv1.ActorContext {
	a := &workflowv1.ActorContext{UserId: "user-carol"}
	if age >= 0 {
		a.MfaVerifiedAtUnix = checkoutNow.Add(-age).Unix()
	}
	return a
}

func sensitiveCheckoutServer(t *testing.T) (*Server, *fakeVaultClient, *capAudit) {
	t.Helper()
	s, vc, ca := newAuditedTestServer(t)
	s.now = func() time.Time { return checkoutNow }
	vc.markSensitiveType("secret-card")
	return s, vc, ca
}

func checkout(s *Server, a *workflowv1.ActorContext, secretID string) error {
	_, err := s.CheckoutSecret(context.Background(), &workflowv1.CheckoutSecretRequest{Actor: a, SecretId: secretID, Hours: 1})
	return err
}

func TestSensitiveCheckoutNeedsAFreshMFAWhenOn(t *testing.T) {
	for name, age := range map[string]time.Duration{"no MFA": -1, "stale MFA": time.Hour} {
		s, _, ca := sensitiveCheckoutServer(t)
		wantRefusal(t, checkout(s, mfaActor(age), "secret-card"), codes.PermissionDenied, ReasonStepUpRequired)
		if ev := ca.find("checkout.denied"); ev == nil || ev.Attributes["reason"] != ReasonStepUpRequired {
			t.Fatalf("%s: audit = %+v", name, ev)
		}
		if l, _ := s.store.ActiveLeaseForSecret(context.Background(), "secret-card"); l != nil {
			t.Fatalf("%s: a lease was issued", name)
		}
	}
	s, _, _ := sensitiveCheckoutServer(t)
	if err := checkout(s, mfaActor(time.Minute), "secret-card"); err != nil {
		t.Fatalf("fresh MFA: %v", err)
	}
}

func TestSensitiveCheckoutMFAOffAllowsAStaleMFA(t *testing.T) {
	s, vc, _ := sensitiveCheckoutServer(t)
	vc.setSensitiveCheckoutMFA(false)
	if err := checkout(s, mfaActor(time.Hour), "secret-card"); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryTypesDontNeedMFAForCheckout(t *testing.T) {
	s, _, _ := sensitiveCheckoutServer(t)
	if err := checkout(s, mfaActor(-1), "secret-plain"); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveCheckoutUsesTheConfiguredMFAMaxAge(t *testing.T) {
	s, _, _ := sensitiveCheckoutServer(t)
	s.SetMFAMaxAge(15 * time.Minute)
	if err := checkout(s, mfaActor(10*time.Minute), "secret-card"); err != nil {
		t.Fatalf("10m-old MFA under a 15m window: %v", err)
	}
}
