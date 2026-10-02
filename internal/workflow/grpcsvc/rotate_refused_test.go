// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func vaultRefusal(t *testing.T, code codes.Code, reason string) error {
	t.Helper()
	st, err := status.New(code, "refused").WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: reason})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// A secret whose type can't rotate (or that opted out) still checks in: the
// vault refuses the rotation, and the lease closes anyway.
func TestCheckinClosesTheLeaseWhenTheSecretCantRotate(t *testing.T) {
	for _, reason := range []string{"ROTATION_NOT_SUPPORTED", "ROTATION_OPTED_OUT"} {
		s, vc := newTestServerWithVault(t)
		vc.enqueueErr = vaultRefusal(t, codes.FailedPrecondition, reason)
		ctx := context.Background()
		carol := &workflowv1.ActorContext{UserId: "user-carol"}
		if _, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{Actor: carol, SecretId: "secret-web", Hours: 1}); err != nil {
			t.Fatal(err)
		}
		runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-web", "user-carol")
		if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{Actor: carol, SecretId: "secret-web"}); err != nil {
			t.Fatalf("%s: checkin: %v", reason, err)
		}
		waitLeaseReturned(t, s, runID)
	}
}
