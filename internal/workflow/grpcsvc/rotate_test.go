// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// TestRotateSecretEnqueuesRotation proves RotateSecret starts the
// rotation saga, whose rotate action calls vault.EnqueueRotation with
// reason="manual".
func TestRotateSecretEnqueuesRotation(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()

	resp, err := s.RotateSecret(ctx, &workflowv1.RotateSecretRequest{
		Actor:    &workflowv1.ActorContext{UserId: "user-carol"},
		SecretId: "secret-seed-1",
	})
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if !resp.GetOk() {
		t.Fatal("expected ok=true")
	}

	waitForCalls(t, vc, 1)
	got := vc.lastCall()
	if got.GetSecretId() != "secret-seed-1" {
		t.Fatalf("secret id = %q, want secret-seed-1", got.GetSecretId())
	}
	if got.GetReason() != "manual" {
		t.Fatalf("reason = %q, want manual", got.GetReason())
	}
	if !got.GetActor().GetIsRoot() {
		t.Fatalf("actor.is_root = %v, want true (system-triggered rotation must present a root actor)", got.GetActor().GetIsRoot())
	}
}
