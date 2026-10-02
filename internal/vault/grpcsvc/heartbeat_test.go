// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
)

func TestNextDueBackoff(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	// valid → base + interval
	if got := nextDue(base, 300, HB_VALID, 0); !got.Equal(base.Add(300 * time.Second)) {
		t.Fatalf("valid: %v", got)
	}
	// unreachable → exponential backoff capped, independent of interval
	d1 := nextDue(base, 300, HB_UNREACHABLE, 1).Sub(base)
	d2 := nextDue(base, 300, HB_UNREACHABLE, 2).Sub(base)
	if d2 <= d1 {
		t.Fatalf("backoff not increasing: %v %v", d1, d2)
	}
}

func TestNextDueBackoffCapped(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	got := nextDue(base, 300, HB_UNREACHABLE, 20).Sub(base)
	if got != hbMaxBackoff {
		t.Fatalf("backoff not capped: %v", got)
	}
}

func TestNextDueValidDefaultsZeroInterval(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	got := nextDue(base, 0, HB_VALID, 0)
	if !got.Equal(base.Add(300 * time.Second)) {
		t.Fatalf("zero interval should default to 300s: %v", got)
	}
}

type rejectVerifier struct{}

func (rejectVerifier) Verify(string) (workloadid.Principal, error) {
	return workloadid.Principal{}, errors.New("rejected")
}

func TestVerifyWorkerRejectsBadIdentity(t *testing.T) {
	s := &Server{wid: rejectVerifier{}}
	if _, err := s.verifyWorker(context.Background(), &vaultv1.WorkerIdentity{Token: "bad"}); err == nil {
		t.Fatal("expected identity rejection")
	}
}

func TestVerifyWorkerUnavailableWithoutVerifier(t *testing.T) {
	s := &Server{}
	if _, err := s.verifyWorker(context.Background(), &vaultv1.WorkerIdentity{}); err == nil {
		t.Fatal("expected unavailable error with no verifier configured")
	}
}

type acceptVerifier struct{ principal workloadid.Principal }

func (a acceptVerifier) Verify(string) (workloadid.Principal, error) {
	return a.principal, nil
}

// TestRevealForHeartbeatRejectsRetiredSecret mirrors
// TestRevealAndCopyRejectRetiredSecret (vault_test.go): a retired secret must
// be unrevealable everywhere, including the connector's heartbeat pull-API —
// otherwise retiring a secret doesn't stop the connector from being handed
// the (still-live) credential.
func TestRevealForHeartbeatRejectsRetiredSecret(t *testing.T) {
	s := newServer(t)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	_, sid := createLifecycleSecret(t, s)

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}

	if _, err := s.RevealForHeartbeat(ctx, &vaultv1.RevealForHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "any"}, SecretId: sid,
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("RevealForHeartbeat on retired secret: want FailedPrecondition, got %v", err)
	}
}

// TestRevealForHeartbeatRejectsNonHeartbeatCapableSecret pins the scope check:
// without it, a verified worker could RevealForHeartbeat ANY
// secret by id — an arbitrary-secret exfil oracle gated only by the token
// check. createLifecycleSecret's secret is type-password (heartbeat: false),
// so it must be rejected before any decryption is attempted.
func TestRevealForHeartbeatRejectsNonHeartbeatCapableSecret(t *testing.T) {
	s := newServer(t)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	ctx := context.Background()
	_, sid := createLifecycleSecret(t, s)

	if _, err := s.RevealForHeartbeat(ctx, &vaultv1.RevealForHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "any"}, SecretId: sid,
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("RevealForHeartbeat on non-heartbeat-capable secret: want PermissionDenied, got %v", err)
	}
}
