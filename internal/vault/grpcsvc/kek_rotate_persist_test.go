// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// failingStore is a Store whose Persist always fails, to prove a rotation
// whose re-wraps could not be made durable is reported as a failure.
type failingStore struct{ memStore }

func (failingStore) Persist(context.Context, *state) error { return errors.New("db down") }

// RotateKek persists its own outcome (synchronously, before answering), so a
// caller that sees success knows the re-wrapped records are durable.
func TestRotateKek_PersistsBeforeReturningSuccess(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s := fx.s
	seedRecordsOnV1(t, s, 2)
	rs := &recordingStore{}
	s.store = rs

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	if got := rs.persistCalls(); got != 1 {
		t.Fatalf("Persist calls = %d, want 1 (RotateKek persists itself)", got)
	}
}

// A persist failure after the in-memory sweep must surface as an error, not
// a silent success, and must not emit a success audit event.
func TestRotateKek_PersistFailure_ReturnsError(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s := fx.s
	seedRecordsOnV1(t, s, 2)
	s.store = failingStore{}

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	resp, err := s.RotateKek(context.Background(), &vaultv1.RotateKekRequest{Actor: admin})
	if code(err) != codes.Internal {
		t.Fatalf("RotateKek with failing persist: want Internal, got resp=%v err=%v", resp, err)
	}
	ev := auditor.find("kek.rotate")
	if ev == nil {
		t.Fatal("expected a kek.rotate audit event recording the failed outcome")
	}
	if ev.Attributes["outcome"] != "persist_failed" {
		t.Fatalf("audit outcome = %q, want persist_failed", ev.Attributes["outcome"])
	}
}

// PersistUnary must not persist RotateKek a second time (the handler already
// did, synchronously).
func TestPersistUnary_SkipsRotateKek(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	rs := &recordingStore{}
	s.store = rs
	info := &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/RotateKek"}
	h := func(context.Context, any) (any, error) { return &vaultv1.RotateKekResponse{}, nil }
	if _, err := s.PersistUnary(context.Background(), nil, info, h); err != nil {
		t.Fatal(err)
	}
	if got := rs.persistCalls(); got != 0 {
		t.Fatalf("PersistUnary persisted RotateKek %d times, want 0", got)
	}
}

// The scheduler must report a persist failure as a tick error.
func TestKekSchedulerTick_PersistFailure_ReturnsError(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	s.store = failingStore{}
	s.mu.Lock()
	s.settings.KekRotationDays = 1
	s.mu.Unlock()
	fx.ks.mu.Lock()
	fx.ks.rows[0].CreatedAt = fx.ks.rows[0].CreatedAt.AddDate(0, 0, -10)
	fx.ks.mu.Unlock()
	if err := s.kekSchedulerTick(context.Background()); err == nil {
		t.Fatal("kekSchedulerTick: want error when persist fails")
	}
}
