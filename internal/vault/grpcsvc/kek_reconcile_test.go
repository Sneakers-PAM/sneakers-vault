// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// TestReconcileKeyring_PicksUpPeerRotatedGeneration is the HA regression:
// a peer replica ran RotateKek and persisted kek-v2 to the shared kek_keyring
// table, but THIS replica's in-memory keyring never saw it (only reload's
// hydrate ran, refreshing s.records — which now reference kek-v2 — not the
// keyring). Without reconcileKeyring, this replica cannot unwrap anything
// sealed under kek-v2 and every reveal fails with "no working KEK for ref
// kek-v2" until it restarts. After reconcileKeyring, the
// generation is present, active, and usable.
func TestReconcileKeyring_PicksUpPeerRotatedGeneration(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	// Simulate the peer's RotateKek outcome landing in the durable keyring
	// store: a new working-KEK generation, wrapped under the same root this
	// replica already trusts, made active.
	rawV2, err := crypto.RandKey()
	if err != nil {
		t.Fatalf("RandKey: %v", err)
	}
	wrappedV2, _, err := fx.root.WrapDEK(rawV2)
	if err != nil {
		t.Fatalf("wrap v2 under root: %v", err)
	}
	if err := fx.ks.InsertActive(ctx, "kek-v2", wrappedV2, "root-v1"); err != nil {
		t.Fatalf("InsertActive kek-v2: %v", err)
	}

	// A DEK the peer wrapped under kek-v2 after its rotation (what a rewrapped
	// secret_record now looks like once this replica's hydrate picks it up).
	dek, err := crypto.RandKey()
	if err != nil {
		t.Fatalf("RandKey dek: %v", err)
	}
	staticV2, err := crypto.NewStaticKEK(rawV2)
	if err != nil {
		t.Fatalf("NewStaticKEK(rawV2): %v", err)
	}
	wrappedDEK, _, err := staticV2.WrapDEK(dek)
	if err != nil {
		t.Fatalf("wrap dek under kek-v2: %v", err)
	}

	// Precondition proving the regression: this replica's keyring has never
	// heard of kek-v2.
	if s.keyring.Has("kek-v2") {
		t.Fatal("precondition: keyring must not already know kek-v2")
	}
	if _, err := s.keyring.UnwrapDEK(wrappedDEK, "kek-v2"); err == nil {
		t.Fatal("precondition: UnwrapDEK(kek-v2) must fail before reconcileKeyring")
	}

	if err := s.reconcileKeyring(ctx); err != nil {
		t.Fatalf("reconcileKeyring: %v", err)
	}

	if !s.keyring.Has("kek-v2") {
		t.Fatal("reconcileKeyring did not add kek-v2 to the in-memory keyring")
	}
	if got := s.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef after reconcile = %q, want kek-v2", got)
	}
	got, err := s.keyring.UnwrapDEK(wrappedDEK, "kek-v2")
	if err != nil {
		t.Fatalf("UnwrapDEK(kek-v2) after reconcile: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK after reconcile does not match original")
	}

	// kek-v1 must still be present and usable too — reconcile only adds, never
	// drops, a generation.
	if !s.keyring.Has("kek-v1") {
		t.Fatal("reconcileKeyring must not drop the pre-existing kek-v1 generation")
	}
}

// TestReconcileKeyring_AlreadyCurrent_NoOp verifies a reconcile that finds
// nothing new (this replica ran the rotation itself, or was already
// reconciled) leaves the keyring exactly as-is.
func TestReconcileKeyring_AlreadyCurrent_NoOp(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	if err := s.reconcileKeyring(ctx); err != nil {
		t.Fatalf("reconcileKeyring: %v", err)
	}
	if got := s.keyring.ActiveRef(); got != "kek-v1" {
		t.Fatalf("ActiveRef after no-op reconcile = %q, want unchanged kek-v1", got)
	}
}

// TestReconcileKeyring_UnwrapFailure_FailsClosed verifies that a stored
// working-KEK generation this root cannot unwrap makes reconcileKeyring
// return an error rather than silently running with an incomplete keyring
// (mirrors BuildKeyring's boot-time fail-closed behaviour).
func TestReconcileKeyring_UnwrapFailure_FailsClosed(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()

	// Garbage wrapped bytes: this root cannot possibly unwrap them.
	fx.ks.mu.Lock()
	fx.ks.rows = append(fx.ks.rows, keyringRow{Ref: "kek-vbad", WrappedKey: []byte("not-a-valid-wrap"), RootRef: "root-v1"})
	fx.ks.mu.Unlock()

	if err := s.reconcileKeyring(ctx); err == nil {
		t.Fatal("reconcileKeyring must fail closed when root cannot unwrap a stored generation")
	}
	if s.keyring.Has("kek-vbad") {
		t.Fatal("a generation that failed to unwrap must never be added to the keyring")
	}
}

// TestReconcileKeyring_NilKeyring_NoOp verifies the no-keyring/no-Postgres
// path (SetKeyring never called) is a safe no-op, not a panic.
func TestReconcileKeyring_NilKeyring_NoOp(t *testing.T) {
	s := newServer(t)
	if err := s.reconcileKeyring(context.Background()); err != nil {
		t.Fatalf("reconcileKeyring with no keyring wired: %v", err)
	}
}

// TestReload_ReconcilesKeyringAfterPeerRotation is the full regression,
// end to end: two replicas share a durable store AND a durable keyring store
// (as two pods share Postgres). Replica A rotates the KEK (as the RotateKek
// RPC handler would); replica B — which never ran the rotation itself — only
// learns about it via reload. Before this fix, B's hydrate would refresh its
// records (now on kek-v2) while leaving its keyring on kek-v1 only, so
// decrypting the rewrapped record on B would fail. After the fix, reload's
// reconcileKeyring call closes that gap and B can decrypt it.
func TestReload_ReconcilesKeyringAfterPeerRotation(t *testing.T) {
	store := &sharedStore{}
	root, err := crypto.NewStaticKEKFromSeed("reload-reconcile-root")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rawV1, err := crypto.RandKey()
	if err != nil {
		t.Fatalf("RandKey: %v", err)
	}
	wrappedV1, _, err := root.WrapDEK(rawV1)
	if err != nil {
		t.Fatalf("wrap v1: %v", err)
	}
	ks := &fakeKeyringAdmin{rows: []keyringRow{
		{Ref: "kek-v1", WrappedKey: wrappedV1, RootRef: "root-v1", Active: true},
	}}

	newReplica := func() *Server {
		kr, err := crypto.NewKeyringKEK(root, []crypto.WorkingKey{{Ref: "kek-v1", Key: rawV1}}, "kek-v1")
		if err != nil {
			t.Fatalf("NewKeyringKEK: %v", err)
		}
		s, err := NewWithStore(context.Background(), store, crypto.New(kr), nil, "dev")
		if err != nil {
			t.Fatalf("NewWithStore: %v", err)
		}
		s.SetKeyring(kr, ks, root, "root-v1")
		return s
	}

	serverA := newReplica()
	serverB := newReplica()
	ctx := context.Background()

	ids, plaintext := seedRecordsOnV1(t, serverA, 1)
	persistNow(t, serverA)
	if err := serverB.reload(ctx); err != nil {
		t.Fatalf("B initial reload: %v", err)
	}

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := serverA.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("RotateKek on A: %v", err)
	}
	persistNow(t, serverA)

	if err := serverB.reload(ctx); err != nil {
		t.Fatalf("B reload after peer rotation: %v", err)
	}

	id := ids[0]
	serverB.mu.RLock()
	rec := serverB.records[id]
	serverB.mu.RUnlock()
	if rec.KeyRef != "kek-v2" {
		t.Fatalf("B record KeyRef after reload = %q, want kek-v2 (hydrate should refresh records)", rec.KeyRef)
	}
	if got := serverB.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("B keyring ActiveRef after reload = %q, want kek-v2", got)
	}
	got, err := serverB.crypt.Open(rec, "password")
	if err != nil {
		t.Fatalf("Open on B after peer rotation + reload: %v (the bug: B's keyring never learned kek-v2)", err)
	}
	if got != plaintext[id] {
		t.Fatalf("B decrypted plaintext = %q, want %q", got, plaintext[id])
	}
}
