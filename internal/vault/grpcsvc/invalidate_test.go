// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/alicebob/miniredis/v2"
	"google.golang.org/protobuf/proto"
)

// sharedStore is a process-local Store that ACTUALLY persists and reloads a
// deep-cloned snapshot, so two Server instances backed by the same sharedStore
// behave like two replicas over one Postgres: a write persisted by one is only
// visible to the other after it reloads. (memStore can't model this — its Load
// always reports empty.) The deep clone mirrors pgStore's protojson round-trip,
// so the two servers never share slice/pointer memory.
type sharedStore struct {
	st *state
}

func (m *sharedStore) Load(context.Context) (*state, bool, error) {
	if m.st == nil {
		return nil, true, nil
	}
	st := cloneState(m.st)
	empty := len(st.types) == 0 && len(st.folders) == 0 && st.settings == nil
	return st, empty, nil
}

func (m *sharedStore) Persist(_ context.Context, st *state) error {
	m.st = cloneState(st)
	return nil
}

func cloneSlice[T proto.Message](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	for i, msg := range in {
		out[i] = proto.Clone(msg).(T)
	}
	return out
}

func cloneState(st *state) *state {
	if st == nil {
		return nil
	}
	cp := &state{
		types:       cloneSlice(st.types),
		folders:     cloneSlice(st.folders),
		rules:       cloneSlice(st.rules),
		raciRules:   cloneSlice(st.raciRules),
		secrets:     cloneSlice(st.secrets),
		connections: cloneSlice(st.connections),
		targets:     cloneSlice(st.targets),
		policies:    cloneSlice(st.policies),
		extCatalog:  cloneSlice(st.extCatalog),
		records:     map[string]crypto.Record{},
	}
	if st.settings != nil {
		cp.settings = proto.Clone(st.settings).(*vaultv1.SecuritySettings)
	}
	for k, v := range st.records {
		cp.records[k] = v
	}
	return cp
}

// newSharedServer builds a dev Server backed by the given sharedStore, mirroring
// newServerWithEnv but with a durable, shareable store.
func newSharedServer(t *testing.T, store *sharedStore) *Server {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	s, err := NewWithStore(context.Background(), store, crypto.New(kek), nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	return s
}

// persistNow mimics the PersistUnary interceptor: snapshot under the read lock,
// then persist. Direct handler calls in tests don't go through the interceptor,
// so a test that wants a write to become durable calls this.
func persistNow(t *testing.T, s *Server) {
	t.Helper()
	s.mu.RLock()
	snap := s.snapshot()
	s.mu.RUnlock()
	if err := s.store.Persist(context.Background(), snap); err != nil {
		t.Fatalf("persist: %v", err)
	}
}

func hasSecret(s *Server, id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findSecret(id) != nil
}

// createSecretVia creates a shared folder owned by carol and a secret in it on
// the given server, returning the secret id.
func createSecretVia(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "Platform Team"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	sec, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db creds", FolderId: f.GetFolder().GetId(), TypeId: "type-password",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return sec.GetSecret().GetId()
}

// TestReloadReflectsPeerWrite proves a secret written and
// persisted by replica A is invisible to replica B until B reloads from the
// shared store — after which B sees it. This is exactly the stale-read bug
// (writes on one pod never reaching another) and its fix.
func TestReloadReflectsPeerWrite(t *testing.T) {
	store := &sharedStore{}
	serverA := newSharedServer(t, store)
	serverB := newSharedServer(t, store)

	sid := createSecretVia(t, serverA)
	persistNow(t, serverA)

	if hasSecret(serverB, sid) {
		t.Fatal("precondition failed: B saw A's write without reloading")
	}
	if err := serverB.reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !hasSecret(serverB, sid) {
		t.Fatal("after reload, B still does not see A's persisted secret")
	}
}

// TestPublishTriggersReloadViaRedis is the end-to-end pub/sub path over
// miniredis: B's background subscriber, on receiving A's invalidation, reloads
// and converges on A's persisted write.
func TestPublishTriggersReloadViaRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	rcA, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rcA.Close() }()
	rcB, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rcB.Close() }()

	store := &sharedStore{}
	serverA := newSharedServer(t, store)
	serverB := newSharedServer(t, store)
	serverA.SetInvalidation(rcA, DefaultInvalidateChannel)
	serverB.SetInvalidation(rcB, DefaultInvalidateChannel)
	serverB.invDebounceD = 2 * time.Millisecond // fast reload for the test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serverB.RunInvalidationSubscriber(ctx)

	sid := createSecretVia(t, serverA)
	persistNow(t, serverA)

	// Re-publish while polling so the test is robust to the lazy subscription
	// warm-up (the first ReceiveMessage establishes the subscription).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		serverA.publishInvalidate(ctx, "CreateSecret", sid)
		if hasSecret(serverB, sid) {
			return // success
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("B never converged on A's write via Redis invalidation")
}

// TestInvalidationNoRedisIsNoop confirms that with no Redis wired the publisher
// is a safe no-op and the subscriber returns immediately (degraded single-
// replica behaviour, never a hang or panic).
func TestInvalidationNoRedisIsNoop(t *testing.T) {
	store := &sharedStore{}
	s := newSharedServer(t, store)
	// publishInvalidate must not panic without Redis.
	s.publishInvalidate(context.Background(), "CreateSecret", "sec-x")

	done := make(chan struct{})
	go func() {
		s.RunInvalidationSubscriber(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunInvalidationSubscriber did not return when Redis is unwired")
	}
}
