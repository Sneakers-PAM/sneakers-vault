// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
)

// stateTables are the snapshot-persisted tables pgStore owns (see migrations/vault).
var stateTables = []string{
	"secret_types", "folders", "folder_rules", "raci_rules", "secrets", "connections",
	"targets", "password_policies", "extension_catalog", "security_settings",
	"secret_records", "target_raci_rules",
}

func lostWritePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// replica boots one vault replica: its own pool (a separate pod), a pgStore over
// the shared database, and a Redis invalidation subscriber with the production
// 200 ms debounce.
func replica(ctx context.Context, t *testing.T, kek crypto.KEKProvider, mr *miniredis.Miniredis) *Server {
	t.Helper()
	s, err := NewWithStore(ctx, NewPGStore(lostWritePool(t)), crypto.New(kek), nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	rc, err := bredis.Connect(ctx, bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	s.SetInvalidation(rc, DefaultInvalidateChannel) // defaultInvDebounce = 200 ms
	go s.RunInvalidationSubscriber(ctx)
	return s
}

// viaInterceptor runs fn through the real PersistUnary interceptor, exactly as
// the gRPC server does for a mutating RPC.
func viaInterceptor(ctx context.Context, t *testing.T, s *Server, method string, fn func() (any, error)) any {
	t.Helper()
	resp, err := s.PersistUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/" + method},
		func(context.Context, any) (any, error) { return fn() })
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return resp
}

func createViaInterceptor(ctx context.Context, t *testing.T, s *Server, name string) string {
	t.Helper()
	operator := &vaultv1.ActorContext{UserId: "user-operator"}
	f := viaInterceptor(ctx, t, s, "CreateFolder", func() (any, error) {
		return s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: operator, Name: name + " folder"})
	}).(*vaultv1.CreateFolderResponse)
	sec := viaInterceptor(ctx, t, s, "CreateSecret", func() (any, error) {
		return s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
			Actor: operator, Name: name, FolderId: f.GetFolder().GetId(), TypeId: "type-password",
			Fields: map[string]string{"password": "pw-" + name},
		})
	}).(*vaultv1.CreateSecretResponse)
	return sec.GetSecret().GetId()
}

func dbHasSecret(ctx context.Context, t *testing.T, p *pgxpool.Pool, id string) bool {
	t.Helper()
	var n int
	if err := p.QueryRow(ctx, "SELECT count(*) FROM secrets WHERE id=$1", id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func setupLostWrite(t *testing.T) (context.Context, *pgxpool.Pool, *Server, *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := lostWritePool(t)
	for _, tbl := range stateTables {
		if _, err := p.Exec(ctx, "TRUNCATE "+tbl); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	a := replica(ctx, t, kek, mr)
	b := replica(ctx, t, kek, mr)
	time.Sleep(100 * time.Millisecond) // let both subscriptions establish
	return ctx, p, a, b
}

// TestMultiReplicaConcurrentCreatesKeepBothWrites: replica A and replica
// B each accept a CreateSecret inside one 200 ms debounce window. Before the
// write lock, B's full-snapshot Persist (DELETE-all + INSERT-all) was built from
// a state that never contained A's secret, so it deleted A's row, and the
// invalidation then made A reload and drop its own write from memory too.
func TestMultiReplicaConcurrentCreatesKeepBothWrites(t *testing.T) {
	ctx, p, a, b := setupLostWrite(t)

	idA := createViaInterceptor(ctx, t, a, "written-on-A") // success returned to caller A
	idB := createViaInterceptor(ctx, t, b, "written-on-B") // success returned to caller B, <200 ms later

	time.Sleep(1 * time.Second) // well past debounce: both replicas have reloaded

	for _, c := range []struct {
		name string
		id   string
	}{{"A's secret", idA}, {"B's secret", idB}} {
		if !dbHasSecret(ctx, t, p, c.id) {
			t.Errorf("LOST WRITE: %s (%s) was acknowledged but is not in Postgres", c.name, c.id)
		}
		if !hasSecret(a, c.id) {
			t.Errorf("LOST WRITE: %s (%s) missing on replica A after convergence", c.name, c.id)
		}
		if !hasSecret(b, c.id) {
			t.Errorf("LOST WRITE: %s (%s) missing on replica B after convergence", c.name, c.id)
		}
	}
}

// TestMultiReplicaCopyOnStaleReplicaKeepsPeerWrite: the clobbering write
// did not even need to be a create. RevealSecretField/CopySecret bump
// view_count and are in mutatingMethods, so a plain *read* of an unrelated
// secret on a stale replica persisted a full snapshot and deleted a peer's
// just-created secret.
func TestMultiReplicaCopyOnStaleReplicaKeepsPeerWrite(t *testing.T) {
	ctx, p, a, b := setupLostWrite(t)

	existing := createViaInterceptor(ctx, t, a, "pre-existing")
	time.Sleep(600 * time.Millisecond) // B converges on "pre-existing"
	if !hasSecret(b, existing) {
		t.Fatal("precondition: B never converged on the pre-existing secret")
	}

	idA := createViaInterceptor(ctx, t, a, "fresh-on-A")
	viaInterceptor(ctx, t, b, "CopySecret", func() (any, error) { // an agent merely copies another secret on B
		return b.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: &vaultv1.ActorContext{UserId: "user-operator"}, Id: existing})
	})

	time.Sleep(1 * time.Second)
	if !dbHasSecret(ctx, t, p, idA) {
		t.Errorf("LOST WRITE: A's secret %s deleted from Postgres by a CopySecret on replica B", idA)
	}
	if !hasSecret(a, idA) {
		t.Errorf("LOST WRITE: A's secret %s vanished from replica A itself after reload", idA)
	}
}

// TestMultiReplicaConcurrentWritersKeepEveryWrite: many writers on both
// replicas at once, with no pause for invalidations. Every acknowledged create
// must be durable and visible on both replicas once they converge.
func TestMultiReplicaConcurrentWritersKeepEveryWrite(t *testing.T) {
	ctx, p, a, b := setupLostWrite(t)
	operator := &vaultv1.ActorContext{UserId: "user-operator"}
	f := viaInterceptor(ctx, t, a, "CreateFolder", func() (any, error) {
		return a.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: operator, Name: "stress"})
	}).(*vaultv1.CreateFolderResponse)
	folderID := f.GetFolder().GetId()
	time.Sleep(600 * time.Millisecond) // B converges on the folder

	const writersPerReplica, createsPerWriter = 4, 5
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 2*writersPerReplica*createsPerWriter)
	var wg sync.WaitGroup
	for _, s := range []*Server{a, b} {
		for w := 0; w < writersPerReplica; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < createsPerWriter; i++ {
					name := fmt.Sprintf("stress-%p-%d-%d", s, w, i)
					resp, err := s.PersistUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/CreateSecret"},
						func(context.Context, any) (any, error) {
							return s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
								Actor: operator, Name: name, FolderId: folderID, TypeId: "type-password",
								Fields: map[string]string{"password": "pw-" + name},
							})
						})
					if err != nil {
						results <- result{err: err}
						continue
					}
					results <- result{id: resp.(*vaultv1.CreateSecretResponse).GetSecret().GetId()}
				}
			}()
		}
	}
	wg.Wait()
	close(results)

	time.Sleep(1 * time.Second) // both replicas reload after the last write
	var acked int
	for r := range results {
		if r.err != nil {
			t.Errorf("CreateSecret failed: %v", r.err)
			continue
		}
		acked++
		if !dbHasSecret(ctx, t, p, r.id) {
			t.Errorf("LOST WRITE: %s acknowledged but not in Postgres", r.id)
		}
		if !hasSecret(a, r.id) || !hasSecret(b, r.id) {
			t.Errorf("LOST WRITE: %s missing on a replica after convergence", r.id)
		}
	}
	if want := 2 * writersPerReplica * createsPerWriter; acked != want {
		t.Errorf("acknowledged creates: want %d, got %d", want, acked)
	}
}
