// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	sagapg "github.com/Bugs5382/go-saga-orchestration/store/postgres"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// TestPGCheckoutSagaPersists runs against a live Postgres when WORKFLOW_PG_DSN
// is set (otherwise skipped). It proves the checkout saga persists a lease,
// check-in advances the run through rotate-on-checkin + close (lease returned),
// approvals persist, and state survives a "restart" (fresh store/engine/server
// on the same database).
//
//	WORKFLOW_PG_DSN=postgres://postgres@localhost:5432/workflow_test?sslmode=disable \
//	  go test ./internal/workflow/grpcsvc -run TestPG -v
func TestPGCheckoutSagaPersists(t *testing.T) {
	dsn := os.Getenv("WORKFLOW_PG_DSN")
	if dsn == "" {
		t.Skip("set WORKFLOW_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.MigrateWithTable(dsn, "../../../migrations/workflow", "workflow_schema_migrations"); err != nil {
		t.Fatalf("migrate service: %v", err)
	}
	if err := sagapg.Migrate(dsn); err != nil {
		t.Fatalf("migrate saga store: %v", err)
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	pool := db.Pool()
	if _, err := pool.Exec(ctx, `TRUNCATE leases, approval_requests`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	newServer := func() *Server {
		sagaStore, err := sagapg.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("open saga store: %v", err)
		}
		st := NewPGStore(pool)
		vc := newFakeVaultClient()
		eng, err := BuildEngine(sagaStore, st, vc)
		if err != nil {
			t.Fatalf("build engine: %v", err)
		}
		return New(st, eng, vc)
	}

	s := newServer()

	// Checkout -> lease persisted + active.
	co, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-1", Hours: 3,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	if co.GetLease().GetId() == "" {
		t.Fatal("checkout returned no lease")
	}
	var leaseRows int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM leases WHERE returned=false`).Scan(&leaseRows)
	if leaseRows != 1 {
		t.Fatalf("active lease rows in DB = %d, want 1", leaseRows)
	}
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-seed-1", "user-carol")
	if runID == "" {
		t.Fatal("no run id for the active lease")
	}

	// Check-in -> saga advances (rotate stub + close) -> lease returned.
	if _, err := s.CheckinSecret(ctx, &workflowv1.CheckinSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-seed-1",
	}); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	returned := false
	for i := 0; i < 200; i++ {
		var r bool
		if err := pool.QueryRow(ctx, `SELECT returned FROM leases WHERE run_id=$1`, runID).Scan(&r); err == nil && r {
			returned = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !returned {
		t.Fatal("lease not returned in DB after check-in")
	}

	// Approvals persist through create -> resolve.
	created, err := s.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-clarke"}, SecretId: "secret-seed-1",
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if _, err := s.ResolveApproval(ctx, &workflowv1.ResolveApprovalRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, Id: created.GetRequest().GetId(), Approve: true,
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// "Restart": a fresh server on the same DB sees the persisted state — the
	// lease is closed (no active leases), the approval is resolved.
	s2 := newServer()
	active, _ := s2.ListActiveLeasesForUser(ctx, &workflowv1.ListActiveLeasesForUserRequest{UserId: "user-carol"})
	if len(active.GetLeases()) != 0 {
		t.Fatalf("after restart: active leases = %d, want 0", len(active.GetLeases()))
	}
	reqs, _ := s2.ListApprovalRequests(ctx, &workflowv1.ListApprovalRequestsRequest{})
	var approved int
	for _, r := range reqs.GetRequests() {
		if r.GetStatus() == workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED {
			approved++
		}
	}
	if approved != 1 {
		t.Fatalf("after restart: approved requests = %d, want 1", approved)
	}

	_, _ = pool.Exec(ctx, `TRUNCATE leases, approval_requests`)
}
