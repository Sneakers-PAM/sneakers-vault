// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// The database keeps one active lease per secret, so two check-outs racing
// past the pre-check can't both get one.
func TestPGOneActiveLeasePerSecret(t *testing.T) {
	dsn := os.Getenv("WORKFLOW_PG_DSN")
	if dsn == "" {
		t.Skip("set WORKFLOW_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()
	if err := postgres.MigrateWithTable(dsn, "../../../migrations/workflow", "workflow_schema_migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Pool().Exec(ctx, `TRUNCATE leases`); err != nil {
		t.Fatal(err)
	}
	st := NewPGStore(db.Pool())
	now := time.Now().UTC()
	if err := st.InsertLease(ctx, newLease("secret-u", "user-a", now, 1), "run-a"); err != nil {
		t.Fatalf("first lease: %v", err)
	}
	if err := st.InsertLease(ctx, newLease("secret-u", "user-b", now, 1), "run-b"); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second active lease: err %v, want ErrLeaseHeld", err)
	}
	if err := st.InsertLease(ctx, newLease("secret-other", "user-b", now, 1), "run-c"); err != nil {
		t.Fatalf("another secret: %v", err)
	}
	if err := st.CloseLeaseByRun(ctx, "run-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertLease(ctx, newLease("secret-u", "user-b", now, 1), "run-d"); err != nil {
		t.Fatalf("after the first was returned: %v", err)
	}
}
