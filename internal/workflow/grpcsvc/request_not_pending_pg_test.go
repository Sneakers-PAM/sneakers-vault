// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
)

func TestPGStoreResolvesOnlyAPendingRequest(t *testing.T) {
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
	if _, err := db.Pool().Exec(ctx, `TRUNCATE approval_comments, approval_requests`); err != nil {
		t.Fatal(err)
	}
	testStoreResolvesOnlyAPendingRequest(t, NewPGStore(db.Pool()))
}
