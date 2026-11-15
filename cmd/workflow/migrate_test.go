// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
)

// runMigrate applies the service migrations and the saga engine's tables to
// an empty database, and a second run is a no-op (#81).
func TestRunMigrate_AppliesAndIsRepeatable(t *testing.T) {
	dsn := freshDB(t)
	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		if err := runMigrate(ctx, dsn, "../../migrations/workflow"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var dirty bool
	if err := db.Querier().QueryRow(ctx, "SELECT dirty FROM workflow_schema_migrations").Scan(&dirty); err != nil {
		t.Fatalf("read workflow_schema_migrations: %v", err)
	}
	if dirty {
		t.Fatal("workflow_schema_migrations is dirty after migrate")
	}
}

func TestIsMigrateCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"workflow"}, false},
		{[]string{"workflow", "migrate"}, true},
		{[]string{"workflow", "serve"}, false},
	} {
		if got := isMigrateCommand(tc.args); got != tc.want {
			t.Errorf("isMigrateCommand(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
