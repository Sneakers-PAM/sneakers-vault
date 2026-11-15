// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"
)

// runMigrate brings an empty database to the head migration and a second run
// leaves it there: the migrate command is safe to repeat (#81).
func TestRunMigrate_AppliesAndIsRepeatable(t *testing.T) {
	dsn := freshDB(t)
	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		if err := runMigrate(ctx, dsn, repoMigrations, "dev"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if v, dirty := schemaVersion(t, dsn); v != headMigration(t) || dirty {
			t.Fatalf("run %d: schema version = %d dirty=%v, want %d clean", i, v, dirty, headMigration(t))
		}
	}
}

// A non-dev run with no root KEK is refused before any migration runs, so the
// migrate command keeps the same guard as a normal boot.
func TestRunMigrate_NeedsTheRootKEKOutsideDev(t *testing.T) {
	dsn := freshDB(t)
	t.Setenv("VAULT_ROOT_KEK", "")
	if err := runMigrate(context.Background(), dsn, repoMigrations, "qa"); err == nil {
		t.Fatal("runMigrate in qa without VAULT_ROOT_KEK succeeded, want an error")
	}
}

func TestIsMigrateCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"vault"}, false},
		{[]string{"vault", "migrate"}, true},
		{[]string{"vault", "serve"}, false},
	} {
		if got := isMigrateCommand(tc.args); got != tc.want {
			t.Errorf("isMigrateCommand(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
