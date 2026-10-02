// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"fmt"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
)

// The Postgres-backed tests expect the real schema, so bring the test database
// to head once before any of them run.
func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_DATABASE_DSN"); dsn != "" {
		if err := postgres.Migrate(dsn, "../../../migrations/vault"); err != nil {
			fmt.Fprintln(os.Stderr, "migrate test database:", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}
