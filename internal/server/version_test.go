// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/buildinfo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// healthHeaders runs a server and returns the response headers of one health check.
func healthHeaders(t *testing.T) metadata.MD {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, port, nil) }()
	t.Cleanup(func() { cancel(); <-done })

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var md metadata.MD
	deadline := time.Now().Add(5 * time.Second)
	for {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
		_, err = healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}, grpc.Header(&md), grpc.WaitForReady(true))
		ccancel()
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	return md
}

// TestRun_HealthCheckReportsBuild checks the health answer carries the build's
// version and commit in its response headers, for the gateway's diagnostics.
func TestRun_HealthCheckReportsBuild(t *testing.T) {
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })
	SetDependencyVersion(DependencyPostgres, "")

	md := healthHeaders(t)
	if got := md.Get(HeaderVersion); len(got) != 1 || got[0] != "v9.9.9-test" {
		t.Errorf("%s = %v, want v9.9.9-test", HeaderVersion, got)
	}
	if got := md.Get(HeaderCommit); len(got) != 1 || got[0] != "0123456789abcdef" {
		t.Errorf("%s = %v, want 0123456789abcdef", HeaderCommit, got)
	}
	if got := md.Get(HeaderDependencyPrefix + DependencyPostgres); len(got) != 0 {
		t.Errorf("%s = %v, want no header while the version is unknown", HeaderDependencyPrefix+DependencyPostgres, got)
	}
}

// TestRun_HealthCheckReportsPostgres checks a known database version rides
// along as sneakers-dep-postgres, trimmed to its first token.
func TestRun_HealthCheckReportsPostgres(t *testing.T) {
	SetDependencyVersion(DependencyPostgres, "16.4 (Debian 16.4-1.pgdg120+1)")
	t.Cleanup(func() { SetDependencyVersion(DependencyPostgres, "") })

	md := healthHeaders(t)
	if got := md.Get(HeaderDependencyPrefix + DependencyPostgres); len(got) != 1 || got[0] != "16.4" {
		t.Errorf("%s = %v, want 16.4", HeaderDependencyPrefix+DependencyPostgres, got)
	}
}

func TestSetDependencyVersion_Normalises(t *testing.T) {
	t.Cleanup(func() { SetDependencyVersion(DependencyPostgres, "") })
	cases := map[string]string{
		"":                       "",
		"   ":                    "",
		"17.0":                   "17.0",
		"  15.8 (Ubuntu 15.8) ":  "15.8",
		strings.Repeat("9", 100): strings.Repeat("9", 64),
	}
	for in, want := range cases {
		SetDependencyVersion(DependencyPostgres, in)
		if got := DependencyVersion(DependencyPostgres); got != want {
			t.Errorf("SetDependencyVersion(%q): DependencyVersion() = %q, want %q", in, got, want)
		}
	}
}

// TestRecordPostgresVersion_RealDatabase reads the version from a real server
// when TEST_DATABASE_DSN is set.
func TestRecordPostgresVersion_RealDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	t.Cleanup(func() { SetDependencyVersion(DependencyPostgres, "") })
	db, err := postgres.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	if err := RecordPostgresVersion(context.Background(), db.Querier()); err != nil {
		t.Fatalf("RecordPostgresVersion: %v", err)
	}
	if v := DependencyVersion(DependencyPostgres); v == "" || strings.ContainsAny(v, " (") {
		t.Fatalf("DependencyVersion(postgres) = %q, want a bare version such as 17.0", v)
	}
}
