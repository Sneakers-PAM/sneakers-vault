// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func stampBuild(t *testing.T) {
	t.Helper()
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })
}

// healthHeaders runs a server with checker and returns the response headers
// of one health check of service.
func healthHeaders(t *testing.T, checker *health.Checker, service string) metadata.MD {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, nil, checker, nil) }()
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
		_, err = healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&md), grpc.WaitForReady(true))
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

func postgresWithVersion(version func(context.Context) (string, error)) health.Dependency {
	return health.Dependency{Name: "postgres", Required: true, Check: func(context.Context) error { return nil }, Version: version}
}

// TestRun_HealthCheckReportsBuild checks the health answer carries the build's
// version and commit in its response headers, for the gateway's diagnostics.
func TestRun_HealthCheckReportsBuild(t *testing.T) {
	stampBuild(t)
	md := healthHeaders(t, nil, "")
	if got := md.Get("sneakers-version"); len(got) != 1 || got[0] != "v9.9.9-test" {
		t.Errorf("sneakers-version = %v, want v9.9.9-test", got)
	}
	if got := md.Get("sneakers-commit"); len(got) != 1 || got[0] != "0123456789abcdef" {
		t.Errorf("sneakers-commit = %v, want 0123456789abcdef", got)
	}
	if got := md.Get("sneakers-dep-postgres"); len(got) != 0 {
		t.Errorf("sneakers-dep-postgres = %v, want no header without a postgres dependency", got)
	}
}

// TestRun_HealthCheckReportsPostgres checks a known database version rides
// along as sneakers-dep-postgres, trimmed to its first token, and an unread
// one as unknown.
func TestRun_HealthCheckReportsPostgres(t *testing.T) {
	read := func(context.Context) (string, error) { return dependencyVersion("16.4 (Debian 16.4-1.pgdg120+1)"), nil }
	if got := healthHeaders(t, newTestChecker(t, postgresWithVersion(read)), "").Get("sneakers-dep-postgres"); len(got) != 1 || got[0] != "16.4" {
		t.Errorf("sneakers-dep-postgres = %v, want 16.4", got)
	}
	unread := func(context.Context) (string, error) { return "", context.DeadlineExceeded }
	if got := healthHeaders(t, newTestChecker(t, postgresWithVersion(unread)), "").Get("sneakers-dep-postgres"); len(got) != 1 || got[0] != "unknown" {
		t.Errorf("sneakers-dep-postgres = %v, want unknown", got)
	}
}

func TestDependencyVersion_Normalises(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"   ":                    "",
		"17.0":                   "17.0",
		"  15.8 (Ubuntu 15.8) ":  "15.8",
		strings.Repeat("9", 100): strings.Repeat("9", 64),
	}
	for in, want := range cases {
		if got := dependencyVersion(in); got != want {
			t.Errorf("dependencyVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHealthCheck_HeaderNames pins the exact header names the gateway's
// diagnostics read, on readiness and on liveness.
func TestHealthCheck_HeaderNames(t *testing.T) {
	stampBuild(t)
	checker := newTestChecker(t,
		postgresWithVersion(func(context.Context) (string, error) { return "17.11", nil }),
		health.Dependency{Name: "audit", Check: func(context.Context) error { return nil }},
	)
	keys := func(md metadata.MD) []string {
		var out []string
		for k := range md {
			if strings.HasPrefix(k, "sneakers-") {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	want := []string{"sneakers-commit", "sneakers-dep-postgres", "sneakers-depstate-audit", "sneakers-depstate-postgres", "sneakers-health", "sneakers-version"}
	if got := keys(healthHeaders(t, checker, "")); !slices.Equal(got, want) {
		t.Fatalf("readiness headers = %v, want %v", got, want)
	}
	if got := keys(healthHeaders(t, checker, LivenessService)); !slices.Equal(got, []string{"sneakers-commit", "sneakers-version"}) {
		t.Fatalf("liveness headers = %v", got)
	}
}

// TestPostgresVersion_RealDatabase reads the version from a real server when
// TEST_DATABASE_DSN is set.
func TestPostgresVersion_RealDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	db, err := postgres.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	v, err := PostgresVersion(db.Querier())(context.Background())
	if err != nil || v == "" || strings.ContainsAny(v, " (") {
		t.Fatalf("PostgresVersion = %q %v, want a bare version such as 17.0", v, err)
	}
}
