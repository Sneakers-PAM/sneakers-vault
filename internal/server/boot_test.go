// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func bootClient(t *testing.T, port string) healthpb.HealthClient {
	t.Helper()
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return healthpb.NewHealthClient(conn)
}

func bootCheck(t *testing.T, c healthpb.HealthClient, service string) (healthpb.HealthCheckResponse_ServingStatus, metadata.MD) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var md metadata.MD
	resp, err := c.Check(ctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&md), grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("check %q: %v", service, err)
	}
	return resp.GetStatus(), md
}

func bootReport(t *testing.T, c healthpb.HealthClient) health.Report {
	t.Helper()
	st, md := bootCheck(t, c, "")
	if st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness while booting = %v, want NOT_SERVING", st)
	}
	raw := md.Get(HeaderHealth)
	if len(raw) != 1 {
		t.Fatalf("%s = %v, want one value", HeaderHealth, raw)
	}
	var r health.Report
	if err := json.Unmarshal([]byte(raw[0]), &r); err != nil {
		t.Fatalf("%s is not JSON: %v", HeaderHealth, err)
	}
	if len(md.Get("sneakers-version")) != 1 {
		t.Fatalf("the version header is missing while booting: %v", md)
	}
	return r
}

// While main waits for its dependencies, the port answers: liveness SERVING
// (the startup and liveness probes pass, nothing restarts the process),
// readiness NOT_SERVING with each dependency listed.
func TestBootHealth_ServesWhileDependenciesAreAwaited(t *testing.T) {
	port := freePort(t)
	b, err := StartBootHealth(port, log.Nop(), "postgres", "workload-identity")
	if err != nil {
		t.Fatalf("StartBootHealth: %v", err)
	}
	c := bootClient(t, port)

	if st, _ := bootCheck(t, c, LivenessService); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness while booting = %v, want SERVING", st)
	}
	r := bootReport(t, c)
	if r.Ready || r.Status != health.StateDown || len(r.Dependencies) != 2 {
		t.Fatalf("report before any attempt = %+v", r)
	}
	for _, d := range r.Dependencies {
		if d.State != health.StateDown || !d.Required || d.Error != ClassPending {
			t.Fatalf("dependency before any attempt = %+v, want down, required, pending", d)
		}
	}

	b.Waiting("postgres", fmt.Errorf("dial tcp db.example.org:5432: %w", syscall.ECONNREFUSED))
	r = bootReport(t, c)
	if d := r.Dependencies[0]; d.Name != "postgres" || d.Error != "refused" || d.CheckedAt.IsZero() {
		t.Fatalf("postgres after a refused attempt = %+v", d)
	}
	b.Up("postgres")
	r = bootReport(t, c)
	if d := r.Dependencies[0]; d.State != health.StateOK || d.Error != "" {
		t.Fatalf("postgres once up = %+v", d)
	}
	if r.Ready || r.Dependencies[1].State != health.StateDown {
		t.Fatalf("ready with workload-identity still pending: %+v", r)
	}

	b.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, log.Nop(), nil, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	if st, _ := bootCheck(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness from the real server on the same port = %v", st)
	}
}

func TestBootHealth_StopIsIdempotent(t *testing.T) {
	b, err := StartBootHealth(freePort(t), log.Nop(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { b.Stop(); b.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung")
	}
}

// The hook a startup wait calls after each failed attempt keeps the boot
// report current.
func TestBootHealth_RetryHookRecordsTheAttempt(t *testing.T) {
	port := freePort(t)
	b, err := StartBootHealth(port, log.Nop(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	b.RetryHook("postgres")(3, fmt.Errorf("dial: %w", syscall.ECONNREFUSED), 2*time.Second)
	r := bootReport(t, bootClient(t, port))
	if d := r.Dependencies[0]; d.State != health.StateDown || d.Error != "refused" || d.CheckedAt.IsZero() {
		t.Fatalf("postgres after a retried attempt = %+v", d)
	}
}
