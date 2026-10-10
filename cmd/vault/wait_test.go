// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return strconv.Itoa(p)
}

// lateProxy starts forwarding 127.0.0.1:port to target after delay; until
// then nothing listens there, so connections are refused, as when the
// database comes up after the service.
func lateProxy(t *testing.T, port, target string, delay time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	wg.Go(func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Errorf("proxy listen: %v", err)
			return
		}
		go func() { <-ctx.Done(); _ = l.Close() }()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			})
		}
	})
}

// With PostgreSQL unreachable at boot, the service waits: no error, the port
// answers liveness SERVING and readiness NOT_SERVING, and once the database
// answers the preflight, the migrations and the pool all go through. Needs
// TEST_DATABASE_DSN.
func TestOpenPostgres_WaitsForALateDatabase(t *testing.T) {
	dsn := freshDB(t)
	t.Setenv("VAULT_ROOT_KEK", "")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	target := u.Host
	proxyPort := freePort(t)
	u.Host = "127.0.0.1:" + proxyPort
	late := u.String()
	const delay = 3 * time.Second
	lateProxy(t, proxyPort, target, delay)

	port := freePort(t)
	boot, err := server.StartBootHealth(port, log.Nop(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(boot.Stop)

	type opened struct {
		ref string
		db  *postgres.DB
		err error
	}
	done := make(chan opened, 1)
	start := time.Now()
	go func() {
		_, ref, db, err := openPostgres(context.Background(), boot, late, repoMigrations, "dev", late,
			postgres.WithWaitBackoff(100*time.Millisecond, 500*time.Millisecond))
		done <- opened{ref, db, err}
	}()

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	hc := healthpb.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for svc, want := range map[string]healthpb.HealthCheckResponse_ServingStatus{
		server.LivenessService: healthpb.HealthCheckResponse_SERVING,
		"":                     healthpb.HealthCheckResponse_NOT_SERVING,
	} {
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: svc}, grpc.WaitForReady(true))
		if err != nil || resp.GetStatus() != want {
			t.Fatalf("health %q while waiting = %v, %v; want %v", svc, resp.GetStatus(), err, want)
		}
	}

	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("openPostgres = %v, want it to wait", o.err)
		}
		defer o.db.Close()
		if waited := time.Since(start); waited < delay {
			t.Fatalf("connected after %v, before the database was reachable", waited)
		}
		if o.ref != "dev-root-v1" {
			t.Fatalf("root ref = %q", o.ref)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("openPostgres did not finish after the database came up")
	}
}

// A missing root KEK outside dev is a misconfiguration: the boot stops at
// once instead of waiting.
func TestOpenPostgres_MissingRootKEKStopsTheBoot(t *testing.T) {
	t.Setenv("VAULT_ROOT_KEK", "")
	boot, err := server.StartBootHealth(freePort(t), log.Nop(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(boot.Stop)
	done := make(chan error, 1)
	go func() {
		_, _, _, err := openPostgres(context.Background(), boot, "postgres://vault@192.0.2.1:5432/vault", t.TempDir(), "production", "postgres://vault@192.0.2.1:5432/vault")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || postgres.Transient(err) {
			t.Fatalf("openPostgres = %v, want a permanent error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openPostgres waited on a misconfiguration")
	}
}
