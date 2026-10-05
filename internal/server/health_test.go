// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-vault/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// startWithHealth serves RunWithHealth on a free port and returns a health
// client.
func startWithHealth(t *testing.T, checker *health.Checker) healthpb.HealthClient {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, nil, checker, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := healthpb.NewHealthClient(conn)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "liveness"}); err == nil {
			return c
		} else if time.Now().After(deadline) {
			t.Fatalf("server never answered: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHealth_ReadinessFollowsRequiredDependencyLivenessDoesNot(t *testing.T) {
	var down atomic.Bool
	checker := health.New(nil,
		health.Dep{Name: "postgres", Required: true, Check: func(context.Context) error {
			if down.Load() {
				return errors.New("dial tcp db.example.test:5432: refused; password=hunter2")
			}
			return nil
		}},
		health.Dep{Name: "audit", Check: func(context.Context) error { return nil }},
	)
	checker.SetCacheTTL(10 * time.Millisecond)
	SetDependencyVersion(DependencyPostgres, "17.11")
	t.Cleanup(func() { SetDependencyVersion(DependencyPostgres, "") })
	c := startWithHealth(t, checker)

	ready := func() (healthpb.HealthCheckResponse_ServingStatus, string) {
		t.Helper()
		var hdr metadata.MD
		resp, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{}, grpc.Header(&hdr))
		if err != nil {
			t.Fatal(err)
		}
		if got := hdr.Get(HeaderVersion); len(got) != 1 {
			t.Fatalf("the build headers must stay: %v", hdr)
		}
		h := hdr.Get(HeaderHealth)
		if len(h) != 1 {
			t.Fatalf("no %s header: %v", HeaderHealth, hdr)
		}
		return resp.GetStatus(), h[0]
	}
	live := func() healthpb.HealthCheckResponse_ServingStatus {
		t.Helper()
		resp, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "liveness"})
		if err != nil {
			t.Fatal(err)
		}
		return resp.GetStatus()
	}

	st, body := ready()
	if st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("healthy readiness = %v", st)
	}
	var rep struct {
		Status       string
		Dependencies []struct {
			Name, State, Error, CheckedAt, Version string
			Required                               bool
		}
	}
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatalf("%s is not JSON: %v (%s)", HeaderHealth, err, body)
	}
	if rep.Status != "ok" || len(rep.Dependencies) != 2 || rep.Dependencies[0].Name != "postgres" ||
		!rep.Dependencies[0].Required || rep.Dependencies[0].Version != "17.11" || rep.Dependencies[0].CheckedAt == "" {
		t.Fatalf("health body = %s", body)
	}

	down.Store(true)
	time.Sleep(20 * time.Millisecond)
	st, body = ready()
	if st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness with postgres down = %v (%s)", st, body)
	}
	if !strings.Contains(body, `"state":"down"`) || strings.Contains(body, "hunter2") || strings.Contains(body, "example.test") {
		t.Fatalf("health body = %s", body)
	}
	if got := live(); got != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness with postgres down = %v", got)
	}

	down.Store(false)
	time.Sleep(20 * time.Millisecond)
	if st, body := ready(); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness after recovery = %v (%s)", st, body)
	}
}

func TestHealth_OptionalDependencyKeepsServing(t *testing.T) {
	checker := health.New(nil, health.Dep{Name: "notify", Check: func(context.Context) error { return status.Error(codes.Unavailable, "x") }})
	c := startWithHealth(t, checker)
	var hdr metadata.MD
	resp, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{}, grpc.Header(&hdr))
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	if h := hdr.Get(HeaderHealth); len(h) != 1 || !strings.Contains(h[0], `"status":"degraded"`) {
		t.Fatalf("header = %v", h)
	}
}

func TestHealth_UnknownServiceAndWatch(t *testing.T) {
	c := startWithHealth(t, nil)
	if _, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown service: %v", err)
	}
	if resp, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("no checker: resp=%v err=%v", resp, err)
	}
	stream, err := c.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("watch: %v", err)
	}
}
