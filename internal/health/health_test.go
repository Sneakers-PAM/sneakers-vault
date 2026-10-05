// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// switchable is a dependency whose failure the test flips mid-test.
type switchable struct {
	err   atomic.Pointer[error]
	calls atomic.Int32
}

func (s *switchable) set(err error) { s.err.Store(&err) }
func (s *switchable) check(context.Context) error {
	s.calls.Add(1)
	if p := s.err.Load(); p != nil {
		return *p
	}
	return nil
}

func newChecker(c *clock, deps ...Dep) *Checker {
	ch := New(nil, deps...)
	ch.now = c.now
	return ch
}

func stateOf(r Report, name string) DepStatus {
	for _, d := range r.Dependencies {
		if d.Name == name {
			return d
		}
	}
	return DepStatus{}
}

func TestRequiredDependencyDownThenRecovers(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	pg := &switchable{}
	ch := newChecker(c, Dep{Name: "postgres", Required: true, Check: pg.check})

	if r := ch.Report(context.Background()); r.Status != StatusOK || stateOf(r, "postgres").State != StatusOK {
		t.Fatalf("healthy: %+v", r)
	}
	pg.set(errors.New("dial tcp db.example.test:5432: connect: connection refused password=hunter2"))
	if r := ch.Report(context.Background()); r.Status != StatusOK {
		t.Fatalf("inside the cache window the last result must be reused: %+v", r)
	}
	c.add(CacheTTL)
	r := ch.Report(context.Background())
	if r.Status != StatusDown {
		t.Fatalf("required dep failing: status %q, want down", r.Status)
	}
	d := stateOf(r, "postgres")
	if d.State != StatusDown || !d.Required || d.Error != "error" || d.CheckedAt != "2026-10-05T12:00:05Z" {
		t.Fatalf("dep = %+v", d)
	}
	pg.set(nil)
	if r := ch.Report(context.Background()); r.Status != StatusDown {
		t.Fatalf("recovery must wait for the cache window: %+v", r)
	}
	c.add(CacheTTL)
	if r := ch.Report(context.Background()); r.Status != StatusOK || stateOf(r, "postgres").Error != "" {
		t.Fatalf("recovered: %+v", r)
	}
}

func TestOptionalDependencyDegrades(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	audit := &switchable{}
	audit.set(status.Error(codes.Unavailable, "connection error: desc = transport: dial audit.example.test"))
	ch := newChecker(c,
		Dep{Name: "postgres", Required: true, Check: func(context.Context) error { return nil }},
		Dep{Name: "audit", Check: audit.check},
	)
	r := ch.Report(context.Background())
	if r.Status != StatusDegraded {
		t.Fatalf("status %q, want degraded", r.Status)
	}
	if d := stateOf(r, "audit"); d.State != StatusDegraded || d.Required || d.Error != "unavailable" {
		t.Fatalf("audit = %+v", d)
	}
}

func TestChecksTimeOutAndShareOneRun(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	slow := &switchable{}
	ch := newChecker(c, Dep{Name: "postgres", Required: true, Check: func(ctx context.Context) error {
		_ = slow.check(ctx)
		<-ctx.Done()
		return ctx.Err()
	}})
	ch.timeout = 50 * time.Millisecond
	var wg sync.WaitGroup
	reports := make([]Report, 8)
	for i := range reports {
		wg.Add(1)
		go func(i int) { defer wg.Done(); reports[i] = ch.Report(context.Background()) }(i)
	}
	wg.Wait()
	if n := slow.calls.Load(); n != 1 {
		t.Fatalf("concurrent probes ran the check %d times, want 1", n)
	}
	for _, r := range reports {
		if r.Status != StatusDown || stateOf(r, "postgres").Error != "timeout" {
			t.Fatalf("report = %+v", r)
		}
	}
}

func TestNoDependenciesIsOK(t *testing.T) {
	if r := New(nil).Report(context.Background()); r.Status != StatusOK || r.Dependencies == nil {
		t.Fatalf("report = %+v", r)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]error{
		"":                nil,
		"timeout":         fmt.Errorf("ping: %w", context.DeadlineExceeded),
		"refused":         &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		"unavailable":     status.Error(codes.Unavailable, "down"),
		"unauthenticated": status.Error(codes.PermissionDenied, "no"),
		"error":           errors.New("something odd"),
	}
	for want, err := range cases {
		if got := Classify(err); got != want {
			t.Errorf("Classify(%v) = %q, want %q", err, got, want)
		}
	}
	if got := Classify(status.Error(codes.DeadlineExceeded, "slow")); got != "timeout" {
		t.Errorf("grpc deadline = %q", got)
	}
	if got := Classify(&net.DNSError{Err: "no such host", Name: "db.example.test"}); got != "unavailable" {
		t.Errorf("dns = %q", got)
	}
	if strings.Contains(Classify(errors.New("password=hunter2")), "hunter2") {
		t.Error("the class must never carry the error text")
	}
}
