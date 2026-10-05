// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package health decides readiness from the service's dependencies. Each
// dependency is pinged with a short timeout and the results are cached for a
// few seconds, so frequent probes don't load the dependencies. A required
// dependency that fails makes the service down; an optional one makes it
// degraded. Liveness never comes here.
package health

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// The states of a dependency and of the service as a whole.
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
	StatusDown     = "down"
)

const (
	// CacheTTL is how long a set of results is reused.
	CacheTTL = 5 * time.Second
	// CheckTimeout bounds each dependency's ping.
	CheckTimeout = time.Second
)

// Dep is one dependency. Check returns nil while it's usable.
type Dep struct {
	Name     string
	Required bool
	Check    func(context.Context) error
}

// DepStatus is a dependency's last result. Error is a class from Classify,
// never the error's text.
type DepStatus struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Required  bool   `json:"required"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checkedAt"`
	Version   string `json:"version,omitempty"`
}

// Report is the service's state and each dependency's.
type Report struct {
	Status       string      `json:"status"`
	Dependencies []DepStatus `json:"dependencies"`
}

// Checker runs the dependency checks. The zero value is not usable; use New.
type Checker struct {
	deps    []Dep
	log     log.Logger
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	last    *Report
	at      time.Time
	running chan struct{}
	states  map[string]string
}

// New returns a Checker for deps. lg gets one line per state change; nil logs
// nothing.
func New(lg log.Logger, deps ...Dep) *Checker {
	return &Checker{deps: deps, log: lg, ttl: CacheTTL, timeout: CheckTimeout, now: time.Now, states: map[string]string{}}
}

// SetCacheTTL changes how long results are reused (tests).
func (c *Checker) SetCacheTTL(d time.Duration) { c.ttl = d }

// Report returns the dependencies' state, from cache while it's fresh.
// Concurrent callers share one run of the checks.
func (c *Checker) Report(ctx context.Context) Report {
	c.mu.Lock()
	for {
		if c.last != nil && c.now().Sub(c.at) < c.ttl {
			r := *c.last
			c.mu.Unlock()
			return r
		}
		if c.running == nil {
			break
		}
		w := c.running
		c.mu.Unlock()
		<-w
		c.mu.Lock()
		if c.last != nil {
			r := *c.last
			c.mu.Unlock()
			return r
		}
	}
	w := make(chan struct{})
	c.running = w
	c.mu.Unlock()

	r := c.run(context.WithoutCancel(ctx))

	c.mu.Lock()
	c.last, c.at, c.running = &r, c.now(), nil
	c.mu.Unlock()
	close(w)
	return r
}

func (c *Checker) run(ctx context.Context) Report {
	r := Report{Status: StatusOK, Dependencies: make([]DepStatus, len(c.deps))}
	var wg sync.WaitGroup
	for i, d := range c.deps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()
			err := d.Check(cctx)
			s := DepStatus{Name: d.Name, State: StatusOK, Required: d.Required, CheckedAt: c.now().UTC().Format(time.RFC3339)}
			if err != nil {
				s.Error = Classify(err)
				s.State = StatusDegraded
				if d.Required {
					s.State = StatusDown
				}
			}
			r.Dependencies[i] = s
		}()
	}
	wg.Wait()
	for _, s := range r.Dependencies {
		switch {
		case s.State == StatusDown:
			r.Status = StatusDown
		case s.State == StatusDegraded && r.Status == StatusOK:
			r.Status = StatusDegraded
		}
		c.logChange(ctx, s)
	}
	return r
}

// logChange logs a dependency whose state differs from its last check. Run
// only from the single in-flight run, so states needs no lock of its own.
func (c *Checker) logChange(ctx context.Context, s DepStatus) {
	prev, seen := c.states[s.Name]
	c.states[s.Name] = s.State
	if c.log == nil || prev == s.State || (!seen && s.State == StatusOK) {
		return
	}
	fields := []log.Field{log.F("dependency", s.Name), log.F("required", s.Required), log.F("state", s.State)}
	if s.State == StatusOK {
		c.log.Ctx(ctx).Info("health: dependency recovered", fields...)
		return
	}
	c.log.Ctx(ctx).Warn("health: dependency failing", append(fields, log.F("error_class", s.Error))...)
}

// Classify names an error's kind from a fixed set, so the error's own text
// (which can hold a DSN or an address) never leaves the service.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable:
			return "unavailable"
		case codes.DeadlineExceeded:
			return "timeout"
		case codes.Unauthenticated, codes.PermissionDenied:
			return "unauthenticated"
		}
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return "timeout"
		}
		return "unavailable"
	}
	return "error"
}

// Pinger is a datastore client with a cheap round trip (go-postgres's DB).
type Pinger interface {
	Ping(context.Context) error
}

// Postgres is the required database dependency.
func Postgres(db Pinger) Dep {
	return Dep{Name: "postgres", Required: true, Check: db.Ping}
}

// errNotServing is a peer that answers but isn't ready.
var errNotServing = status.Error(codes.Unavailable, "peer not serving")

// GRPCPeer checks another service's readiness through its standard health
// check on an existing connection.
func GRPCPeer(name string, conn grpc.ClientConnInterface, required bool) Dep {
	hc := healthpb.NewHealthClient(conn)
	return Dep{Name: name, Required: required, Check: func(ctx context.Context) error {
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return errNotServing
		}
		return nil
	}}
}
