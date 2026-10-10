// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// ClassPending is the error class of a dependency the boot has not reached
// or tried yet.
const ClassPending = "pending"

// BootHealth answers the health service on the service's port while main
// waits for its dependencies at startup, before the real server exists:
// liveness is SERVING, so the startup and liveness probes pass and nothing
// restarts the process; readiness is NOT_SERVING, and its sneakers-health
// report lists every dependency the boot waits for. Stop it before
// RunWithHealth binds the same port.
type BootHealth struct {
	srv  *grpc.Server
	lg   log.Logger
	done chan struct{}
	once sync.Once

	mu   sync.Mutex
	deps []health.DependencyReport
}

// StartBootHealth listens on :port and serves the boot health service. deps
// names the required dependencies the boot waits for, in order; each starts
// down with the class "pending".
func StartBootHealth(port string, lg log.Logger, deps ...string) (*BootHealth, error) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("boot health listen: %w", err)
	}
	hs := grpchealth.NewServer()
	bi, err := grpcbuildinfo.New(grpcbuildinfo.WithPrefix(HeaderPrefix), grpcbuildinfo.WithHealthServer(hs), grpcbuildinfo.WithLivenessService(LivenessService))
	if err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("boot health: %w", err)
	}
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	b := &BootHealth{lg: lg, done: make(chan struct{})}
	for _, name := range deps {
		b.deps = append(b.deps, health.DependencyReport{Name: name, Required: true, State: health.StateDown, Error: ClassPending})
	}
	b.srv = grpc.NewServer(grpc.ChainUnaryInterceptor(bi.UnaryServerInterceptor(), b.reportInterceptor()))
	healthpb.RegisterHealthServer(b.srv, hs)
	go func() {
		defer close(b.done)
		if err := b.srv.Serve(lis); err != nil {
			lg.Warn("boot health server stopped", log.F("error", err.Error()))
		}
	}()
	lg.Info("boot health serving; waiting for dependencies", log.F("port", port), log.F("dependencies", len(deps)))
	return b, nil
}

// Waiting records a failed attempt to reach name: it stays down, with the
// error's class (never the error text).
func (b *BootHealth) Waiting(name string, err error) {
	b.set(name, health.StateDown, bootClass(err))
}

// RetryHook is the hook for a startup wait on name (go-postgres' or
// go-redis' WithRetryHook): each failed attempt logs one warning, with the
// attempt, the wait that follows and the error, and is recorded as Waiting.
func (b *BootHealth) RetryHook(name string) func(attempt int, err error, delay time.Duration) {
	return func(attempt int, err error, delay time.Duration) {
		b.lg.Warn("dependency not reachable yet; retrying", log.F("dependency", name), log.F("attempt", attempt),
			log.F("retry_in", delay.String()), log.F("error", err.Error()))
		b.Waiting(name, err)
	}
}

// Up records that name is reachable.
func (b *BootHealth) Up(name string) {
	b.set(name, health.StateOK, "")
}

// Stop shuts the boot server down and frees the port. It is safe to call
// more than once.
func (b *BootHealth) Stop() {
	b.once.Do(func() {
		stopped := make(chan struct{})
		go func() { b.srv.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			b.srv.Stop()
		}
		<-b.done
		b.lg.Info("boot health stopped; dependencies reached")
	})
}

func (b *BootHealth) set(name string, st health.State, class string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.deps {
		if b.deps[i].Name == name {
			b.deps[i].State, b.deps[i].Error, b.deps[i].CheckedAt = st, class, time.Now().UTC()
			return
		}
	}
}

func (b *BootHealth) report() health.Report {
	b.mu.Lock()
	defer b.mu.Unlock()
	return health.Report{Status: health.StateDown, Ready: false, Dependencies: append([]health.DependencyReport(nil), b.deps...)}
}

func (b *BootHealth) reportInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if r, ok := req.(*healthpb.HealthCheckRequest); ok && info.FullMethod == healthCheckMethod && r.GetService() == "" {
			if raw, err := json.Marshal(b.report()); err == nil {
				_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(raw)))
			}
		}
		return handler(ctx, req)
	}
}

// bootClass is the class a failed boot attempt reports, in the same terms as
// the readiness checks.
func bootClass(err error) string {
	if c := classOf(err); c != "" {
		return c
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return health.ClassTimeout
	}
	return health.ClassError
}
