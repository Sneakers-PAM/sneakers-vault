// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package server provides a RunWithLogger helper that boots a gRPC server with the
// standard health + reflection services and graceful shutdown on context
// cancellation.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-mtls"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// gracefulStopTimeout bounds how long the server will wait for in-flight RPCs to
// drain before forcibly stopping the server. Without it, a hung peer could
// keep GracefulStop blocked indefinitely.
const gracefulStopTimeout = 10 * time.Second

// RunWithLogger boots a gRPC server listening on :port, registers the health
// and reflection services, calls register to attach caller-owned services,
// then serves until ctx is cancelled. On cancellation it performs a graceful
// stop and returns nil. A non-nil error indicates a fatal startup or serve
// failure. lg logs the panics the recovery interceptors catch.
//
// Optional grpc.ServerOptions (e.g. interceptors) are passed through to
// grpc.NewServer.
func RunWithLogger(ctx context.Context, port string, lg log.Logger, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealth(ctx, port, lg, nil, register, opts...)
}

// RunWithHealth is RunWithLogger with readiness taken from checker: the
// health check answers NOT_SERVING while a required dependency is down. A nil
// checker has no dependencies, so the service is always ready. A nil lg
// discards the recovery interceptors' panics.
func RunWithHealth(ctx context.Context, port string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealthTLS(ctx, port, "", nil, lg, checker, register, opts...)
}

// RunWithHealthTLS is RunWithHealth with mutual TLS on the service port when p
// is not nil: every caller must present a certificate the CA behind p signed,
// over TLS 1.3. The health service then also answers, and only it, on a plain
// listener at healthPort, because the kubelet's gRPC probe cannot present a
// certificate. A non-nil p with an empty healthPort is refused. A nil p is
// plaintext, as RunWithHealth.
func RunWithHealthTLS(ctx context.Context, port, healthPort string, p *mtls.Provider, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	if p != nil && healthPort == "" {
		return errors.New("mutual TLS is on and HEALTH_PORT is not set: the kubelet probe cannot present a certificate, so health needs its own plain port")
	}
	if lg == nil {
		lg = log.Nop()
	}
	hs, bi, err := newHealth(checker)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Build the default ServerOptions, prepended before caller-supplied opts.
	//
	//   - StatsHandler(otelgrpc): traces every service by default. Prepended so
	//     a caller StatsHandler (gRPC applies the last one) can still override.
	//   - ChainUnaryInterceptor(recovery) / StreamInterceptor(recovery): make
	//     panic recovery the OUTERMOST interceptor. grpc.ChainUnaryInterceptor
	//     is additive across ServerOptions (v1.81.x appends, no "last wins"),
	//     and the chain executes first-added-outermost. Prepending our
	//     ChainUnaryInterceptor before caller opts means recovery runs before
	//     any caller-supplied interceptor (e.g. an auth interceptor) and before the
	//     handler, so it catches panics from all of them. The otelgrpc
	//     StatsHandler still creates the server span first, so the recovery
	//     interceptor can record the panic on a live span.
	//
	// ChainStreamInterceptor is additive (like the unary chain), so a caller
	// that later supplies its own stream interceptor composes with recovery
	// rather than panicking (plain grpc.StreamInterceptor allows only one and
	// panics on a second).
	defaults := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(lg), bi.UnaryServerInterceptor(), reportUnaryInterceptor(checker)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(lg), bi.StreamServerInterceptor()),
	}
	healthOpts := append([]grpc.ServerOption(nil), defaults...)
	opts = append(defaults, opts...)
	if p != nil {
		opts = append([]grpc.ServerOption{p.ServerOption()}, opts...)
	}

	s := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(s, hs)
	reflection.Register(s)
	if register != nil {
		register(s)
	}

	biCtx, stopBI := context.WithCancel(ctx)
	defer stopBI()
	go bi.Run(biCtx)
	if checker != nil {
		go checker.Run(biCtx)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.Serve(lis); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	hsrv, err := startHealthOnly(p, healthPort, healthOpts, hs, errCh)
	if err != nil {
		s.Stop()
		return err
	}
	if p != nil {
		lg.Info("mutual TLS on: service port requires a client certificate; health is plain on its own port", log.F("port", port), log.F("health_port", healthPort))
	}

	select {
	case <-ctx.Done():
		hs.Shutdown()
		gracefulStop(s, hsrv)
		<-errCh
		return nil
	case err := <-errCh:
		if hsrv != nil {
			hsrv.Stop()
		}
		s.Stop()
		return err
	}
}

// gracefulStop drains s and the optional health-only server hsrv, forcing both
// to stop when the drain outlasts gracefulStopTimeout.
func gracefulStop(s, hsrv *grpc.Server) {
	stopped := make(chan struct{})
	go func() {
		s.GracefulStop()
		if hsrv != nil {
			hsrv.GracefulStop()
		}
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(gracefulStopTimeout):
		s.Stop()
		if hsrv != nil {
			hsrv.Stop()
		}
	}
}

// startHealthOnly serves the health service alone on a plain listener at
// healthPort when mutual TLS is on (p not nil), with the same health state and
// interceptors as the service port and nothing else registered: no reflection,
// no services. It returns a nil server when mutual TLS is off. A serve failure
// is sent to errCh.
func startHealthOnly(p *mtls.Provider, healthPort string, opts []grpc.ServerOption, hs healthpb.HealthServer, errCh chan<- error) (*grpc.Server, error) {
	if p == nil {
		return nil, nil
	}
	lis, err := net.Listen("tcp", ":"+healthPort)
	if err != nil {
		return nil, fmt.Errorf("health listen: %w", err)
	}
	srv := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(srv, hs)
	go func() {
		if err := srv.Serve(lis); err != nil {
			errCh <- fmt.Errorf("health serve: %w", err)
		}
	}()
	return srv, nil
}

// ClientStatsHandler returns the grpc.DialOption that installs the OpenTelemetry
// client stats handler on an outbound gRPC connection, so trace context is
// injected into outgoing RPC metadata and client spans are recorded.
//
//	conn, err := grpc.NewClient(target, server.ClientStatsHandler(), ...)
func ClientStatsHandler() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}
