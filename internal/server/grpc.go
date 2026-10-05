// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package server provides a Run helper that boots a gRPC server with the
// standard health + reflection services and graceful shutdown on context
// cancellation.
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/health"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// gracefulStopTimeout bounds how long Run will wait for in-flight RPCs to
// drain before forcibly stopping the server. Without it, a hung peer could
// keep GracefulStop blocked indefinitely.
const gracefulStopTimeout = 10 * time.Second

// Run boots a gRPC server listening on :port, registers the health and
// reflection services, calls register to attach caller-owned services, then
// serves until ctx is cancelled. On cancellation it performs a graceful stop
// and returns nil. A non-nil error indicates a fatal startup or serve failure.
//
// Optional grpc.ServerOptions (e.g. interceptors) are passed through to
// grpc.NewServer; callers that pass none get the previous behaviour.
func Run(ctx context.Context, port string, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithLogger(ctx, port, log.Nop(), register, opts...)
}

// RunWithLogger is Run with lg logging the panics the recovery interceptors
// catch. Run itself discards them.
func RunWithLogger(ctx context.Context, port string, lg log.Logger, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealth(ctx, port, lg, nil, register, opts...)
}

// RunWithHealth is RunWithLogger with readiness taken from checker: the
// health check answers NOT_SERVING while a required dependency is down. A nil
// checker has no dependencies, so the service is always ready. A nil lg
// discards the recovery interceptors' panics.
func RunWithHealth(ctx context.Context, port string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	if lg == nil {
		lg = log.Nop()
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
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(lg), VersionUnaryInterceptor()),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(lg)),
	}
	opts = append(defaults, opts...)

	s := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(s, newHealthServer(checker))
	reflection.Register(s)
	if register != nil {
		register(s)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := s.Serve(lis); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			s.Stop()
		}
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

// ClientStatsHandler returns the grpc.DialOption that installs the OpenTelemetry
// client stats handler on an outbound gRPC connection, so trace context is
// injected into outgoing RPC metadata and client spans are recorded.
//
//	conn, err := grpc.NewClient(target, server.ClientStatsHandler(), ...)
func ClientStatsHandler() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}
