// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"runtime/debug"

	log "github.com/Bugs5382/go-log"

	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryUnaryInterceptor returns a grpc.UnaryServerInterceptor that recovers
// from panics raised anywhere in the downstream chain (inner interceptors and
// the handler itself). On a panic it captures the stack, logs both the
// recovered value and the stack via the context-aware logger, records the error
// on the active span, and returns a generic codes.Internal error to the caller.
//
// The panic value and stack are deliberately kept out of the returned status so
// no internal detail leaks to the client; both are only emitted to the server
// log and the trace.
//
// It must run outermost in the unary chain so it catches panics from every
// inner interceptor as well as the handler. Run wires it as the first default
// interceptor for exactly this reason.
func RecoveryUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				resp, err = nil, recoverPanic(ctx, r, info.FullMethod)
			}
		}()
		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor is the streaming counterpart of
// RecoveryUnaryInterceptor. The vault and workflow APIs are unary (only the
// health service's Watch streams), so this is defence in depth: any stream
// handler is covered too. It must run outermost in the stream chain.
func RecoveryStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = recoverPanic(ss.Context(), r, info.FullMethod)
			}
		}()
		return handler(srv, ss)
	}
}

// recoverPanic performs the shared handling for a recovered panic: it logs the
// value and stack, records the error on the active span, and returns the
// generic internal error that is safe to send to the caller.
func recoverPanic(ctx context.Context, r any, method string) error {
	stack := debug.Stack()

	logger := log.Ctx(ctx)
	logger.Error().
		Interface("panic", r).
		Str("method", method).
		Bytes("stack", stack).
		Msg("recovered from panic in grpc handler")

	span := trace.SpanFromContext(ctx)
	span.RecordError(errorFromPanic(r), trace.WithStackTrace(true))
	span.SetStatus(otelcodes.Error, "panic recovered")

	// Generic message only: never surface the panic value or stack to the caller.
	return status.Errorf(grpccodes.Internal, "internal error")
}

// errorFromPanic coerces an arbitrary recovered panic value into an error so it
// can be recorded on a span. An error value is returned as-is; anything else is
// wrapped via its default formatting.
func errorFromPanic(r any) error {
	if err, ok := r.(error); ok {
		return err
	}
	return fmt.Errorf("panic: %v", r)
}
