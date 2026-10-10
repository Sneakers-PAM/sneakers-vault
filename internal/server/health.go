// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HeaderPrefix starts every build and dependency header a health check
// carries: sneakers-version, sneakers-commit, sneakers-dep-<name> and
// sneakers-depstate-<name>. The gateway's diagnostics read them.
const HeaderPrefix = "sneakers"

// HeaderHealth carries the readiness report (health.Report as JSON) on a
// readiness check's response.
const HeaderHealth = "sneakers-health"

// LivenessService is the health service name the liveness probe asks for. It
// answers SERVING while the process does, whatever its dependencies.
const LivenessService = "liveness"

// CacheTTL is how long a check's result is reused; CheckTimeout bounds each
// check.
const (
	CacheTTL     = 5 * time.Second
	CheckTimeout = time.Second
)

const maxDependencyVersion = 64

// NewChecker returns the readiness checker over deps. Each check's error is
// tagged with one of the classes the gateway's diagnostics know (refused,
// unavailable, unauthenticated) where go-buildinfo's own class would differ.
// opts follow the defaults, so a test can shorten the TTL.
//
// Probes only read the checker's cache: RunWithHealth runs the checks in the
// background once per CacheTTL, so a slow dependency never makes a probe
// wait. Until the first pass settles, each dependency is down with the class
// "pending".
func NewChecker(lg log.Logger, deps []health.Dependency, opts ...health.Option) (*health.Checker, error) {
	c := health.New(append([]health.Option{health.WithBackgroundRefresh(), health.WithTTL(CacheTTL), health.WithTimeout(CheckTimeout), health.WithLogger(lg)}, opts...)...)
	for i := range deps {
		if deps[i].Check != nil {
			deps[i].Check = classified(deps[i].Check)
		}
	}
	return c, c.Register(deps...)
}

func classified(check func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		err := check(ctx)
		if c := classOf(err); c != "" {
			return health.Classify(err, c)
		}
		return err
	}
}

// classOf is the class for errors go-buildinfo would report differently, ""
// to keep its own (timeout, error).
func classOf(err error) string {
	var gs interface{ GRPCStatus() *status.Status }
	var ne net.Error
	switch {
	case err == nil, errors.Is(err, context.DeadlineExceeded):
		return ""
	case errors.Is(err, os.ErrDeadlineExceeded):
		return health.ClassTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.As(err, &gs):
		switch gs.GRPCStatus().Code() {
		case codes.DeadlineExceeded:
			return health.ClassTimeout
		case codes.Unavailable:
			return "unavailable"
		case codes.Unauthenticated, codes.PermissionDenied:
			return "unauthenticated"
		}
		return health.ClassError
	case errors.As(err, &ne):
		if ne.Timeout() {
			return health.ClassTimeout
		}
		return "unavailable"
	}
	return ""
}

// errNotServing is a peer that answers but isn't ready.
var errNotServing = status.Error(codes.Unavailable, "peer not serving")

// GRPCPeer checks another service's readiness through its standard health
// check on an existing connection.
func GRPCPeer(name string, conn grpc.ClientConnInterface, required bool) health.Dependency {
	hc := healthpb.NewHealthClient(conn)
	return health.Dependency{Name: name, Required: required, Check: func(ctx context.Context) error {
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

// Database is a datastore client with a cheap round trip and a query
// interface (go-postgres's DB).
type Database interface {
	Ping(context.Context) error
	Querier() postgres.Querier
}

// Postgres is the required database dependency: a ping, and the server's
// version for the sneakers-dep-postgres header.
func Postgres(db Database) health.Dependency {
	return health.Dependency{Name: "postgres", Required: true, Check: db.Ping, Version: PostgresVersion(db.Querier())}
}

// PostgresVersion reads the database server's version for the
// sneakers-dep-postgres header: the first token of SHOW server_version ("16.4"
// from "16.4 (Debian ...)"), at most 64 characters.
func PostgresVersion(q postgres.Querier) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var raw string
		if err := q.QueryRow(ctx, "SHOW server_version").Scan(&raw); err != nil {
			return "", err
		}
		return dependencyVersion(raw), nil
	}
}

func dependencyVersion(raw string) string {
	v := ""
	if f := strings.Fields(raw); len(f) > 0 {
		v = f[0]
	}
	if len(v) > maxDependencyVersion {
		v = v[:maxDependencyVersion]
	}
	return v
}

// newHealth wires grpc.health.v1 to go-buildinfo: service "" is readiness,
// which follows checker; LivenessService is the process only; anything else is
// NotFound. A nil checker is always ready.
func newHealth(checker *health.Checker) (*grpchealth.Server, *grpcbuildinfo.Server, error) {
	hs := grpchealth.NewServer()
	opts := []grpcbuildinfo.Option{
		grpcbuildinfo.WithPrefix(HeaderPrefix),
		grpcbuildinfo.WithHealthServer(hs),
		grpcbuildinfo.WithLivenessService(LivenessService),
	}
	if checker != nil {
		opts = append(opts, grpcbuildinfo.WithChecker(checker))
	}
	bi, err := grpcbuildinfo.New(opts...)
	return hs, bi, err
}

const healthCheckMethod = "/grpc.health.v1.Health/Check"

// reportUnaryInterceptor adds the sneakers-health header to a readiness
// check's answer. The checker caches its report, so this costs no extra check.
func reportUnaryInterceptor(checker *health.Checker) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if r, ok := req.(*healthpb.HealthCheckRequest); ok && info.FullMethod == healthCheckMethod && r.GetService() == "" {
			rep := health.Report{Status: health.StateOK, Ready: true, Dependencies: []health.DependencyReport{}}
			if checker != nil {
				rep = checker.Report(ctx)
			}
			if b, err := json.Marshal(rep); err == nil {
				_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(b)))
			}
		}
		return handler(ctx, req)
	}
}
