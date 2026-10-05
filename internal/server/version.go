// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"sync"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/buildinfo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// The response headers a health check carries, read by the gateway's
// diagnostics. A dependency's version goes in HeaderDependencyPrefix plus its
// name (sneakers-dep-postgres).
const (
	HeaderVersion          = "sneakers-version"
	HeaderCommit           = "sneakers-commit"
	HeaderDependencyPrefix = "sneakers-dep-"
)

// DependencyPostgres names the database in SetDependencyVersion.
const DependencyPostgres = "postgres"

const (
	healthCheckMethod    = "/grpc.health.v1.Health/Check"
	maxDependencyVersion = 64
)

var (
	depMu       sync.RWMutex
	depVersions = map[string]string{}
)

// SetDependencyVersion records the version of a dependency (a database or a
// broker this service connects to) for the health check headers, as
// sneakers-dep-<name>. Only the first token is kept ("16.4" from
// "16.4 (Debian ...)"), capped at 64 characters; an empty value removes it.
func SetDependencyVersion(name, raw string) {
	v := ""
	if f := strings.Fields(raw); len(f) > 0 {
		v = f[0]
	}
	if len(v) > maxDependencyVersion {
		v = v[:maxDependencyVersion]
	}
	depMu.Lock()
	defer depMu.Unlock()
	if v == "" {
		delete(depVersions, name)
		return
	}
	depVersions[name] = v
}

// DependencyVersion returns the version SetDependencyVersion recorded for
// name, or "".
func DependencyVersion(name string) string {
	depMu.RLock()
	defer depMu.RUnlock()
	return depVersions[name]
}

// VersionUnaryInterceptor adds the build's version and commit, and every
// known dependency version, to the response headers of every health check.
// Other calls are untouched.
func VersionUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == healthCheckMethod {
			v, c := buildinfo.Info()
			md := metadata.Pairs(HeaderVersion, v, HeaderCommit, c)
			depMu.RLock()
			for name, dv := range depVersions {
				md.Set(HeaderDependencyPrefix+name, dv)
			}
			depMu.RUnlock()
			_ = grpc.SetHeader(ctx, md)
		}
		return handler(ctx, req)
	}
}

// RecordPostgresVersion reads the database server's version once and records
// it as the postgres dependency for the health check headers. On error nothing is recorded; the caller
// logs it and carries on.
func RecordPostgresVersion(ctx context.Context, q postgres.Querier) error {
	var v string
	if err := q.QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return err
	}
	SetDependencyVersion(DependencyPostgres, v)
	return nil
}
