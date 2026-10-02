// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workflow/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// callerAuth builds the interceptors that authenticate every caller against
// the workflow's allow-list (the gateway only). It fails closed (see
// server.WorkloadAuth).
func callerAuth(ctx context.Context, getenv func(string) string, lg log.Logger) ([]grpc.ServerOption, error) {
	return server.WorkloadAuth(ctx, getenv, grpcsvc.CallerPolicy(), lg, nil, nil)
}

// mustWorkloadAuthConfig exits when service-to-service authentication isn't
// configured and wasn't explicitly disabled.
func mustWorkloadAuthConfig(logger zerolog.Logger) {
	if _, _, err := workloadauth.ServerConfigFromEnv(os.Getenv); err != nil {
		logger.Fatal().Err(err).Msg("workload auth config")
	}
}

// mustCallerAuth is callerAuth with the process environment, exiting on error.
func mustCallerAuth(ctx context.Context, logger zerolog.Logger, lg log.Logger) []grpc.ServerOption {
	opts, err := callerAuth(ctx, os.Getenv, lg)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload auth")
	}
	return opts
}

// mustDialAudit connects to the audit service (AUDIT_ADDR, default
// localhost:9194) with the workflow's workload token. The connection is lazy,
// so an audit service that is down doesn't stop the boot; events are then
// only logged.
func mustDialAudit(logger zerolog.Logger) *grpc.ClientConn {
	auth, err := server.ClientAuth(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload token")
	}
	addr := os.Getenv("AUDIT_ADDR")
	if addr == "" {
		addr = "localhost:9194"
	}
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler()}, auth...)...)
	if err != nil {
		logger.Fatal().Err(err).Str("audit", addr).Msg("dial audit")
	}
	return conn
}
