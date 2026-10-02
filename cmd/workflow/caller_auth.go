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
