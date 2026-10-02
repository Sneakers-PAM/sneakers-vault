// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// callerAuth builds the interceptors that authenticate every caller against
// the vault's allow-list, audit each refusal, and give a Self caller the
// vault's own actor for it. It fails closed (see server.WorkloadAuth).
func callerAuth(ctx context.Context, getenv func(string) string, lg log.Logger, srv *grpcsvc.Server) ([]grpc.ServerOption, error) {
	return server.WorkloadAuth(ctx, getenv, grpcsvc.CallerPolicy(), lg,
		[]grpc.UnaryServerInterceptor{grpcsvc.RequestContextUnary},
		[]grpc.UnaryServerInterceptor{srv.SelfActorUnary},
		workloadauth.WithDenyHook(srv.AuditDenial))
}

// mustWorkloadAuthConfig exits when service-to-service authentication isn't
// configured and wasn't explicitly disabled.
func mustWorkloadAuthConfig(logger zerolog.Logger) {
	if _, _, err := workloadauth.ServerConfigFromEnv(os.Getenv); err != nil {
		logger.Fatal().Err(err).Msg("workload auth config")
	}
}

// mustDialOptions returns the options for the vault's outbound calls (audit,
// notify): plaintext, traced, and carrying the vault's workload token when
// WORKLOAD_TOKEN_FILE is set. A set but unreadable token file exits.
func mustDialOptions(logger zerolog.Logger) []grpc.DialOption {
	auth, err := server.ClientAuth(os.Getenv)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload token")
	}
	return append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler()}, auth...)
}
