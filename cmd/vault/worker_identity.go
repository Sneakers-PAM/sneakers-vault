// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
)

// connectorVerifier picks the verifier for the connector pull-API. When
// WORKLOAD_OIDC_ISSUER is set the OIDC verifier is used in any environment,
// and its JWKS refresher runs until ctx ends. Otherwise prod gets no verifier
// at all, so verifyWorker fails closed with Unavailable, and other
// environments keep the shared dev token. The dev token is never accepted in
// prod. A malformed WORKLOAD_* config is returned as an error so boot fails.
func connectorVerifier(ctx context.Context, environment string, getenv func(string) string, logger log.Logger) (workloadid.WorkloadIdentityVerifier, error) {
	cfg, ok, err := server.WorkerConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	if ok {
		v, err := workloadid.NewOIDCVerifier(cfg, logger)
		if err != nil {
			return nil, err
		}
		go v.Run(ctx)
		logger.Info("connector worker identity: OIDC verifier",
			log.F("issuer", cfg.Issuer), log.F("audience", cfg.Audience),
			log.F("jwks_override", cfg.JWKSURL != ""), log.F("ca_file", cfg.CAFile != ""),
			log.F("bearer_file", cfg.BearerFile != ""),
			log.F("allowed_serviceaccounts", strings.Join(cfg.AllowedServiceAccounts, ",")))
		return v, nil
	}
	if environment == "prod" || environment == "production" {
		logger.Warn("connector worker identity: none configured in prod; the connector pull-API stays unavailable")
		return nil, nil
	}
	token := getenv("CONNECTOR_DEV_TOKEN")
	if token == "" {
		token = "dev-connector-token" // #nosec G101 -- the public dev-only default, never accepted in production
	}
	logger.Info("connector worker identity: dev shared-token verifier")
	return workloadid.NewDevVerifier(token), nil
}
