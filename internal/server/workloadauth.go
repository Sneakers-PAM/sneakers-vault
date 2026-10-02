// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"google.golang.org/grpc"
)

// WorkloadAuth returns the server options that authenticate every caller
// against policy (see internal/workloadauth). It fails closed: with no
// WORKLOAD_OIDC_ISSUER it returns an error, unless WORKLOAD_AUTH=disabled, in
// which case it returns no options and warns now and every 5 minutes. before
// and after are extra unary interceptors run around the authentication one.
func WorkloadAuth(ctx context.Context, getenv func(string) string, policy workloadauth.Policy, lg log.Logger,
	before, after []grpc.UnaryServerInterceptor, opts ...workloadauth.Option) ([]grpc.ServerOption, error) {
	cfg, enabled, err := workloadauth.ServerConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	if !enabled {
		go workloadauth.WarnDisabled(ctx, lg, workloadauth.DisabledWarnInterval)
		return nil, nil
	}
	v, err := workloadauth.NewVerifier(cfg, lg)
	if err != nil {
		return nil, err
	}
	go v.Run(ctx)
	lg.Info("service-to-service authentication on",
		log.F("issuer", cfg.Issuer), log.F("audience", cfg.Audience),
		log.F("jwks_override", cfg.JWKSURL != ""), log.F("ca_file", cfg.CAFile != ""), log.F("bearer_file", cfg.BearerFile != ""),
		log.F("allowed_serviceaccounts", strings.Join(cfg.AllowedServiceAccounts, ",")))
	unary := append(append(append([]grpc.UnaryServerInterceptor{}, before...),
		workloadauth.UnaryServerInterceptor(v, policy, lg, opts...)), after...)
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, policy, lg, opts...)),
	}, nil
}

// ClientAuth returns the dial options that send this service's workload
// token (WORKLOAD_TOKEN_FILE) on every call; none when it's unset.
func ClientAuth(getenv func(string) string) ([]grpc.DialOption, error) {
	opt, ok, err := workloadauth.DialOptionFromEnv(getenv)
	if err != nil || !ok {
		return nil, err
	}
	return []grpc.DialOption{opt}, nil
}
