// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"
)

// The token audience and the service-account prefix every Sneakers service
// uses. go-workload-identity has no defaults for either, so they are set here.
const (
	// WorkloadAudience is the audience required when WORKLOAD_AUDIENCE is unset.
	WorkloadAudience = "sneakers"
	// WorkloadServiceAccountPrefix is stripped from a service account to give
	// the caller name: "sneakers-gateway" is the caller "gateway".
	WorkloadServiceAccountPrefix = "sneakers-"
)

// WorkloadConfigFromEnv reads the WORKLOAD_* variables for a callee, failing
// closed like workloadauth.ServerConfigFromEnv. WORKLOAD_AUDIENCE defaults to
// WorkloadAudience and the caller name always drops
// WorkloadServiceAccountPrefix; WORKLOAD_SERVICEACCOUNT_PREFIX is not read.
func WorkloadConfigFromEnv(getenv func(string) string) (workloadauth.Config, bool, error) {
	cfg, enabled, err := workloadauth.ServerConfigFromEnv(withWorkloadAudience(getenv))
	if err != nil || !enabled {
		return cfg, enabled, err
	}
	cfg.ServiceAccountPrefix = WorkloadServiceAccountPrefix
	return cfg, true, nil
}

// WorkerConfigFromEnv is WorkloadConfigFromEnv without the WORKLOAD_AUTH
// switch: ok is false when WORKLOAD_OIDC_ISSUER is unset.
func WorkerConfigFromEnv(getenv func(string) string) (workloadauth.Config, bool, error) {
	cfg, ok, err := workloadauth.ConfigFromEnv(withWorkloadAudience(getenv))
	if err != nil || !ok {
		return cfg, ok, err
	}
	cfg.ServiceAccountPrefix = WorkloadServiceAccountPrefix
	return cfg, true, nil
}

func withWorkloadAudience(getenv func(string) string) func(string) string {
	return func(k string) string {
		switch k {
		case workloadauth.EnvAudience:
			if v := getenv(k); strings.TrimSpace(v) != "" {
				return v
			}
			return WorkloadAudience
		case workloadauth.EnvServiceAccountPrefix:
			return ""
		}
		return getenv(k)
	}
}

// WorkloadAuth returns the verifier it built (nil when authentication is
// disabled, for WorkloadIdentity) and the server options that authenticate
// every caller against policy (see github.com/Bugs5382/go-workload-identity).
// It fails closed: with no WORKLOAD_OIDC_ISSUER it returns an error, unless
// WORKLOAD_AUTH=disabled, in which case it returns no verifier or options and
// warns now and every 5 minutes. before and after are extra unary
// interceptors run around the authentication one.
func WorkloadAuth(ctx context.Context, getenv func(string) string, policy workloadauth.Policy, lg log.Logger,
	before, after []grpc.UnaryServerInterceptor, opts ...workloadauth.Option) (*workloadauth.Verifier, []grpc.ServerOption, error) {
	cfg, enabled, err := WorkloadConfigFromEnv(getenv)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		go workloadauth.WarnDisabled(ctx, lg, workloadauth.DisabledWarnInterval)
		return nil, nil, nil
	}
	v, err := workloadauth.NewVerifier(cfg, lg)
	if err != nil {
		return nil, nil, err
	}
	go v.Run(ctx)
	lg.Info("service-to-service authentication on",
		log.F("issuer", cfg.Issuer), log.F("audience", cfg.Audience),
		log.F("jwks_override", cfg.JWKSURL != ""), log.F("ca_file", cfg.CAFile != ""), log.F("bearer_file", cfg.BearerFile != ""),
		log.F("allowed_serviceaccounts", strings.Join(cfg.AllowedServiceAccounts, ",")))
	unary := append(append(append([]grpc.UnaryServerInterceptor{}, before...),
		workloadauth.UnaryServerInterceptor(v, policy, lg, opts...)), after...)
	return v, []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, policy, lg, opts...)),
	}, nil
}

// ReadinessVerifier reports whether a caller verifier's key set has loaded,
// the contract go-workload-identity's Verifier.Ready gives.
type ReadinessVerifier interface {
	Ready() error
}

// WorkloadIdentity is the required dependency over a caller verifier: no
// caller can be checked before its key set has loaded, so readiness answers
// NOT_SERVING until then (see go-workload-identity's Verifier.Ready). Callers
// build it only when v is non-nil (WORKLOAD_AUTH is not disabled).
func WorkloadIdentity(v ReadinessVerifier) health.Dependency {
	return health.Dependency{Name: "workload-identity", Required: true, Check: func(context.Context) error {
		return v.Ready()
	}}
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
