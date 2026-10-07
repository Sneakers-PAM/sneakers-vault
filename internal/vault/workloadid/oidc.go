// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import (
	"context"
	"errors"

	log "github.com/Bugs5382/go-log"
	workloadidentity "github.com/Bugs5382/go-workload-identity"
)

// Environment variables the OIDC verifier is configured from. They are the
// same ones the service-to-service verifier reads.
const (
	EnvIssuer                 = workloadidentity.EnvIssuer
	EnvJWKSURL                = workloadidentity.EnvJWKSURL
	EnvCAFile                 = workloadidentity.EnvCAFile
	EnvBearerFile             = workloadidentity.EnvBearerFile
	EnvAudience               = workloadidentity.EnvAudience
	EnvAllowedServiceAccounts = workloadidentity.EnvAllowedServiceAccounts
)

// DefaultAudience is the token audience required when the config has none.
const DefaultAudience = "sneakers"

// OIDCConfig configures the OIDC verifier.
type OIDCConfig = workloadidentity.Config

// OIDCVerifier checks a connector worker's Kubernetes projected
// ServiceAccount token with go-workload-identity and names the worker by its
// "<namespace>/<serviceaccount>". Safe for concurrent use.
type OIDCVerifier struct{ v *workloadidentity.Verifier }

var _ WorkloadIdentityVerifier = (*OIDCVerifier)(nil)

// NewOIDCVerifier validates cfg and builds a verifier. It fetches no keys: an
// issuer that is down at start-up leaves the verifier answering
// ErrUnavailable until Run loads a set, rather than failing the boot.
func NewOIDCVerifier(cfg OIDCConfig, logger log.Logger) (*OIDCVerifier, error) {
	if cfg.Audience == "" {
		cfg.Audience = DefaultAudience
	}
	v, err := workloadidentity.NewVerifier(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &OIDCVerifier{v: v}, nil
}

// Run loads the key set now and then every refresh interval until ctx ends.
func (o *OIDCVerifier) Run(ctx context.Context) { o.v.Run(ctx) }

// Verify checks a token and returns the worker as "<namespace>/<serviceaccount>".
// ErrUnavailable means no key set has loaded yet; any other error is a
// rejected token. The token itself is never logged.
func (o *OIDCVerifier) Verify(token string) (Principal, error) {
	c, err := o.v.Verify(token)
	switch {
	case errors.Is(err, workloadidentity.ErrUnavailable):
		return Principal{}, ErrUnavailable
	case err != nil:
		return Principal{}, err
	}
	return Principal{WorkerID: c.ServiceAccount}, nil
}
