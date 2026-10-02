// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Environment variables read by OIDCConfigFromEnv.
const (
	EnvIssuer                 = "WORKLOAD_OIDC_ISSUER"
	EnvJWKSURL                = "WORKLOAD_OIDC_JWKS_URL"
	EnvCAFile                 = "WORKLOAD_OIDC_CA_FILE"
	EnvBearerFile             = "WORKLOAD_OIDC_BEARER_FILE" // #nosec G101 -- an environment variable name, not a credential
	EnvAudience               = "WORKLOAD_AUDIENCE"
	EnvAllowedServiceAccounts = "WORKLOAD_ALLOWED_SERVICEACCOUNTS"
)

// DefaultAudience is the token audience required when WORKLOAD_AUDIENCE is unset.
const DefaultAudience = "sneakers-vault"

// OIDCConfig configures the OIDC verifier.
type OIDCConfig struct {
	// Issuer must equal the token's iss exactly.
	Issuer string
	// JWKSURL overrides discovery via <Issuer>/.well-known/openid-configuration.
	JWKSURL string
	// CAFile is an extra PEM bundle trusted for the discovery and JWKS fetch.
	CAFile string
	// BearerFile holds a token sent on the discovery and JWKS fetch. It is
	// re-read on every fetch because projected tokens rotate in place.
	BearerFile string
	// Audience must appear in the token's aud.
	Audience string
	// AllowedServiceAccounts are "<namespace>/<serviceaccount>" entries.
	AllowedServiceAccounts []string
}

// OIDCConfigFromEnv reads the WORKLOAD_* variables. ok is false when
// WORKLOAD_OIDC_ISSUER is unset, meaning the verifier is not configured. A
// set issuer with a missing or malformed value elsewhere is an error, so a
// typo fails startup instead of silently denying every worker.
func OIDCConfigFromEnv(getenv func(string) string) (cfg OIDCConfig, ok bool, err error) {
	raw := getenv(EnvIssuer)
	if raw == "" {
		return OIDCConfig{}, false, nil
	}
	cfg = OIDCConfig{
		Issuer:     strings.TrimSpace(raw),
		JWKSURL:    strings.TrimSpace(getenv(EnvJWKSURL)),
		CAFile:     strings.TrimSpace(getenv(EnvCAFile)),
		BearerFile: strings.TrimSpace(getenv(EnvBearerFile)),
		Audience:   strings.TrimSpace(getenv(EnvAudience)),
	}
	if cfg.Audience == "" {
		cfg.Audience = DefaultAudience
	}
	cfg.AllowedServiceAccounts, err = parseAllowed(getenv(EnvAllowedServiceAccounts))
	if err != nil {
		return OIDCConfig{}, false, err
	}
	if err := cfg.validate(); err != nil {
		return OIDCConfig{}, false, err
	}
	return cfg, true, nil
}

func (c OIDCConfig) validate() error {
	if err := requireHTTPS(EnvIssuer, c.Issuer); err != nil {
		return err
	}
	if c.JWKSURL != "" {
		if err := requireHTTPS(EnvJWKSURL, c.JWKSURL); err != nil {
			return err
		}
	}
	if c.Audience == "" {
		return fmt.Errorf("workloadid: %s is empty", EnvAudience)
	}
	if len(c.AllowedServiceAccounts) == 0 {
		return fmt.Errorf("workloadid: %s is required when %s is set", EnvAllowedServiceAccounts, EnvIssuer)
	}
	for _, e := range c.AllowedServiceAccounts {
		if err := checkEntry(e); err != nil {
			return err
		}
	}
	return nil
}

// requireHTTPS rejects plain-http key sources: whoever can rewrite the JWKS
// in transit can mint any worker identity.
func requireHTTPS(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("workloadid: %s must be an absolute https URL, got %q", name, raw)
	}
	return nil
}

func parseAllowed(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("workloadid: %s is required when %s is set", EnvAllowedServiceAccounts, EnvIssuer)
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if err := checkEntry(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

var errEntry = errors.New("must be <namespace>/<serviceaccount>")

func checkEntry(e string) error {
	ns, sa, found := strings.Cut(e, "/")
	if !found || ns == "" || sa == "" || strings.ContainsAny(e, ": \t") || strings.Contains(sa, "/") {
		return fmt.Errorf("workloadid: %s entry %q %w", EnvAllowedServiceAccounts, e, errEntry)
	}
	return nil
}
