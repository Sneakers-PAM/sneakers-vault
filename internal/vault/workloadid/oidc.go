// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const (
	// DefaultRefreshInterval is how often Run refetches the JWKS.
	DefaultRefreshInterval = 15 * time.Minute
	unknownKidRefreshEvery = 30 * time.Second
	clockSkew              = 60 * time.Second
	fetchTimeout           = 10 * time.Second
	saSubjectPrefix        = "system:serviceaccount:"
)

var allowedMethods = []string{"RS256", "ES256"}

var errRejected = errors.New("workloadid: token rejected")

// OIDCOption tunes an OIDCVerifier, mostly for tests.
type OIDCOption func(*OIDCVerifier)

// WithClock replaces time.Now for token time checks and the refresh rate limit.
func WithClock(now func() time.Time) OIDCOption { return func(v *OIDCVerifier) { v.now = now } }

// WithRefreshInterval replaces DefaultRefreshInterval for Run.
func WithRefreshInterval(d time.Duration) OIDCOption {
	return func(v *OIDCVerifier) { v.interval = d }
}

// OIDCVerifier checks Kubernetes projected ServiceAccount tokens against the
// issuer's JWKS and an exact allow-list of service accounts. Safe for
// concurrent use.
type OIDCVerifier struct {
	cfg      OIDCConfig
	allowed  map[string]struct{}
	keys     *jwksCache
	log      zerolog.Logger
	now      func() time.Time
	interval time.Duration
}

var _ WorkloadIdentityVerifier = (*OIDCVerifier)(nil)

// NewOIDCVerifier validates cfg and builds a verifier. It does not fetch keys:
// an issuer that is down at startup leaves the verifier answering
// ErrUnavailable until a fetch succeeds, rather than failing the boot.
func NewOIDCVerifier(cfg OIDCConfig, logger zerolog.Logger, opts ...OIDCOption) (*OIDCVerifier, error) {
	if cfg.Audience == "" {
		cfg.Audience = DefaultAudience
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client, err := fetchClient(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	if cfg.BearerFile != "" {
		if _, err := readBearer(cfg.BearerFile); err != nil {
			return nil, err
		}
	}
	v := &OIDCVerifier{
		cfg:      cfg,
		allowed:  make(map[string]struct{}, len(cfg.AllowedServiceAccounts)),
		log:      logger.With().Str("component", "workloadid.oidc").Logger(),
		now:      time.Now,
		interval: DefaultRefreshInterval,
	}
	for _, e := range cfg.AllowedServiceAccounts {
		v.allowed[e] = struct{}{}
	}
	for _, o := range opts {
		o(v)
	}
	v.keys = &jwksCache{
		issuer: cfg.Issuer, override: cfg.JWKSURL, bearerFile: cfg.BearerFile,
		client: client, log: v.log, now: v.now,
	}
	return v, nil
}

func fetchClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pemBytes, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, fmt.Errorf("workloadid: read %s: %w", EnvCAFile, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("workloadid: %s %q has no PEM certificates", EnvCAFile, caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   fetchTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}, nil
}

// Run loads the key set now and then every refresh interval until ctx ends.
func (v *OIDCVerifier) Run(ctx context.Context) {
	_ = v.refresh(ctx)
	t := time.NewTicker(v.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = v.refresh(ctx)
		}
	}
}

func (v *OIDCVerifier) refresh(ctx context.Context) error { return v.keys.refresh(ctx, false) }

// Verify checks a token and returns the worker as "<namespace>/<serviceaccount>".
// A token that fails any check is rejected; ErrUnavailable means no key set
// has ever loaded. The token itself is never logged.
func (v *OIDCVerifier) Verify(token string) (Principal, error) {
	p, reason, err := v.verify(token)
	if errors.Is(err, ErrUnavailable) {
		v.log.Error().Str("reason", reason).Msg("worker token not checked: verifier unavailable")
		return Principal{}, err
	}
	if err != nil {
		v.log.Warn().Str("reason", reason).Msg("worker token rejected")
		return Principal{}, err
	}
	v.log.Debug().Str("worker", p.WorkerID).Msg("worker token accepted")
	return p, nil
}

type tokenClaims struct {
	jwt.RegisteredClaims
	Kubernetes json.RawMessage `json:"kubernetes.io"`
}

func (v *OIDCVerifier) verify(token string) (Principal, string, error) {
	if token == "" {
		return reject("empty token")
	}
	var claims tokenClaims
	_, err := jwt.ParseWithClaims(token, &claims, v.keyFunc,
		jwt.WithValidMethods(allowedMethods),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return Principal{}, "no issuer key set loaded", ErrUnavailable
		}
		return reject(parseReason(err))
	}
	ns, sa, ok := parseSubject(claims.Subject)
	if !ok {
		return reject("subject is not a service account")
	}
	if claims.Kubernetes != nil {
		if err := checkKubernetesClaim(claims.Kubernetes, ns, sa); err != nil {
			return reject(err.Error())
		}
	}
	worker := ns + "/" + sa
	if _, ok := v.allowed[worker]; !ok {
		return reject("service account " + worker + " not allowed")
	}
	return Principal{WorkerID: worker}, "", nil
}

// keyFunc resolves the kid and insists the key type matches the token's
// method, so an RSA-signed token can never be checked against an EC key or
// the reverse.
func (v *OIDCVerifier) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("missing kid")
	}
	key, err := v.keys.key(kid)
	if err != nil {
		return nil, err
	}
	switch t.Method.(type) {
	case *jwt.SigningMethodRSA:
		if _, ok := key.(*rsa.PublicKey); ok {
			return key, nil
		}
	case *jwt.SigningMethodECDSA:
		if _, ok := key.(*ecdsa.PublicKey); ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key %q does not match alg %s", kid, t.Method.Alg())
}

func reject(reason string) (Principal, string, error) {
	return Principal{}, reason, fmt.Errorf("%w: %s", errRejected, reason)
}

func parseReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "wrong iss"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "wrong aud"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "nbf in the future"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "iat in the future"
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return "required claim missing"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "bad signature or disallowed alg"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "unverifiable: " + err.Error()
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed token"
	default:
		return "invalid token"
	}
}

func parseSubject(sub string) (ns, sa string, ok bool) {
	rest, found := strings.CutPrefix(sub, saSubjectPrefix)
	if !found {
		return "", "", false
	}
	ns, sa, found = strings.Cut(rest, ":")
	if !found || ns == "" || sa == "" || strings.Contains(sa, ":") {
		return "", "", false
	}
	return ns, sa, true
}

// checkKubernetesClaim requires the kubernetes.io claim, when the issuer sends
// one, to name the same namespace and service account as sub. A claim that is
// present but not the expected shape counts as a mismatch.
func checkKubernetesClaim(raw json.RawMessage, ns, sa string) error {
	var k struct {
		Namespace      *string `json:"namespace"`
		ServiceAccount *struct {
			Name *string `json:"name"`
		} `json:"serviceaccount"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return errors.New("kubernetes.io claim malformed")
	}
	if k.Namespace == nil || k.ServiceAccount == nil || k.ServiceAccount.Name == nil {
		return errors.New("kubernetes.io claim incomplete")
	}
	if *k.Namespace != ns || *k.ServiceAccount.Name != sa {
		return errors.New("kubernetes.io claim does not match sub")
	}
	return nil
}

func readBearer(p string) (string, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- operator-configured path
	if err != nil {
		return "", fmt.Errorf("workloadid: read %s: %w", EnvBearerFile, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("workloadid: %s %q is empty", EnvBearerFile, p)
	}
	return tok, nil
}
