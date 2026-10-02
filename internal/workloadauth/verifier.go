// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

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

	log "github.com/Bugs5382/go-log"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultRefreshInterval is how often Run refetches the JWKS.
	DefaultRefreshInterval = 15 * time.Minute
	unknownKidRefreshEvery = 30 * time.Second
	clockSkew              = 60 * time.Second
	fetchTimeout           = 10 * time.Second
	saSubjectPrefix        = "system:serviceaccount:"
	// callerPrefix is stripped from a service account name to give the caller
	// name: "sneakers-gateway" is the caller "gateway".
	callerPrefix = "sneakers-"
)

var allowedMethods = []string{"RS256", "ES256"}

// ErrRejected means the token failed a check: signature, issuer, audience,
// time, subject or the service-account allow-list.
var ErrRejected = errors.New("workloadauth: token rejected")

// ErrUnavailable means the verifier can't judge any token right now: no
// issuer key set has loaded since start. Callers must fail closed.
var ErrUnavailable = errors.New("workloadauth: verifier unavailable")

// Caller is a verified workload.
type Caller struct {
	// Name is the caller name, the service account without its "sneakers-"
	// prefix (gateway, workflow, connector and so on).
	Name string
	// ServiceAccount is the allow-listed "<namespace>/<serviceaccount>".
	ServiceAccount string
}

// TokenVerifier checks a caller's token. Verifier is the production one.
type TokenVerifier interface {
	Verify(token string) (Caller, error)
}

// Verifier checks Kubernetes projected ServiceAccount tokens against the
// issuer's JWKS and an exact allow-list of service accounts. Safe for
// concurrent use.
type Verifier struct {
	cfg      Config
	allowed  map[string]struct{}
	keys     *jwksCache
	log      log.Logger
	now      func() time.Time
	interval time.Duration
}

var _ TokenVerifier = (*Verifier)(nil)

// NewVerifier validates cfg and builds a verifier. It fetches no keys: an
// issuer that is down at start leaves the verifier answering ErrUnavailable
// until Run or Refresh loads a set, rather than failing the boot. A nil
// logger discards.
func NewVerifier(cfg Config, logger log.Logger) (*Verifier, error) {
	if logger == nil {
		logger = log.Nop()
	}
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
	v := &Verifier{
		cfg:      cfg,
		allowed:  make(map[string]struct{}, len(cfg.AllowedServiceAccounts)),
		log:      logger.With(log.F("component", "workloadauth")),
		now:      time.Now,
		interval: DefaultRefreshInterval,
	}
	for _, e := range cfg.AllowedServiceAccounts {
		v.allowed[e] = struct{}{}
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
			return nil, fmt.Errorf("workloadauth: read %s: %w", EnvCAFile, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("workloadauth: %s %q has no PEM certificates", EnvCAFile, caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   fetchTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}, nil
}

// Run loads the key set now and then every refresh interval until ctx ends.
func (v *Verifier) Run(ctx context.Context) {
	_ = v.Refresh(ctx)
	t := time.NewTicker(v.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = v.Refresh(ctx)
		}
	}
}

// Refresh fetches the key set once. A failure keeps the last good set.
func (v *Verifier) Refresh(ctx context.Context) error { return v.keys.refresh(ctx, false) }

// Verify checks a token and returns the caller. A token that fails any check
// returns ErrRejected; ErrUnavailable means no key set has loaded yet. The
// token itself is never logged.
func (v *Verifier) Verify(token string) (Caller, error) {
	c, reason, err := v.verify(token)
	if errors.Is(err, ErrUnavailable) {
		v.log.Error(err, "caller token not checked: verifier unavailable", log.F("reason", reason))
		return Caller{}, err
	}
	if err != nil {
		v.log.Warn("caller token rejected", log.F("reason", reason))
		return Caller{}, err
	}
	log.Trace(v.log, "caller token accepted", log.F("caller", c.Name), log.F("service_account", c.ServiceAccount))
	return c, nil
}

type tokenClaims struct {
	jwt.RegisteredClaims
	Kubernetes json.RawMessage `json:"kubernetes.io"`
}

func (v *Verifier) verify(token string) (Caller, string, error) {
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
			return Caller{}, "no issuer key set loaded", ErrUnavailable
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
	entry := ns + "/" + sa
	if _, ok := v.allowed[entry]; !ok {
		return reject("service account " + entry + " not allowed")
	}
	return Caller{Name: callerName(sa), ServiceAccount: entry}, "", nil
}

func callerName(sa string) string { return strings.TrimPrefix(sa, callerPrefix) }

// keyFunc resolves the kid and insists the key type matches the token's
// method, so an RSA-signed token can never be checked against an EC key or
// the reverse.
func (v *Verifier) keyFunc(t *jwt.Token) (any, error) {
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

func reject(reason string) (Caller, string, error) {
	return Caller{}, reason, fmt.Errorf("%w: %s", ErrRejected, reason)
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
		return "", fmt.Errorf("workloadauth: read %s: %w", EnvBearerFile, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("workloadauth: %s %q is empty", EnvBearerFile, p)
	}
	return tok, nil
}
