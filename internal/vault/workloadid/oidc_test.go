// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const (
	testNS = "apps"
	testSA = "connector"
)

func testLogger() zerolog.Logger { return zerolog.Nop() }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestVerifier(t *testing.T, iss *oidctest.Issuer, mutate func(*OIDCConfig), opts ...OIDCOption) *OIDCVerifier {
	t.Helper()
	cfg := OIDCConfig{
		Issuer:                 iss.URL,
		CAFile:                 iss.CAFile,
		Audience:               DefaultAudience,
		AllowedServiceAccounts: []string{testNS + "/" + testSA},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewOIDCVerifier(cfg, testLogger(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func saClaims(iss *oidctest.Issuer) jwt.MapClaims {
	return oidctest.ServiceAccountClaims(iss.URL, DefaultAudience, testNS, testSA, time.Now())
}

func TestVerifyValidRS256AndES256(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	for kid, alg := range map[string]jwt.SigningMethod{"rsa-1": jwt.SigningMethodRS256, "ec-1": jwt.SigningMethodES256} {
		p, err := v.Verify(iss.Sign(t, kid, kid, alg, saClaims(iss)))
		if err != nil {
			t.Fatalf("%s: valid token rejected: %v", alg, err)
		}
		if p.WorkerID != testNS+"/"+testSA {
			t.Fatalf("%s: worker id %q", alg, p.WorkerID)
		}
	}
}

func TestVerifyRejectsBadClaims(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	now := time.Now()
	cases := map[string]func(jwt.MapClaims){
		"wrong iss":           func(c jwt.MapClaims) { c["iss"] = iss.URL + "/other" },
		"iss trailing slash":  func(c jwt.MapClaims) { c["iss"] = iss.URL + "/" },
		"wrong aud":           func(c jwt.MapClaims) { c["aud"] = []string{"someone-else"} },
		"no aud":              func(c jwt.MapClaims) { delete(c, "aud") },
		"expired":             func(c jwt.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
		"no exp":              func(c jwt.MapClaims) { delete(c, "exp") },
		"nbf in the future":   func(c jwt.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
		"iat in the future":   func(c jwt.MapClaims) { c["iat"] = now.Add(2 * time.Minute).Unix() },
		"subject not allowed": func(c jwt.MapClaims) { setSA(c, testNS, "intruder") },
		"namespace not allowed": func(c jwt.MapClaims) {
			setSA(c, "other-ns", testSA)
		},
		"subject not a service account": func(c jwt.MapClaims) { c["sub"] = "user:" + testNS + ":" + testSA },
		"subject extra segment":         func(c jwt.MapClaims) { c["sub"] = "system:serviceaccount:" + testNS + ":" + testSA + ":x" },
		"subject missing":               func(c jwt.MapClaims) { delete(c, "sub") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := saClaims(iss)
			mutate(c)
			_, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c))
			if err == nil {
				t.Fatal("want rejection")
			}
			if errors.Is(err, ErrUnavailable) {
				t.Fatalf("a bad token must not read as Unavailable: %v", err)
			}
		})
	}
}

// setSA moves both sub and the kubernetes.io claim to ns/sa so only the
// allow-list decides.
func setSA(c jwt.MapClaims, ns, sa string) {
	c["sub"] = "system:serviceaccount:" + ns + ":" + sa
	c["kubernetes.io"] = map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": sa}}
}

func TestVerifyClockSkewWithinSixtySeconds(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	now := time.Now()
	for name, mutate := range map[string]func(jwt.MapClaims){
		"expired 30s ago":  func(c jwt.MapClaims) { c["exp"] = now.Add(-30 * time.Second).Unix() },
		"nbf 30s ahead":    func(c jwt.MapClaims) { c["nbf"] = now.Add(30 * time.Second).Unix() },
		"iat 30s ahead":    func(c jwt.MapClaims) { c["iat"] = now.Add(30 * time.Second).Unix() },
		"no nbf or iat":    func(c jwt.MapClaims) { delete(c, "nbf"); delete(c, "iat") },
		"multi-value aud":  func(c jwt.MapClaims) { c["aud"] = []string{"other", DefaultAudience} },
		"no kubernetes.io": func(c jwt.MapClaims) { delete(c, "kubernetes.io") },
	} {
		t.Run(name, func(t *testing.T) {
			c := saClaims(iss)
			mutate(c)
			if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c)); err != nil {
				t.Fatalf("want accepted: %v", err)
			}
		})
	}
}

func TestVerifyRejectsKubernetesClaimMismatch(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	cases := map[string]any{
		"namespace differs":  map[string]any{"namespace": "other-ns", "serviceaccount": map[string]any{"name": testSA}},
		"name differs":       map[string]any{"namespace": testNS, "serviceaccount": map[string]any{"name": "intruder"}},
		"missing namespace":  map[string]any{"serviceaccount": map[string]any{"name": testSA}},
		"missing sa":         map[string]any{"namespace": testNS},
		"sa not an object":   map[string]any{"namespace": testNS, "serviceaccount": "connector"},
		"claim not object":   "apps/connector",
		"namespace a number": map[string]any{"namespace": 7, "serviceaccount": map[string]any{"name": testSA}},
		"claim null":         nil,
	}
	for name, k8s := range cases {
		t.Run(name, func(t *testing.T) {
			c := saClaims(iss)
			c["kubernetes.io"] = k8s
			if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c)); err == nil {
				t.Fatal("want rejection")
			}
		})
	}
}

func TestVerifyRejectsDisallowedAlgorithms(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	cases := map[string]string{
		"RS384": iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS384, saClaims(iss)),
		"PS256": iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodPS256, saClaims(iss)),
		"HS256": oidctest.SignHMAC(t, []byte("0123456789abcdef0123456789abcdef"), "rsa-1", saClaims(iss)),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(tok); err == nil {
				t.Fatal("want rejection")
			}
		})
	}
}

func TestVerifyRejectsGarbageAndForgedSignature(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	iss.AddRSAKey(t, "attacker", false)
	cases := map[string]string{
		"empty":      "",
		"not a jwt":  "dev-connector-token",
		"three dots": "a.b.c",
		// Signed by a key the issuer never published but labelled with a
		// published kid: the signature must not verify.
		"forged signature": iss.Sign(t, "attacker", "rsa-1", jwt.SigningMethodRS256, saClaims(iss)),
		"no kid":           iss.Sign(t, "rsa-1", "", jwt.SigningMethodRS256, saClaims(iss)),
		// An RSA token pointing at the EC key: key type mismatch.
		"kid of another key type": iss.Sign(t, "rsa-1", "ec-1", jwt.SigningMethodRS256, saClaims(iss)),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(tok)
			if err == nil {
				t.Fatal("want rejection")
			}
			if errors.Is(err, ErrUnavailable) {
				t.Fatalf("a bad token must not read as Unavailable: %v", err)
			}
		})
	}
}

func TestVerifyUnknownKidRefreshesThenRateLimits(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	clk := &clock{t: time.Now()}
	v := newTestVerifier(t, iss, nil, WithClock(clk.now))

	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("initial: %v", err)
	}
	hits := iss.JWKSHits.Load()

	// The issuer rotates in a new key: once the 30s window since the initial
	// fetch has passed, the first token with its kid forces one refresh.
	iss.AddRSAKey(t, "rsa-2", true)
	clk.t = clk.t.Add(31 * time.Second)
	if _, err := v.Verify(iss.Sign(t, "rsa-2", "rsa-2", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if got := iss.JWKSHits.Load(); got != hits+1 {
		t.Fatalf("unknown kid should refetch once: hits %d -> %d", hits, got)
	}

	// Another new kid within 30s is rejected without a fetch.
	iss.AddRSAKey(t, "rsa-3", true)
	clk.t = clk.t.Add(10 * time.Second)
	tok3 := iss.Sign(t, "rsa-3", "rsa-3", jwt.SigningMethodRS256, saClaims(iss))
	if _, err := v.Verify(tok3); err == nil {
		t.Fatal("refresh is rate-limited, so rsa-3 must still be unknown")
	}
	if got := iss.JWKSHits.Load(); got != hits+1 {
		t.Fatalf("rate limit broken: hits %d", got)
	}

	// After the 30s window the next unknown kid refreshes again.
	clk.t = clk.t.Add(25 * time.Second)
	if _, err := v.Verify(tok3); err != nil {
		t.Fatalf("after window: %v", err)
	}
	if got := iss.JWKSHits.Load(); got != hits+2 {
		t.Fatalf("want a second refetch: hits %d", got)
	}
}

func TestJWKSDiscoveredFromIssuer(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatal(err)
	}
	if iss.DiscoveryHits.Load() == 0 || iss.JWKSHits.Load() == 0 || iss.AltJWKSHits.Load() != 0 {
		t.Fatalf("discovery=%d jwks=%d alt=%d", iss.DiscoveryHits.Load(), iss.JWKSHits.Load(), iss.AltJWKSHits.Load())
	}
}

func TestJWKSOverrideSkipsDiscovery(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, func(c *OIDCConfig) { c.JWKSURL = iss.URL + oidctest.AltJWKSPath })
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatal(err)
	}
	if iss.DiscoveryHits.Load() != 0 || iss.JWKSHits.Load() != 0 || iss.AltJWKSHits.Load() == 0 {
		t.Fatalf("discovery=%d jwks=%d alt=%d", iss.DiscoveryHits.Load(), iss.JWKSHits.Load(), iss.AltJWKSHits.Load())
	}
}

func TestJWKSFetchSendsBearerFromFile(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	bearer := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(bearer, []byte("first-bearer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	iss.RequireBearer("first-bearer")
	clk := &clock{t: time.Now()}
	v := newTestVerifier(t, iss, func(c *OIDCConfig) { c.BearerFile = bearer }, WithClock(clk.now))
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("with bearer: %v", err)
	}

	// The kubelet rotates the bearer file in place; the next fetch uses the
	// new contents.
	if err := os.WriteFile(bearer, []byte("second-bearer"), 0o600); err != nil {
		t.Fatal(err)
	}
	iss.RequireBearer("second-bearer")
	if err := v.refresh(context.Background()); err != nil {
		t.Fatalf("refresh with rotated bearer: %v", err)
	}
	if got := iss.LastAuthorization(); got != "Bearer second-bearer" {
		t.Fatalf("authorization %q", got)
	}
}

func TestJWKSFetchWithoutBearerSendsNoAuthorization(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	if err := v.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := iss.LastAuthorization(); got != "" {
		t.Fatalf("unexpected authorization %q", got)
	}
}

// The API server serves its JWKS only as application/jwk-set+json and answers
// 406 to a plain application/json Accept; discovery is application/json.
func TestJWKSFetchNegotiatesJWKSetMediaType(t *testing.T) {
	for name, override := range map[string]string{"discovered": "", "override": oidctest.JWKSPath} {
		t.Run(name, func(t *testing.T) {
			iss := oidctest.NewIssuer(t)
			v := newTestVerifier(t, iss, func(c *OIDCConfig) {
				if override != "" {
					c.JWKSURL = iss.URL + override
				}
			})
			if err := v.refresh(context.Background()); err != nil {
				t.Fatalf("refresh against a negotiating issuer: %v", err)
			}
			if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

func TestJWKSNotAcceptableIsLoggedAndKeepsLastGoodSet(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	bearer := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(bearer, []byte("cluster-reader-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	iss.RequireBearer("cluster-reader-secret")
	jwksURL := iss.URL + oidctest.JWKSPath
	var logs bytes.Buffer
	cfg := OIDCConfig{
		Issuer: iss.URL, CAFile: iss.CAFile, Audience: DefaultAudience,
		JWKSURL: jwksURL, BearerFile: bearer,
		AllowedServiceAccounts: []string{testNS + "/" + testSA},
	}
	v, err := NewOIDCVerifier(cfg, zerolog.New(&logs))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}

	iss.RejectAccept.Store(true)
	logs.Reset()
	err = v.refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "406") {
		t.Fatalf("a 406 must fail the refresh with its status, got %v", err)
	}
	out := logs.String()
	for _, want := range []string{`"level":"error"`, "406", jwksURL, `"kept_keys":2`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "cluster-reader-secret") {
		t.Fatalf("bearer token logged: %s", out)
	}
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("last good set dropped: %v", err)
	}
}

func TestJWKSFetchFailureKeepsLastGoodSet(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	if err := v.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Fail.Store(true)
	if err := v.refresh(context.Background()); err == nil {
		t.Fatal("refresh against a failing issuer should report an error")
	}
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("last good set dropped: %v", err)
	}
}

func TestJWKSEmptySetKeepsLastGoodSet(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil)
	if err := v.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Publish()
	if err := v.refresh(context.Background()); err == nil {
		t.Fatal("an empty key set should be a failed refresh")
	}
	if _, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss))); err != nil {
		t.Fatalf("last good set dropped: %v", err)
	}
}

func TestNoKeySetIsUnavailable(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	iss.Fail.Store(true)
	v := newTestVerifier(t, iss, nil)
	_, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss)))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestUntrustedIssuerCertIsUnavailable(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, func(c *OIDCConfig) { c.CAFile = "" })
	_, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss)))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable without the issuer CA, got %v", err)
	}
}

func TestRunRefreshesPeriodically(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	v := newTestVerifier(t, iss, nil, WithRefreshInterval(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { v.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for iss.JWKSHits.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("periodic refresh did not run: hits %d", iss.JWKSHits.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestDefaultRefreshTimings(t *testing.T) {
	if DefaultRefreshInterval != 15*time.Minute || unknownKidRefreshEvery != 30*time.Second || clockSkew != 60*time.Second {
		t.Fatalf("refresh=%v unknownKid=%v skew=%v", DefaultRefreshInterval, unknownKidRefreshEvery, clockSkew)
	}
}

// The in-cluster path: the issuer URL itself is not reachable for discovery,
// so the JWKS comes from an override that needs the cluster CA and a bearer.
func TestInClusterOverrideWithCAAndBearer(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	iss.FailDiscovery.Store(true)
	iss.RequireBearer("cluster-reader")
	bearer := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(bearer, []byte("cluster-reader"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := newTestVerifier(t, iss, func(c *OIDCConfig) {
		c.JWKSURL = iss.URL + oidctest.JWKSPath
		c.BearerFile = bearer
	})
	p, err := v.Verify(iss.Sign(t, "ec-1", "ec-1", jwt.SigningMethodES256, saClaims(iss)))
	if err != nil {
		t.Fatalf("in-cluster path: %v", err)
	}
	if p.WorkerID != testNS+"/"+testSA || iss.DiscoveryHits.Load() != 0 {
		t.Fatalf("worker %q discovery hits %d", p.WorkerID, iss.DiscoveryHits.Load())
	}
}

func TestInClusterOverrideWithoutBearerIsUnavailable(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	iss.FailDiscovery.Store(true)
	iss.RequireBearer("cluster-reader")
	v := newTestVerifier(t, iss, func(c *OIDCConfig) { c.JWKSURL = iss.URL + oidctest.JWKSPath })
	_, err := v.Verify(iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(iss)))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a 401 JWKS with no set loaded must be Unavailable, got %v", err)
	}
}
