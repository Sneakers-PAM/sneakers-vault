// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package oidctest is a local OIDC issuer for tests: an httptest TLS server
// that serves discovery and a JWKS built from keys generated in the test, and
// signs ServiceAccount-style tokens with them. It never talks to a real issuer.
//
// Like the Kubernetes API server, it negotiates on Accept: discovery is served
// as application/json and the JWKS as application/jwk-set+json, and a request
// whose Accept names neither the type nor a matching wildcard gets 406.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Paths served by the issuer. AltJWKSPath serves the same set as JWKSPath but
// is never advertised by discovery, so tests can tell an override from a
// discovered URL.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/openid/v1/jwks"
	AltJWKSPath   = "/alt/jwks"

	DiscoveryMediaType = "application/json"
	JWKSMediaType      = "application/jwk-set+json"
)

// Issuer is a running test issuer.
type Issuer struct {
	URL    string
	CAFile string

	srv *httptest.Server

	mu        sync.Mutex
	keys      map[string]any
	published []string

	DiscoveryHits atomic.Int32
	JWKSHits      atomic.Int32
	AltJWKSHits   atomic.Int32
	// Fail makes discovery and both JWKS paths return 500.
	Fail atomic.Bool
	// FailDiscovery makes only discovery return 500.
	FailDiscovery atomic.Bool
	// RejectAccept makes both JWKS paths return 406 whatever the Accept.
	RejectAccept atomic.Bool

	authMu        sync.Mutex
	requireBearer string
	lastAuth      string
}

// NewIssuer starts an issuer with an RSA key "rsa-1" and an EC P-256 key
// "ec-1", both published. The server's CA is written to CAFile.
func NewIssuer(t *testing.T) *Issuer {
	t.Helper()
	i := &Issuer{keys: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc(DiscoveryPath, i.serveDiscovery)
	mux.HandleFunc(JWKSPath, func(w http.ResponseWriter, r *http.Request) {
		i.JWKSHits.Add(1)
		i.serveJWKS(w, r)
	})
	mux.HandleFunc(AltJWKSPath, func(w http.ResponseWriter, r *http.Request) {
		i.AltJWKSHits.Add(1)
		i.serveJWKS(w, r)
	})
	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)
	i.URL = i.srv.URL

	i.CAFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw})
	if err := os.WriteFile(i.CAFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	i.AddRSAKey(t, "rsa-1", true)
	i.AddECKey(t, "ec-1", true)
	return i
}

// AddRSAKey generates an RSA key under kid; publish controls whether the JWKS
// advertises it yet.
func (i *Issuer) AddRSAKey(t *testing.T, kid string, publish bool) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	i.addKey(kid, k, publish)
}

// AddECKey generates an EC P-256 key under kid.
func (i *Issuer) AddECKey(t *testing.T, kid string, publish bool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	i.addKey(kid, k, publish)
}

func (i *Issuer) addKey(kid string, key any, publish bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys[kid] = key
	if publish {
		i.published = append(i.published, kid)
	}
}

// Publish replaces the advertised set with exactly kids.
func (i *Issuer) Publish(kids ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.published = append([]string(nil), kids...)
}

// RequireBearer makes both JWKS paths demand "Authorization: Bearer <tok>".
func (i *Issuer) RequireBearer(tok string) {
	i.authMu.Lock()
	defer i.authMu.Unlock()
	i.requireBearer = tok
}

// LastAuthorization is the Authorization header of the latest JWKS request.
func (i *Issuer) LastAuthorization() string {
	i.authMu.Lock()
	defer i.authMu.Unlock()
	return i.lastAuth
}

func (i *Issuer) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	i.DiscoveryHits.Add(1)
	if i.Fail.Load() || i.FailDiscovery.Load() {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	if !accepts(r, DiscoveryMediaType) {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		return
	}
	w.Header().Set("Content-Type", DiscoveryMediaType)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":   i.URL,
		"jwks_uri": i.URL + JWKSPath,
	})
}

func (i *Issuer) serveJWKS(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	i.authMu.Lock()
	i.lastAuth = auth
	want := i.requireBearer
	i.authMu.Unlock()
	if i.Fail.Load() {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	if want != "" && auth != "Bearer "+want {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if i.RejectAccept.Load() || !accepts(r, JWKSMediaType) {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		return
	}
	w.Header().Set("Content-Type", JWKSMediaType)
	i.mu.Lock()
	keys := make([]map[string]string, 0, len(i.published))
	for _, kid := range i.published {
		keys = append(keys, publicJWK(kid, i.keys[kid]))
	}
	i.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// accepts reports whether r's Accept admits mediaType. A missing Accept admits
// anything, as it does for the API server.
func accepts(r *http.Request, mediaType string) bool {
	accept := r.Header.Values("Accept")
	if len(accept) == 0 {
		return true
	}
	major, _, _ := strings.Cut(mediaType, "/")
	for _, line := range accept {
		for _, part := range strings.Split(line, ",") {
			mt, _, _ := strings.Cut(part, ";")
			mt = strings.ToLower(strings.TrimSpace(mt))
			if mt == mediaType || mt == "*/*" || mt == major+"/*" {
				return true
			}
		}
	}
	return false
}

func publicJWK(kid string, key any) map[string]string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return map[string]string{
			"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		}
	case *ecdsa.PrivateKey:
		pub, _ := k.PublicKey.ECDH()
		raw := pub.Bytes() // 0x04 || X || Y, fixed width
		size := (len(raw) - 1) / 2
		return map[string]string{
			"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
			"x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:]),
		}
	default:
		panic("oidctest: unsupported key type")
	}
}

// Sign signs claims with the key under kid using method. The kid header is
// set to headerKid (omitted when empty), so tests can send a kid the issuer
// never published or point at the wrong key.
func (i *Issuer) Sign(t *testing.T, kid, headerKid string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	i.mu.Lock()
	k, ok := i.keys[kid]
	i.mu.Unlock()
	if !ok {
		t.Fatalf("no key %q", kid)
	}
	return sign(t, method, headerKid, k, claims)
}

// SignHMAC signs claims with a shared secret, for alg-confusion tests.
func SignHMAC(t *testing.T, secret []byte, headerKid string, claims jwt.MapClaims) string {
	t.Helper()
	return sign(t, jwt.SigningMethodHS256, headerKid, secret, claims)
}

func sign(t *testing.T, method jwt.SigningMethod, headerKid string, key any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if headerKid != "" {
		tok.Header["kid"] = headerKid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// ServiceAccountClaims returns the claims a Kubernetes projected token
// carries for namespace/sa, valid for an hour from now.
func ServiceAccountClaims(issuer, audience, namespace, sa string, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": issuer,
		"aud": []string{audience},
		"sub": "system:serviceaccount:" + namespace + ":" + sa,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": sa, "uid": "00000000-0000-0000-0000-000000000001"},
		},
	}
}
