// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testIssuer is a local OIDC issuer: discovery and a JWKS over TLS, with keys
// generated in the test. It never talks to a real issuer.
type testIssuer struct {
	URL    string
	CAFile string

	mu        sync.Mutex
	keys      map[string]any
	published []string

	jwksHits atomic.Int32
	fail     atomic.Bool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	i := &testIssuer{keys: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if i.fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": i.URL, "jwks_uri": i.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		i.jwksHits.Add(1)
		if i.fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		i.mu.Lock()
		keys := make([]map[string]string, 0, len(i.published))
		for _, kid := range i.published {
			keys = append(keys, testPublicJWK(kid, i.keys[kid]))
		}
		i.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	i.URL = srv.URL
	i.CAFile = filepath.Join(t.TempDir(), "issuer-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(i.CAFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	i.keys["rsa-1"], i.keys["ec-1"] = rk, ek
	i.published = []string{"rsa-1", "ec-1"}
	return i
}

func testPublicJWK(kid string, key any) map[string]string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
	case *ecdsa.PrivateKey:
		pub, _ := k.PublicKey.ECDH()
		raw := pub.Bytes()
		size := (len(raw) - 1) / 2
		return map[string]string{"kty": "EC", "kid": kid, "use": "sig", "crv": "P-256", "x": b64(raw[1 : 1+size]), "y": b64(raw[1+size:])}
	default:
		panic("unsupported key type")
	}
}

// sign signs claims with the key under kid; headerKid is the kid header sent
// (omitted when empty).
func (i *testIssuer) sign(t *testing.T, kid, headerKid string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	i.mu.Lock()
	k := i.keys[kid]
	i.mu.Unlock()
	tok := jwt.NewWithClaims(method, claims)
	if headerKid != "" {
		tok.Header["kid"] = headerKid
	}
	s, err := tok.SignedString(k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// token returns a valid RS256 token for namespace/sa with the default audience.
func (i *testIssuer) token(t *testing.T, namespace, sa string) string {
	t.Helper()
	return i.sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, saClaims(i.URL, DefaultAudience, namespace, sa, time.Now()))
}

func saClaims(issuer, audience, namespace, sa string, now time.Time) jwt.MapClaims {
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
