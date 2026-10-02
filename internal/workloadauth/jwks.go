// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

const maxDocBytes = 1 << 20

// The API server serves discovery as application/json and the JWKS only as
// application/jwk-set+json, answering 406 to a plain application/json Accept.
const (
	discoveryAccept = "application/json"
	jwksAccept      = "application/jwk-set+json, application/json"
)

// jwksCache holds the issuer's signing keys. A failed fetch never replaces a
// good set; with no set at all, lookups fail with ErrUnavailable.
type jwksCache struct {
	issuer     string
	override   string
	bearerFile string
	client     *http.Client
	log        log.Logger
	now        func() time.Time

	mu   sync.RWMutex
	keys map[string]crypto.PublicKey

	fetchMu     sync.Mutex
	lastAttempt time.Time
}

// key returns the key for kid. An unknown kid triggers one refresh, at most
// every unknownKidRefreshEvery, so a key the issuer just rotated in works
// before the periodic refresh while a flood of junk kids can't hammer the
// issuer.
func (j *jwksCache) key(kid string) (crypto.PublicKey, error) {
	if k, ok, _ := j.lookup(kid); ok {
		return k, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	_ = j.refresh(ctx, true)
	k, ok, loaded := j.lookup(kid)
	switch {
	case ok:
		return k, nil
	case !loaded:
		return nil, ErrUnavailable
	default:
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
}

func (j *jwksCache) lookup(kid string) (crypto.PublicKey, bool, bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	k, ok := j.keys[kid]
	return k, ok, j.keys != nil
}

func (j *jwksCache) refresh(ctx context.Context, rateLimited bool) error {
	j.fetchMu.Lock()
	defer j.fetchMu.Unlock()
	if rateLimited && !j.lastAttempt.IsZero() && j.now().Sub(j.lastAttempt) < unknownKidRefreshEvery {
		j.log.Debug("JWKS refresh skipped: rate limited")
		return nil
	}
	j.lastAttempt = j.now()
	start := time.Now()
	jwksURL, keys, err := j.fetch(ctx)
	if err != nil {
		j.mu.RLock()
		kept := len(j.keys)
		j.mu.RUnlock()
		j.log.Error(err, "JWKS refresh failed; keeping the last good set",
			log.F("issuer", j.issuer), log.F("kept_keys", kept), log.F("duration_ms", time.Since(start).Milliseconds()))
		return err
	}
	j.mu.Lock()
	j.keys = keys
	j.mu.Unlock()
	j.log.Info("JWKS refreshed",
		log.F("jwks_url", jwksURL), log.F("keys", len(keys)), log.F("duration_ms", time.Since(start).Milliseconds()))
	return nil
}

func (j *jwksCache) fetch(ctx context.Context) (string, map[string]crypto.PublicKey, error) {
	jwksURL := j.override
	if jwksURL == "" {
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := j.getJSON(ctx, strings.TrimSuffix(j.issuer, "/")+"/.well-known/openid-configuration", discoveryAccept, &doc); err != nil {
			return "", nil, fmt.Errorf("discovery: %w", err)
		}
		if err := requireHTTPS("jwks_uri", doc.JWKSURI); err != nil {
			return "", nil, fmt.Errorf("discovery: %w", err)
		}
		jwksURL = doc.JWKSURI
	}
	var raw json.RawMessage
	if err := j.getJSON(ctx, jwksURL, jwksAccept, &raw); err != nil {
		return jwksURL, nil, fmt.Errorf("jwks: %w", err)
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return jwksURL, nil, err
	}
	if len(keys) == 0 {
		return jwksURL, nil, errors.New("jwks: no usable RSA or EC signing keys")
	}
	return jwksURL, keys, nil
}

func (j *jwksCache) getJSON(ctx context.Context, target, accept string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	if j.bearerFile != "" {
		// Re-read every time: a projected bearer token is rotated in place.
		tok, err := readBearer(j.bearerFile)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := j.client.Do(req) // #nosec G704 -- operator-configured issuer/JWKS URL, never request input
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", target, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocBytes)).Decode(dst); err != nil {
		return fmt.Errorf("GET %s: decode: %w", target, err)
	}
	return nil
}

// parseJWKS keeps RSA and EC signing keys with a kid; anything else (oct,
// encryption keys, unknown curves) is skipped rather than failing the set.
func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty, Kid, Use string
			N, E          string // RSA
			Crv, X, Y     string // EC
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		var pub crypto.PublicKey
		var err error
		switch k.Kty {
		case "RSA":
			pub, err = rsaPublicFromJWK(k.N, k.E)
		case "EC":
			pub, err = ecdsaPublicFromJWK(k.Crv, k.X, k.Y)
		default:
			continue
		}
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func b64uBig(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func rsaPublicFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	n, err := b64uBig(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	e, err := b64uBig(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("rsa exponent out of range")
	}
	if n.BitLen() < 2048 {
		return nil, errors.New("rsa modulus shorter than 2048 bits")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// ecdsaPublicFromJWK accepts P-256 only, the one curve ES256 uses.
func ecdsaPublicFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	x, err := b64uBig(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	y, err := b64uBig(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) { //nolint:staticcheck // the only stdlib check that takes raw JWK coordinates
		return nil, errors.New("EC point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
