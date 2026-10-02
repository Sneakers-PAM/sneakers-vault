// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/golang-jwt/jwt/v5"
)

const testNS = "apps"

func newVerifier(t *testing.T, iss *testIssuer, allowed ...string) *Verifier {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{testNS + "/sneakers-gateway"}
	}
	v, err := NewVerifier(Config{
		Issuer:                 iss.URL,
		CAFile:                 iss.CAFile,
		Audience:               DefaultAudience,
		AllowedServiceAccounts: allowed,
	}, log.Nop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return v
}

func TestVerifyMapsServiceAccountToCallerName(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	for kid, alg := range map[string]jwt.SigningMethod{"rsa-1": jwt.SigningMethodRS256, "ec-1": jwt.SigningMethodES256} {
		tok := iss.sign(t, kid, kid, alg, saClaims(iss.URL, DefaultAudience, testNS, "sneakers-gateway", time.Now()))
		c, err := v.Verify(tok)
		if err != nil {
			t.Fatalf("%s: valid token rejected: %v", alg.Alg(), err)
		}
		if c.Name != "gateway" || c.ServiceAccount != testNS+"/sneakers-gateway" {
			t.Fatalf("%s: caller %+v", alg.Alg(), c)
		}
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	now := time.Now()
	good := func() jwt.MapClaims { return saClaims(iss.URL, DefaultAudience, testNS, "sneakers-gateway", now) }
	cases := map[string]func(jwt.MapClaims){
		"wrong iss":         func(c jwt.MapClaims) { c["iss"] = iss.URL + "/other" },
		"wrong aud":         func(c jwt.MapClaims) { c["aud"] = []string{"sneakers-vault"} },
		"expired":           func(c jwt.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
		"no exp":            func(c jwt.MapClaims) { delete(c, "exp") },
		"nbf in the future": func(c jwt.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
		"not a sa":          func(c jwt.MapClaims) { c["sub"] = "user:alice" },
		"sa not allowed": func(c jwt.MapClaims) {
			c["sub"] = "system:serviceaccount:" + testNS + ":sneakers-mcp"
			c["kubernetes.io"] = map[string]any{"namespace": testNS, "serviceaccount": map[string]any{"name": "sneakers-mcp"}}
		},
		"kubernetes claim mismatch": func(c jwt.MapClaims) {
			c["kubernetes.io"] = map[string]any{"namespace": "other", "serviceaccount": map[string]any{"name": "sneakers-gateway"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good()
			mutate(c)
			_, err := v.Verify(iss.sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("want ErrRejected, got %v", err)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		if _, err := v.Verify(""); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("no kid", func(t *testing.T) {
		if _, err := v.Verify(iss.sign(t, "rsa-1", "", jwt.SigningMethodRS256, good())); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("hmac", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, good())
		tok.Header["kid"] = "rsa-1"
		s, err := tok.SignedString([]byte("shared"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(s); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
	t.Run("rsa token against ec key", func(t *testing.T) {
		if _, err := v.Verify(iss.sign(t, "rsa-1", "ec-1", jwt.SigningMethodRS256, good())); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
}

func TestVerifyUnavailableBeforeFirstLoad(t *testing.T) {
	iss := newTestIssuer(t)
	iss.fail.Store(true)
	v, err := NewVerifier(Config{Issuer: iss.URL, CAFile: iss.CAFile, AllowedServiceAccounts: []string{testNS + "/sneakers-gateway"}}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(iss.token(t, testNS, "sneakers-gateway")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestVerifyKeepsLastGoodKeysWhenIssuerFails(t *testing.T) {
	iss := newTestIssuer(t)
	v := newVerifier(t, iss)
	iss.fail.Store(true)
	if err := v.Refresh(context.Background()); err == nil {
		t.Fatal("refresh against a failing issuer should error")
	}
	if _, err := v.Verify(iss.token(t, testNS, "sneakers-gateway")); err != nil {
		t.Fatalf("last good set dropped: %v", err)
	}
}

func TestCallerName(t *testing.T) {
	for sa, want := range map[string]string{"sneakers-gateway": "gateway", "sneakers-workflow": "workflow", "ops-tool": "ops-tool"} {
		if got := callerName(sa); got != want {
			t.Fatalf("callerName(%q) = %q, want %q", sa, got, want)
		}
	}
}
