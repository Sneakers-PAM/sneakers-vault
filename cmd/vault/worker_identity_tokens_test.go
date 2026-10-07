// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
	"github.com/golang-jwt/jwt/v5"
)

// TestConnectorVerifierAcceptsAndRefusesTokens pins which connector tokens the
// OIDC verifier accepts: the audience defaults to "sneakers" and the worker is
// "<namespace>/<serviceaccount>"; a token with the wrong audience or issuer,
// an expired one, or one from a service account off the list is refused.
func TestConnectorVerifierAcceptsAndRefusesTokens(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, err := connectorVerifier(ctx, "prod", getenvFrom(oidcEnv(iss)), log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token := func(mutate func(jwt.MapClaims)) string {
		c := oidctest.ServiceAccountClaims(iss.URL, "sneakers", "apps", "connector", now)
		if mutate != nil {
			mutate(c)
		}
		return iss.Sign(t, "ec-1", "ec-1", jwt.SigningMethodES256, c)
	}
	valid := token(nil)
	deadline := time.Now().Add(5 * time.Second)
	p, err := v.Verify(valid)
	for errors.Is(err, workloadid.ErrUnavailable) {
		if time.Now().After(deadline) {
			t.Fatal("the verifier never loaded the issuer's keys")
		}
		time.Sleep(10 * time.Millisecond)
		p, err = v.Verify(valid)
	}
	if err != nil || p.WorkerID != "apps/connector" {
		t.Fatalf("valid token: principal %+v, err %v", p, err)
	}

	refused := map[string]string{
		"wrong audience": token(func(c jwt.MapClaims) { c["aud"] = []string{"other"} }),
		"wrong issuer":   token(func(c jwt.MapClaims) { c["iss"] = "https://issuer.example.org" }),
		"expired":        token(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }),
		"service account not allowed": token(func(c jwt.MapClaims) {
			c["sub"] = "system:serviceaccount:apps:other"
			c["kubernetes.io"] = map[string]any{"namespace": "apps", "serviceaccount": map[string]any{"name": "other"}}
		}),
	}
	for name, tok := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(tok); err == nil || errors.Is(err, workloadid.ErrUnavailable) {
				t.Fatalf("err = %v, want a rejection", err)
			}
		})
	}
}
