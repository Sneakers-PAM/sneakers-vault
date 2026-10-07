// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
)

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func oidcEnv(iss *oidctest.Issuer) map[string]string {
	return map[string]string{
		workloadid.EnvIssuer:                 iss.URL,
		workloadid.EnvCAFile:                 iss.CAFile,
		workloadid.EnvAllowedServiceAccounts: "apps/connector",
	}
}

func TestConnectorVerifierProdInstallsOnlyOIDC(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	for _, environment := range []string{"prod", "production"} {
		t.Run(environment, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env := oidcEnv(iss)
			env["CONNECTOR_DEV_TOKEN"] = "dev-connector-token"
			before := iss.JWKSHits.Load()
			v, err := connectorVerifier(ctx, environment, getenvFrom(env), log.Nop())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := v.(*workloadid.OIDCVerifier); !ok {
				t.Fatalf("want the OIDC verifier, got %T", v)
			}
			if _, err := v.Verify("dev-connector-token"); err == nil {
				t.Fatal("the dev token must not verify in prod")
			}
			deadline := time.Now().Add(5 * time.Second)
			for iss.JWKSHits.Load() == before {
				if time.Now().After(deadline) {
					t.Fatal("the JWKS refresher was not started")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestConnectorVerifierProdWithoutIssuerInstallsNone(t *testing.T) {
	for _, environment := range []string{"prod", "production"} {
		v, err := connectorVerifier(context.Background(), environment,
			getenvFrom(map[string]string{"CONNECTOR_DEV_TOKEN": "dev-connector-token"}), log.Nop())
		if err != nil {
			t.Fatal(err)
		}
		if v != nil {
			t.Fatalf("%s: want no verifier, got %T", environment, v)
		}
	}
}

func TestConnectorVerifierNonProdDefaultsToDevToken(t *testing.T) {
	v, err := connectorVerifier(context.Background(), "dev", getenvFrom(nil), log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*workloadid.OIDCVerifier); ok || v == nil {
		t.Fatalf("want the dev verifier, got %T", v)
	}
	if _, err := v.Verify("dev-connector-token"); err != nil {
		t.Fatalf("default dev token: %v", err)
	}

	v, err = connectorVerifier(context.Background(), "qa",
		getenvFrom(map[string]string{"CONNECTOR_DEV_TOKEN": "qa-token"}), log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify("qa-token"); err != nil {
		t.Fatalf("CONNECTOR_DEV_TOKEN: %v", err)
	}
}

func TestConnectorVerifierOIDCWinsOutsideProd(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := oidcEnv(iss)
	env["CONNECTOR_DEV_TOKEN"] = "dev-connector-token"
	v, err := connectorVerifier(ctx, "dev", getenvFrom(env), log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.(*workloadid.OIDCVerifier); !ok {
		t.Fatalf("want the OIDC verifier, got %T", v)
	}
}

func TestConnectorVerifierBadConfigFailsStartup(t *testing.T) {
	cases := map[string]map[string]string{
		"issuer without allowed SAs": {workloadid.EnvIssuer: "https://issuer.example.test"},
		"malformed SA entry": {
			workloadid.EnvIssuer: "https://issuer.example.test", workloadid.EnvAllowedServiceAccounts: "connector",
		},
		"missing CA file": {
			workloadid.EnvIssuer: "https://issuer.example.test", workloadid.EnvAllowedServiceAccounts: "apps/connector",
			workloadid.EnvCAFile: "/nonexistent/ca.pem",
		},
	}
	for name, env := range cases {
		for _, environment := range []string{"prod", "dev"} {
			t.Run(name+"/"+environment, func(t *testing.T) {
				if _, err := connectorVerifier(context.Background(), environment, getenvFrom(env), log.Nop()); err == nil {
					t.Fatal("want a startup error")
				}
			})
		}
	}
}
