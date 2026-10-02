// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigFromEnvUnsetIssuerIsOff(t *testing.T) {
	_, ok, err := ConfigFromEnv(envMap(nil))
	if ok || err != nil {
		t.Fatalf("ok=%v err=%v, want off", ok, err)
	}
}

func TestConfigFromEnvDefaultsAndTrims(t *testing.T) {
	cfg, ok, err := ConfigFromEnv(envMap(map[string]string{
		EnvIssuer:                 " https://issuer.example.org ",
		EnvAllowedServiceAccounts: "sneakers/sneakers-gateway, sneakers/sneakers-workflow",
	}))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if cfg.Audience != "sneakers" {
		t.Fatalf("default audience %q, want sneakers", cfg.Audience)
	}
	if cfg.Issuer != "https://issuer.example.org" || len(cfg.AllowedServiceAccounts) != 2 || cfg.AllowedServiceAccounts[1] != "sneakers/sneakers-workflow" {
		t.Fatalf("cfg %+v", cfg)
	}
}

func TestConfigFromEnvRejectsBadValues(t *testing.T) {
	base := map[string]string{EnvIssuer: "https://issuer.example.org", EnvAllowedServiceAccounts: "sneakers/sneakers-gateway"}
	cases := map[string]map[string]string{
		"http issuer":       {EnvIssuer: "http://issuer.example.org"},
		"http jwks":         {EnvJWKSURL: "http://issuer.example.org/jwks"},
		"no allow-list":     {EnvAllowedServiceAccounts: " "},
		"entry without ns":  {EnvAllowedServiceAccounts: "sneakers-gateway"},
		"entry with colon":  {EnvAllowedServiceAccounts: "sneakers/sneakers:gateway"},
		"empty entry":       {EnvAllowedServiceAccounts: "sneakers/sneakers-gateway,,sneakers/sneakers-workflow"},
		"unreadable bearer": {EnvBearerFile: "/nonexistent/token"},
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range over {
				m[k] = v
			}
			cfg, ok, err := ConfigFromEnv(envMap(m))
			if err == nil {
				_, err = NewVerifier(cfg, nil)
			}
			if err == nil {
				t.Fatalf("ok=%v: want an error", ok)
			}
			if !strings.Contains(err.Error(), "workloadauth") {
				t.Fatalf("error %q should name the package", err)
			}
		})
	}
}
