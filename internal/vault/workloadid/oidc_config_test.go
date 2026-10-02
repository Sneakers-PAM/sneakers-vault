// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfigFromEnvDisabledWithoutIssuer(t *testing.T) {
	_, ok, err := OIDCConfigFromEnv(envMap(map[string]string{EnvAllowedServiceAccounts: "apps/connector"}))
	if err != nil || ok {
		t.Fatalf("no issuer: ok=%v err=%v; want disabled, no error", ok, err)
	}
}

func TestConfigFromEnvValid(t *testing.T) {
	cfg, ok, err := OIDCConfigFromEnv(envMap(map[string]string{
		EnvIssuer:                 "https://issuer.example.test",
		EnvJWKSURL:                "https://issuer.example.test/keys",
		EnvCAFile:                 "/etc/ca.pem",
		EnvBearerFile:             "/var/run/token",
		EnvAllowedServiceAccounts: " apps/connector , ops/connector-b ",
	}))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	want := OIDCConfig{
		Issuer:                 "https://issuer.example.test",
		JWKSURL:                "https://issuer.example.test/keys",
		CAFile:                 "/etc/ca.pem",
		BearerFile:             "/var/run/token",
		Audience:               DefaultAudience,
		AllowedServiceAccounts: []string{"apps/connector", "ops/connector-b"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("got %+v\nwant %+v", cfg, want)
	}
	if DefaultAudience != "sneakers" {
		t.Fatalf("default audience %q", DefaultAudience)
	}
}

func TestConfigFromEnvAudienceOverride(t *testing.T) {
	cfg, _, err := OIDCConfigFromEnv(envMap(map[string]string{
		EnvIssuer: "https://issuer.example.test", EnvAudience: "other-aud", EnvAllowedServiceAccounts: "apps/connector",
	}))
	if err != nil || cfg.Audience != "other-aud" {
		t.Fatalf("audience %q err %v", cfg.Audience, err)
	}
}

func TestConfigFromEnvRejectsBadConfig(t *testing.T) {
	cases := map[string]map[string]string{
		"no allowed SAs":        {EnvIssuer: "https://issuer.example.test"},
		"blank allowed SAs":     {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: " , "},
		"entry without slash":   {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "connector"},
		"empty namespace":       {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "/connector"},
		"empty name":            {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "apps/"},
		"two slashes":           {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "apps/a/b"},
		"colon in entry":        {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "apps:connector/x"},
		"trailing empty entry":  {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "apps/connector,"},
		"space inside entry":    {EnvIssuer: "https://issuer.example.test", EnvAllowedServiceAccounts: "apps/con nector"},
		"http issuer":           {EnvIssuer: "http://issuer.example.test", EnvAllowedServiceAccounts: "apps/connector"},
		"relative issuer":       {EnvIssuer: "issuer.example.test", EnvAllowedServiceAccounts: "apps/connector"},
		"http jwks override":    {EnvIssuer: "https://issuer.example.test", EnvJWKSURL: "http://issuer.example.test/keys", EnvAllowedServiceAccounts: "apps/connector"},
		"whitespace-only issue": {EnvIssuer: "  ", EnvAllowedServiceAccounts: "apps/connector"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := OIDCConfigFromEnv(envMap(env)); err == nil {
				t.Fatal("want a config error")
			}
		})
	}
}

func TestNewRejectsUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyBearer := filepath.Join(dir, "empty-token")
	if err := os.WriteFile(emptyBearer, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	base := OIDCConfig{Issuer: "https://issuer.example.test", Audience: DefaultAudience, AllowedServiceAccounts: []string{"apps/connector"}}
	cases := map[string]OIDCConfig{
		"missing CA file": withCA(base, filepath.Join(dir, "missing.pem")),
		"CA without cert": withCA(base, notPEM),
		"missing bearer":  withBearer(base, filepath.Join(dir, "missing-token")),
		"empty bearer":    withBearer(base, emptyBearer),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOIDCVerifier(cfg, testLogger()); err == nil {
				t.Fatal("want a startup error")
			}
		})
	}
}

func withCA(c OIDCConfig, p string) OIDCConfig     { c.CAFile = p; return c }
func withBearer(c OIDCConfig, p string) OIDCConfig { c.BearerFile = p; return c }
