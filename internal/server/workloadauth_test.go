// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestWorkloadAuthUnsetIssuerFailsToBoot(t *testing.T) {
	_, err := WorkloadAuth(context.Background(), envOf(nil), workloadauth.Policy{}, log.Nop(), nil, nil)
	if !errors.Is(err, workloadauth.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestWorkloadAuthExplicitlyDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts, err := WorkloadAuth(ctx, envOf(map[string]string{workloadauth.EnvAuthMode: workloadauth.AuthDisabled}), workloadauth.Policy{}, log.Nop(), nil, nil)
	if err != nil || len(opts) != 0 {
		t.Fatalf("opts=%d err=%v, want none", len(opts), err)
	}
}

func TestWorkloadAuthEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts, err := WorkloadAuth(ctx, envOf(map[string]string{
		workloadauth.EnvIssuer:                 "https://issuer.example.org",
		workloadauth.EnvAllowedServiceAccounts: "sneakers/sneakers-gateway",
	}), workloadauth.Policy{}, log.Nop(), nil, nil)
	if err != nil || len(opts) != 2 {
		t.Fatalf("opts=%d err=%v, want the unary and stream interceptors", len(opts), err)
	}
}

func TestClientAuth(t *testing.T) {
	if opts, err := ClientAuth(envOf(nil)); err != nil || len(opts) != 0 {
		t.Fatalf("unset: opts=%d err=%v", len(opts), err)
	}
	if _, err := ClientAuth(envOf(map[string]string{workloadauth.EnvTokenFile: "/nonexistent/token"})); err == nil {
		t.Fatal("a missing token file must fail")
	}
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if opts, err := ClientAuth(envOf(map[string]string{workloadauth.EnvTokenFile: p})); err != nil || len(opts) != 1 {
		t.Fatalf("set: opts=%d err=%v", len(opts), err)
	}
}
