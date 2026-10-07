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
	_, _, err := WorkloadAuth(context.Background(), envOf(nil), workloadauth.Policy{}, log.Nop(), nil, nil)
	if !errors.Is(err, workloadauth.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestWorkloadAuthExplicitlyDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, opts, err := WorkloadAuth(ctx, envOf(map[string]string{workloadauth.EnvAuthMode: workloadauth.AuthDisabled}), workloadauth.Policy{}, log.Nop(), nil, nil)
	if err != nil || len(opts) != 0 || v != nil {
		t.Fatalf("opts=%d err=%v verifier=%v, want none", len(opts), err, v)
	}
}

func TestWorkloadAuthEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, opts, err := WorkloadAuth(ctx, envOf(map[string]string{
		workloadauth.EnvIssuer:                 "https://issuer.example.org",
		workloadauth.EnvAllowedServiceAccounts: "sneakers/sneakers-gateway",
	}), workloadauth.Policy{}, log.Nop(), nil, nil)
	if err != nil || len(opts) != 2 || v == nil {
		t.Fatalf("opts=%d err=%v verifier=%v, want the unary and stream interceptors and a verifier", len(opts), err, v)
	}
}

// fakeReadinessVerifier is a fake behind the ReadinessVerifier interface, not
// a mock of go-workload-identity's own Verifier.
type fakeReadinessVerifier struct{ err error }

func (f fakeReadinessVerifier) Ready() error { return f.err }

func TestWorkloadIdentity_NotReadyUntilKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(fakeReadinessVerifier{err: workloadauth.ErrUnavailable})
	if dep.Name != "workload-identity" || !dep.Required {
		t.Fatalf("dep = %+v, want a required dependency named workload-identity", dep)
	}
	if err := dep.Check(context.Background()); !errors.Is(err, workloadauth.ErrUnavailable) {
		t.Fatalf("check = %v, want ErrUnavailable", err)
	}
}

func TestWorkloadIdentity_ReadyOnceKeySetLoads(t *testing.T) {
	dep := WorkloadIdentity(fakeReadinessVerifier{})
	if err := dep.Check(context.Background()); err != nil {
		t.Fatalf("check = %v, want nil", err)
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
