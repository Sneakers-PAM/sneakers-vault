// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/mtlstest"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestDial_PlaintextWithoutAProvider(t *testing.T) {
	t.Setenv("WORKLOAD_TOKEN_FILE", "")
	t.Setenv("VAULT_ADDR", mtlstest.HealthServer(t, nil))
	c, err := Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := healthpb.NewHealthClient(c.Conn()).Check(t.Context(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("plaintext dial to a plaintext server: %v", err)
	}
}

func TestDial_MutualTLSWithAProvider(t *testing.T) {
	t.Setenv("WORKLOAD_TOKEN_FILE", "")
	p := mtlstest.Provider(t)
	t.Setenv("VAULT_ADDR", mtlstest.HealthServer(t, p))
	c, err := Dial(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := healthpb.NewHealthClient(c.Conn()).Check(t.Context(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("mutual TLS dial to a mutual TLS server: %v", err)
	}
	t.Setenv("VAULT_ADDR", mtlstest.HealthServer(t, nil))
	plain, err := Dial(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if _, err := healthpb.NewHealthClient(plain.Conn()).Check(t.Context(), &healthpb.HealthCheckRequest{}); err == nil {
		t.Fatal("a mutual TLS client reached a plaintext server")
	}
}
