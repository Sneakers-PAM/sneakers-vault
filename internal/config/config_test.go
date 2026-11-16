// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"
)

func TestLoadRequiredAndDefault(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.DatabaseDSN != "postgres://x" {
		t.Fatalf("got %q", c.DatabaseDSN)
	}
	if c.GRPCPort != "9090" {
		t.Fatalf("default GRPCPort got %q", c.GRPCPort)
	}
	if c.OTLPEndpoint != "" {
		t.Fatalf("default OTLPEndpoint got %q, want empty (no collector)", c.OTLPEndpoint)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	if err := os.Unsetenv("DATABASE_DSN"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing DATABASE_DSN")
	}
}

func TestLoad_HealthPort(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://example.org/db")
	t.Setenv("HEALTH_PORT", "")
	c, err := Load()
	if err != nil || c.HealthPort != "" {
		t.Fatalf("unset HEALTH_PORT: port=%q err=%v, want empty", c.HealthPort, err)
	}
	t.Setenv("HEALTH_PORT", "9091")
	c, err = Load()
	if err != nil || c.HealthPort != "9091" {
		t.Fatalf("HEALTH_PORT=9091: port=%q err=%v", c.HealthPort, err)
	}
}
