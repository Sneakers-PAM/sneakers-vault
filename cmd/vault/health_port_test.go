// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/Bugs5382/go-mtls"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
)

func TestBootHealthPort(t *testing.T) {
	cfg := config.Config{GRPCPort: "9090", HealthPort: "9091"}
	if got := bootHealthPort(cfg, nil); got != "9090" {
		t.Fatalf("plaintext: boot health on %q, want the service port 9090", got)
	}
	if got := bootHealthPort(cfg, &mtls.Provider{}); got != "9091" {
		t.Fatalf("mutual TLS: boot health on %q, want the plain health port 9091", got)
	}
}
