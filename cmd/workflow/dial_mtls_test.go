// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/mtlstest"
)

func TestAuditDialOptions(t *testing.T) {
	none := func(string) string { return "" }
	plain, err := auditDialOptions(nil, none)
	if err != nil {
		t.Fatal(err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, nil), plain...); err != nil {
		t.Fatalf("plaintext dial to a plaintext server: %v", err)
	}

	p := mtlstest.Provider(t)
	secure, err := auditDialOptions(p, none)
	if err != nil {
		t.Fatal(err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, p), secure...); err != nil {
		t.Fatalf("mutual TLS dial to a mutual TLS server: %v", err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, nil), secure...); err == nil {
		t.Fatal("a mutual TLS client reached a plaintext server")
	}
}
