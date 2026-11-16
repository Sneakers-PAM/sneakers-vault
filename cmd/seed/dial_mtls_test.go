// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/Bugs5382/go-mtls"
	"github.com/Sneakers-PAM/sneakers-vault/internal/mtlstest"
)

func TestDialOption_PlaintextWithoutTheFiles(t *testing.T) {
	opt, err := dialOption(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, nil), opt); err != nil {
		t.Fatalf("plaintext dial to a plaintext server: %v", err)
	}
}

func TestDialOption_MutualTLSWhenTheFilesAreSet(t *testing.T) {
	files := mtlstest.Files(t)
	p, err := mtls.NewProvider(files)
	if err != nil {
		t.Fatal(err)
	}
	opt, err := dialOption(mtlstest.Env(files))
	if err != nil {
		t.Fatal(err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, p), opt); err != nil {
		t.Fatalf("mutual TLS dial to a mutual TLS server: %v", err)
	}
	if err := mtlstest.CallHealth(t, mtlstest.HealthServer(t, nil), opt); err == nil {
		t.Fatal("a mutual TLS client reached a plaintext server")
	}
}

func TestDialOption_HalfSetFilesRefuse(t *testing.T) {
	files := mtlstest.Files(t)
	env := mtlstest.Env(files)
	if _, err := dialOption(func(k string) string {
		if k == mtls.EnvKeyFile {
			return ""
		}
		return env(k)
	}); err == nil {
		t.Fatal("a half-set switch fell back to plaintext")
	}
}
