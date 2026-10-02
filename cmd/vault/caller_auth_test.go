// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
)

func TestCallerAuth_UnsetIssuerFailsToBoot(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	srv := grpcsvc.New(crypto.New(kek), nil)
	for _, environment := range []string{"dev", "production"} {
		getenv := func(k string) string {
			if k == "ENVIRONMENT" {
				return environment
			}
			return ""
		}
		if _, err := callerAuth(context.Background(), getenv, log.Nop(), srv); !errors.Is(err, workloadauth.ErrNotConfigured) {
			t.Fatalf("%s: err = %v, want ErrNotConfigured", environment, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts, err := callerAuth(ctx, func(k string) string {
		if k == workloadauth.EnvAuthMode {
			return workloadauth.AuthDisabled
		}
		return ""
	}, log.Nop(), srv)
	if err != nil || len(opts) != 0 {
		t.Fatalf("WORKLOAD_AUTH=disabled: opts=%d err=%v", len(opts), err)
	}
}
