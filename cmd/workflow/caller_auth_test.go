// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
)

func TestCallerAuth_UnsetIssuerFailsToBoot(t *testing.T) {
	if _, err := callerAuth(context.Background(), func(string) string { return "" }, log.Nop()); !errors.Is(err, workloadauth.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts, err := callerAuth(ctx, func(k string) string {
		if k == workloadauth.EnvAuthMode {
			return workloadauth.AuthDisabled
		}
		return ""
	}, log.Nop())
	if err != nil || len(opts) != 0 {
		t.Fatalf("WORKLOAD_AUTH=disabled: opts=%d err=%v", len(opts), err)
	}
}
