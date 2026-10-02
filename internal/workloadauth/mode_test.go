// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
)

func TestServerConfigFromEnvFailsClosed(t *testing.T) {
	_, enabled, err := ServerConfigFromEnv(envMap(nil))
	if !errors.Is(err, ErrNotConfigured) || enabled {
		t.Fatalf("unset issuer: enabled=%v err=%v, want ErrNotConfigured", enabled, err)
	}
	for _, v := range []string{"off", "false", "Disabled "} {
		if _, _, err := ServerConfigFromEnv(envMap(map[string]string{EnvAuthMode: v})); err == nil {
			t.Fatalf("WORKLOAD_AUTH=%q should be refused", v)
		}
	}
}

func TestServerConfigFromEnvExplicitlyDisabled(t *testing.T) {
	_, enabled, err := ServerConfigFromEnv(envMap(map[string]string{EnvAuthMode: AuthDisabled}))
	if err != nil || enabled {
		t.Fatalf("enabled=%v err=%v, want disabled", enabled, err)
	}
}

func TestServerConfigFromEnvIssuerAndDisabledConflict(t *testing.T) {
	_, _, err := ServerConfigFromEnv(envMap(map[string]string{
		EnvAuthMode: AuthDisabled, EnvIssuer: "https://issuer.example.org", EnvAllowedServiceAccounts: "sneakers/sneakers-gateway",
	}))
	if err == nil {
		t.Fatal("an issuer together with WORKLOAD_AUTH=disabled should be refused")
	}
}

func TestServerConfigFromEnvEnabled(t *testing.T) {
	cfg, enabled, err := ServerConfigFromEnv(envMap(map[string]string{
		EnvIssuer: "https://issuer.example.org", EnvAllowedServiceAccounts: "sneakers/sneakers-gateway",
	}))
	if err != nil || !enabled || cfg.Issuer != "https://issuer.example.org" {
		t.Fatalf("cfg=%+v enabled=%v err=%v", cfg, enabled, err)
	}
}

type countingLogger struct {
	log.Logger
	warns atomic.Int32
}

func (c *countingLogger) Warn(string, ...log.Field) { c.warns.Add(1) }

func TestWarnDisabledRepeats(t *testing.T) {
	l := &countingLogger{Logger: log.Nop()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { WarnDisabled(ctx, l, 10*time.Millisecond); close(done) }()
	deadline := time.After(5 * time.Second)
	for l.warns.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d warnings", l.warns.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}
