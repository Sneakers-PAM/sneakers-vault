// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
)

// awaitFirstPass waits until c's background refresh has checked every
// dependency once, so the report holds real results instead of "pending".
func awaitFirstPass(t *testing.T, c *health.Checker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending := false
		for _, d := range c.Report(context.Background()).Dependencies {
			pending = pending || d.Error == ClassPending
		}
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the first background refresh never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// refreshed runs c's background refresh for the test, as RunWithHealth does,
// and waits for its first pass.
func refreshed(t *testing.T, c *health.Checker) *health.Checker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	awaitFirstPass(t, c)
	return c
}

// A readiness report never waits on a check: while one hangs, Report
// answers from the cache at once.
func TestNewChecker_ReportNeverWaitsOnACheck(t *testing.T) {
	slow := make(chan struct{}, 1)
	c, err := NewChecker(log.Nop(), []health.Dependency{{Name: "postgres", Required: true, Check: func(ctx context.Context) error {
		select {
		case <-slow:
			<-ctx.Done()
			return ctx.Err()
		default:
			return nil
		}
	}}}, health.WithTTL(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	refreshed(t, c)
	slow <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	for range 10 {
		start := time.Now()
		c.Report(context.Background())
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("Report took %v during a slow check, want a cache read", d)
		}
	}
}
