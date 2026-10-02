// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// freePort returns an ephemeral TCP port that was free at the moment the
// listener was closed. There is an inherent race; tests can retry on bind
// failure if it becomes flaky.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return strconv.Itoa(port)
}

// TestRun_GracefulShutdownOnCancel verifies Run returns nil shortly after
// its context is cancelled.
func TestRun_GracefulShutdownOnCancel(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, port, func(*grpc.Server) {})
	}()

	// Give the server a moment to bind.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit within 5s of cancellation")
	}
}
