// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
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

// TestRunWithLogger_GracefulShutdownOnCancel verifies RunWithLogger returns nil shortly after
// its context is cancelled.
func TestRunWithLogger_GracefulShutdownOnCancel(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithLogger(ctx, port, log.Nop(), func(*grpc.Server) {})
	}()

	// Give the server a moment to bind.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunWithLogger returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunWithLogger did not exit within 5s of cancellation")
	}
}
