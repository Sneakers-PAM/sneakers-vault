// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// reportedClass is the error class the readiness report gives check's error.
func reportedClass(t *testing.T, check func(context.Context) error) string {
	t.Helper()
	c, err := NewChecker(log.Nop(), []health.Dependency{{Name: "dep", Check: check}})
	if err != nil {
		t.Fatal(err)
	}
	return refreshed(t, c).Report(context.Background()).Dependencies[0].Error
}

func TestClassify(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{}}
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("read: %w", os.ErrDeadlineExceeded), "timeout"},
		{fmt.Errorf("ping: %w", syscall.ECONNREFUSED), "refused"},
		{status.Error(codes.Unavailable, "x"), "unavailable"},
		{status.Error(codes.DeadlineExceeded, "x"), "timeout"},
		{status.Error(codes.Unauthenticated, "x"), "unauthenticated"},
		{status.Error(codes.PermissionDenied, "x"), "unauthenticated"},
		{status.Error(codes.Internal, "x"), "error"},
		{refused, "unavailable"},
		{errors.New("secret text"), "error"},
	}
	for _, tc := range cases {
		if got := reportedClass(t, func(context.Context) error { return tc.err }); got != tc.want {
			t.Errorf("class of %v = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestReport_NeverCarriesErrorText(t *testing.T) {
	c, err := NewChecker(log.Nop(), []health.Dependency{{Name: "postgres", Required: true, Check: func(context.Context) error {
		return errors.New("connect to db.example.test:5432 failed: password=hunter2")
	}}})
	if err != nil {
		t.Fatal(err)
	}
	r := refreshed(t, c).Report(context.Background())
	if s := fmt.Sprintf("%+v", r); strings.Contains(s, "hunter2") || strings.Contains(s, "db.example.test") {
		t.Fatalf("report leaks the error: %s", s)
	}
}
