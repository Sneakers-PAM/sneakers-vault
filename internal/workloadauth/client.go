// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// tokenCredentials sends the caller's projected token on every call.
type tokenCredentials struct{ path string }

// NewTokenCredentials returns per-call credentials that read the token at path
// on every call, so a token the kubelet rotates in place is picked up, and
// send it as "authorization: Bearer <token>".
func NewTokenCredentials(path string) credentials.PerRPCCredentials {
	return tokenCredentials{path: path}
}

func (c tokenCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	tok, err := readToken(c.path)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity is false: the services speak plaintext gRPC inside
// the cluster, where the NetworkPolicies limit who can connect at all.
func (tokenCredentials) RequireTransportSecurity() bool { return false }

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return "", fmt.Errorf("workloadauth: read %s: %w", EnvTokenFile, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("workloadauth: %s %q is empty", EnvTokenFile, path)
	}
	return tok, nil
}

// DialOptionFromEnv returns the dial option that sends the token named by
// WORKLOAD_TOKEN_FILE. ok is false when the variable is unset, so the caller
// sends no token. A set path that can't be read now is an error, so a missing
// mount fails start-up instead of every call.
func DialOptionFromEnv(getenv func(string) string) (opt grpc.DialOption, ok bool, err error) {
	path := strings.TrimSpace(getenv(EnvTokenFile))
	if path == "" {
		return nil, false, nil
	}
	if _, err := readToken(path); err != nil {
		return nil, false, err
	}
	return grpc.WithPerRPCCredentials(NewTokenCredentials(path)), true, nil
}
