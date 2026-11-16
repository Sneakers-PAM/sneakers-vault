// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// HeaderRootKey carries the root key replacement status on a readiness health
// check's response: JSON {"state":"none|in-progress|verified|failed",
// "pending":N}, where pending is the number of working keys not yet on the
// current root key. It carries no key, no wrapped key and no key name.
const HeaderRootKey = "sneakers-root-key"

// RootKeyService is the health service name that answers yes or no for the
// same status: SERVING for none and verified, NOT_SERVING otherwise.
const RootKeyService = "root-key-rotation"

// RootKeyStatus is the root key replacement status the vault reports. The zero
// value is none.
type RootKeyStatus struct {
	mu      sync.Mutex
	state   crypto.RotationState
	pending int
}

// Set records the state and the number of working keys not yet on the current root.
func (r *RootKeyStatus) Set(state crypto.RotationState, pending int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state, r.pending = state, pending
}

// Get returns the state and the pending count.
func (r *RootKeyStatus) Get() (crypto.RotationState, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == "" {
		return crypto.RotationNone, 0
	}
	return r.state, r.pending
}

func (r *RootKeyStatus) header() string {
	st, n := r.Get()
	b, _ := json.Marshal(struct {
		State   crypto.RotationState `json:"state"`
		Pending int                  `json:"pending"`
	}{st, n})
	return string(b)
}

func (r *RootKeyStatus) serving() healthpb.HealthCheckResponse_ServingStatus {
	if st, _ := r.Get(); st == crypto.RotationNone || st == crypto.RotationVerified {
		return healthpb.HealthCheckResponse_SERVING
	}
	return healthpb.HealthCheckResponse_NOT_SERVING
}

// rootKeyUnary adds the status header to the readiness check and answers the
// root-key-rotation service itself. It runs ahead of the build-info handler,
// which would otherwise treat that service name as unknown.
func rootKeyUnary(rs *RootKeyStatus) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if r, ok := req.(*healthpb.HealthCheckRequest); ok && info.FullMethod == healthCheckMethod {
			switch r.GetService() {
			case "":
				_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderRootKey, rs.header()))
			case RootKeyService:
				_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderRootKey, rs.header()))
				return &healthpb.HealthCheckResponse{Status: rs.serving()}, nil
			}
		}
		return handler(ctx, req)
	}
}

// rootKeyOption carries a RootKeyStatus through RunWithHealthTLS's options. It
// is not a gRPC option itself: RunWithHealthTLS takes it out of the list.
type rootKeyOption struct {
	grpc.EmptyServerOption
	rs *RootKeyStatus
}

// WithRootKeyStatus makes RunWithHealthTLS report rs on the health check of the
// service port and of the plain health port.
func WithRootKeyStatus(rs *RootKeyStatus) grpc.ServerOption {
	return rootKeyOption{rs: rs}
}

// splitRootKey takes a rootKeyOption out of opts.
func splitRootKey(opts []grpc.ServerOption) (*RootKeyStatus, []grpc.ServerOption) {
	var rs *RootKeyStatus
	rest := make([]grpc.ServerOption, 0, len(opts))
	for _, o := range opts {
		if k, ok := o.(rootKeyOption); ok {
			rs = k.rs
			continue
		}
		rest = append(rest, o)
	}
	return rs, rest
}
