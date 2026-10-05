// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"

	"github.com/Sneakers-PAM/sneakers-vault/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HeaderHealth carries a readiness check's dependency report as compact JSON.
const HeaderHealth = "sneakers-health"

// LivenessService is the health service name liveness probes ask for. It
// answers SERVING whenever the process does, touching no dependency.
const LivenessService = "liveness"

// healthServer is the standard grpc.health.v1 service with readiness taken
// from the dependency checker: service "" is readiness, "liveness" is
// liveness, anything else is NOT_FOUND.
type healthServer struct {
	healthpb.UnimplementedHealthServer
	checker *health.Checker
}

func newHealthServer(c *health.Checker) *healthServer {
	if c == nil {
		c = health.New(nil)
	}
	return &healthServer{checker: c}
}

func (h *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	switch req.GetService() {
	case LivenessService:
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	case "":
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	r := h.checker.Report(ctx)
	for i := range r.Dependencies {
		r.Dependencies[i].Version = DependencyVersion(r.Dependencies[i].Name)
	}
	if b, err := json.Marshal(r); err == nil {
		_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(b)))
	}
	if r.Status == health.StatusDown {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}, nil
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (h *healthServer) Watch(*healthpb.HealthCheckRequest, healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "watch is not supported; poll Check")
}
