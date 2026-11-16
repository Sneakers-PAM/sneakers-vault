// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-mtls"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type rootKeyHeader struct {
	State   string `json:"state"`
	Pending int    `json:"pending"`
}

// checkRoot calls the health check for service on a plaintext connection and
// returns the response status, the sneakers-root-key header (nil when absent)
// and the error.
func checkRoot(t *testing.T, addr, service string) (healthpb.HealthCheckResponse_ServingStatus, *rootKeyHeader, error) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var hdr metadata.MD
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&hdr))
	if err != nil {
		return 0, nil, err
	}
	var h *rootKeyHeader
	if v := hdr.Get(HeaderRootKey); len(v) == 1 {
		h = &rootKeyHeader{}
		if err := json.Unmarshal([]byte(v[0]), h); err != nil {
			t.Fatalf("header %q: %v", v[0], err)
		}
	}
	return resp.GetStatus(), h, nil
}

func serveWithRootKey(t *testing.T, rs *RootKeyStatus) string {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithHealthTLS(ctx, port, "", nil, log.Nop(), nil, func(*grpc.Server) {}, WithRootKeyStatus(rs))
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitDial(t, "127.0.0.1:"+port)
	return "127.0.0.1:" + port
}

func TestRootKeyStatus_HeaderOnTheHealthCheck(t *testing.T) {
	rs := &RootKeyStatus{}
	rs.Set(crypto.RotationInProgress, 3)
	addr := serveWithRootKey(t, rs)
	_, h, err := checkRoot(t, addr, "")
	if err != nil || h == nil || *h != (rootKeyHeader{"in-progress", 3}) {
		t.Fatalf("header=%v err=%v, want in-progress with 3 pending", h, err)
	}
	rs.Set(crypto.RotationFailed, 2)
	if _, h, _ = checkRoot(t, addr, ""); h == nil || *h != (rootKeyHeader{"failed", 2}) {
		t.Fatalf("header=%v, want failed with 2 pending", h)
	}
	rs.Set(crypto.RotationVerified, 0)
	if _, h, _ = checkRoot(t, addr, ""); h == nil || *h != (rootKeyHeader{"verified", 0}) {
		t.Fatalf("header=%v, want verified, 0", h)
	}
}

func TestRootKeyStatus_NoneIsTheDefaultAndCarriesNoKeyMaterial(t *testing.T) {
	rs := &RootKeyStatus{}
	if st, n := rs.Get(); st != crypto.RotationNone || n != 0 {
		t.Fatalf("zero value %s %d, want none, 0", st, n)
	}
	addr := serveWithRootKey(t, rs)
	conn, _ := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer func() { _ = conn.Close() }()
	var hdr metadata.MD
	if _, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{}, grpc.Header(&hdr)); err != nil {
		t.Fatal(err)
	}
	if v := strings.Join(hdr.Get(HeaderRootKey), ""); v != `{"state":"none","pending":0}` {
		t.Fatalf("header %q, want exactly the state and the count", v)
	}
}

func TestRootKeyStatus_YesNoHealthService(t *testing.T) {
	rs := &RootKeyStatus{}
	addr := serveWithRootKey(t, rs)
	for _, c := range []struct {
		state crypto.RotationState
		want  healthpb.HealthCheckResponse_ServingStatus
	}{
		{crypto.RotationNone, healthpb.HealthCheckResponse_SERVING},
		{crypto.RotationVerified, healthpb.HealthCheckResponse_SERVING},
		{crypto.RotationInProgress, healthpb.HealthCheckResponse_NOT_SERVING},
		{crypto.RotationFailed, healthpb.HealthCheckResponse_NOT_SERVING},
	} {
		rs.Set(c.state, 1)
		got, _, err := checkRoot(t, addr, RootKeyService)
		if err != nil || got != c.want {
			t.Fatalf("%s: %v %v, want %v", c.state, got, err, c.want)
		}
	}
}

func TestRootKeyStatus_AbsentWithoutTheOption(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealthTLS(ctx, port, "", nil, log.Nop(), nil, func(*grpc.Server) {}) }()
	t.Cleanup(func() { cancel(); <-done })
	waitDial(t, "127.0.0.1:"+port)
	if _, h, err := checkRoot(t, "127.0.0.1:"+port, ""); err != nil || h != nil {
		t.Fatalf("header=%v err=%v, want no header", h, err)
	}
	if _, _, err := checkRoot(t, "127.0.0.1:"+port, RootKeyService); status.Code(err) != codes.NotFound {
		t.Fatalf("err=%v, want NotFound for an unknown service", err)
	}
}

func TestRootKeyStatus_OnTheBootHealthService(t *testing.T) {
	port := freePort(t)
	b, err := StartBootHealth(port, log.Nop(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	rs := &RootKeyStatus{}
	rs.Set(crypto.RotationInProgress, 4)
	b.SetRootKeyStatus(rs)
	_, h, err := checkRoot(t, "127.0.0.1:"+port, "")
	if err != nil || h == nil || *h != (rootKeyHeader{"in-progress", 4}) {
		t.Fatalf("header=%v err=%v, want in-progress with 4 pending while the vault is still starting", h, err)
	}
}

func TestRootKeyStatus_OnThePlainHealthPortWithMutualTLS(t *testing.T) {
	rs := &RootKeyStatus{}
	rs.Set(crypto.RotationVerified, 0)
	p := mtlsProvider(t)
	port, healthPort := freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunWithHealthTLS(ctx, port, healthPort, p, log.Nop(), nil, func(*grpc.Server) {}, WithRootKeyStatus(rs))
	}()
	t.Cleanup(func() { cancel(); <-done })
	waitDial(t, "127.0.0.1:"+healthPort)
	if _, h, err := checkRoot(t, "127.0.0.1:"+healthPort, ""); err != nil || h == nil || h.State != "verified" {
		t.Fatalf("header=%v err=%v, want verified on the plain health port, no certificate", h, err)
	}
}

func mtlsProvider(t *testing.T) *mtls.Provider {
	t.Helper()
	p, err := mtls.NewProvider(mtlsFiles(t, newTestCA(t)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
