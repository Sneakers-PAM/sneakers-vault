// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

type unavailableVerifier struct{}

func (unavailableVerifier) Verify(string) (workloadid.Principal, error) {
	return workloadid.Principal{}, fmt.Errorf("wrapped: %w", workloadid.ErrUnavailable)
}

func TestVerifyWorkerUnavailableWhenVerifierUnavailable(t *testing.T) {
	s := &Server{wid: unavailableVerifier{}}
	_, err := s.verifyWorker(context.Background(), &vaultv1.WorkerIdentity{Token: "t"})
	if code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

func TestVerifyWorkerRejectedIsPermissionDenied(t *testing.T) {
	s := &Server{wid: rejectVerifier{}}
	_, err := s.verifyWorker(context.Background(), &vaultv1.WorkerIdentity{Token: "t"})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func oidcVerifierFor(t *testing.T, iss *oidctest.Issuer) *workloadid.OIDCVerifier {
	t.Helper()
	v, err := workloadid.NewOIDCVerifier(workloadid.OIDCConfig{
		Issuer:                 iss.URL,
		CAFile:                 iss.CAFile,
		Audience:               workloadid.DefaultAudience,
		AllowedServiceAccounts: []string{"apps/connector"},
	}, log.Nop())
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	return v
}

// serveVault runs s on a loopback gRPC server and returns a client for it.
func serveVault(t *testing.T, s *Server) vaultv1.VaultServiceClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	s.RegisterInto(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return vaultv1.NewVaultServiceClient(conn)
}

func connectorToken(t *testing.T, iss *oidctest.Issuer, ns, sa string) string {
	t.Helper()
	return iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256,
		oidctest.ServiceAccountClaims(iss.URL, workloadid.DefaultAudience, ns, sa, time.Now()))
}

func TestClaimDueHeartbeatsOIDCDeniedOverGRPC(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	s := newServer(t)
	s.wid = oidcVerifierFor(t, iss)
	client := serveVault(t, s)
	ctx := context.Background()

	_, err := client.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{
		Identity: &vaultv1.WorkerIdentity{Token: connectorToken(t, iss, "apps", "intruder")},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("SA not on the list: want PermissionDenied, got %v", err)
	}
	_, err = client.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "dev-connector-token"},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("dev token against the OIDC verifier: want PermissionDenied, got %v", err)
	}

	iss.Fail.Store(true)
	down := newServer(t)
	down.wid = oidcVerifierFor(t, iss)
	_, err = serveVault(t, down).ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{
		Identity: &vaultv1.WorkerIdentity{Token: connectorToken(t, iss, "apps", "connector")},
	})
	if code(err) != codes.Unavailable {
		t.Fatalf("no key set: want Unavailable, got %v", err)
	}
}

func TestClaimDueHeartbeatsOIDCEndToEnd(t *testing.T) {
	fx := newNoTargetFixture(t)
	iss := oidctest.NewIssuer(t)
	fx.s.wid = oidcVerifierFor(t, iss)
	sid := fx.createHuman(t, fx.target)
	client := serveVault(t, fx.s)

	resp, err := client.ClaimDueHeartbeats(context.Background(), &vaultv1.ClaimDueHeartbeatsRequest{
		Identity: &vaultv1.WorkerIdentity{Token: connectorToken(t, iss, "apps", "connector")},
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("ClaimDueHeartbeats with an OIDC token: %v", err)
	}
	if len(resp.GetJobs()) != 1 || resp.GetJobs()[0].GetSecretId() != sid {
		t.Fatalf("jobs %v; want exactly %s", resp.GetJobs(), sid)
	}
}
