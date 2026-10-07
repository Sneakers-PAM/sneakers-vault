// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

const probeMethod = "/sneakers.probe.v1.Probe/Call"

// probeConn serves an echo handler behind the interceptors WorkloadAuth builds
// from env and returns a client connection to it.
func probeConn(t *testing.T, env map[string]string, policy workloadauth.Policy) *grpc.ClientConn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opts, err := WorkloadAuth(ctx, envOf(env), policy, log.Nop(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(append(opts, grpc.UnknownServiceHandler(func(_ any, ss grpc.ServerStream) error {
		var in emptypb.Empty
		if err := ss.RecvMsg(&in); err != nil {
			return err
		}
		return ss.SendMsg(&emptypb.Empty{})
	}))...)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///probe",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func callWith(conn *grpc.ClientConn, token string) codes.Code {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	return status.Code(conn.Invoke(ctx, probeMethod, &emptypb.Empty{}, &emptypb.Empty{}))
}

// TestWorkloadAuthAcceptsAndRefusesTokens pins which projected tokens the
// callee accepts: the audience defaults to "sneakers", the caller name is the
// service account without its "sneakers-" prefix, and a token with the wrong
// audience or issuer, an expired one, or one from a caller not on the method's
// list is refused.
func TestWorkloadAuthAcceptsAndRefusesTokens(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	env := map[string]string{
		"WORKLOAD_OIDC_ISSUER":             iss.URL,
		"WORKLOAD_OIDC_CA_FILE":            iss.CAFile,
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway,sneakers/sneakers-audit",
	}
	conn := probeConn(t, env, workloadauth.Policy{probeMethod: {"gateway": workloadauth.Self}})

	now := time.Now()
	token := func(mutate func(jwt.MapClaims)) string {
		c := oidctest.ServiceAccountClaims(iss.URL, "sneakers", "sneakers", "sneakers-gateway", now)
		if mutate != nil {
			mutate(c)
		}
		return iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256, c)
	}
	valid := token(nil)
	deadline := time.Now().Add(5 * time.Second)
	for callWith(conn, valid) == codes.Unavailable {
		if time.Now().After(deadline) {
			t.Fatal("the verifier never loaded the issuer's keys")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sa := func(name string) func(jwt.MapClaims) {
		return func(c jwt.MapClaims) {
			c["sub"] = "system:serviceaccount:sneakers:" + name
			c["kubernetes.io"] = map[string]any{"namespace": "sneakers", "serviceaccount": map[string]any{"name": name}}
		}
	}
	cases := map[string]struct {
		token string
		want  codes.Code
	}{
		"listed caller":               {valid, codes.OK},
		"wrong audience":              {token(func(c jwt.MapClaims) { c["aud"] = []string{"other"} }), codes.Unauthenticated},
		"wrong issuer":                {token(func(c jwt.MapClaims) { c["iss"] = "https://issuer.example.org" }), codes.Unauthenticated},
		"expired":                     {token(func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }), codes.Unauthenticated},
		"caller not on the method":    {token(sa("sneakers-audit")), codes.PermissionDenied},
		"service account not allowed": {token(sa("sneakers-identity")), codes.Unauthenticated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := callWith(conn, tc.token); got != tc.want {
				t.Fatalf("code = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWorkloadConfigFromEnvSetsTheSneakersValues(t *testing.T) {
	env := map[string]string{
		"WORKLOAD_OIDC_ISSUER":             "https://issuer.example.org",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway",
		"WORKLOAD_SERVICEACCOUNT_PREFIX":   "other-",
	}
	cfg, enabled, err := WorkloadConfigFromEnv(envOf(env))
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if cfg.Audience != "sneakers" || cfg.ServiceAccountPrefix != "sneakers-" {
		t.Fatalf("audience %q prefix %q, want sneakers and sneakers-", cfg.Audience, cfg.ServiceAccountPrefix)
	}
	env["WORKLOAD_AUDIENCE"] = "vault.sneakers.example.org"
	if cfg, _, _ = WorkloadConfigFromEnv(envOf(env)); cfg.Audience != "vault.sneakers.example.org" {
		t.Fatalf("audience %q, want the configured one", cfg.Audience)
	}
	cfg, ok, err := WorkerConfigFromEnv(envOf(env))
	if err != nil || !ok || cfg.ServiceAccountPrefix != "sneakers-" || cfg.Audience != "vault.sneakers.example.org" {
		t.Fatalf("worker config %+v ok=%v err=%v", cfg, ok, err)
	}
}
