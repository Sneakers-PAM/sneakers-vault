// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package vaultclient dials the vault service's gRPC endpoint on behalf of
// the workflow service (rotation triggers: manual, check-in, break-glass,
// lease-expiry all resolve to vault.EnqueueRotation calls).
package vaultclient

import (
	"context"
	"os"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// defaultAddr is the vault's local development address.
const defaultAddr = "localhost:9091"

// Client wraps the dialled gRPC connection alongside the generated vault
// client so callers get one value to hold and Close, while still satisfying
// vaultv1.VaultServiceClient directly (via the embedded interface) for
// passing into grpcsvc.BuildEngine.
type Client struct {
	conn *grpc.ClientConn
	vaultv1.VaultServiceClient
}

// Conn is the dialled connection, for the vault's own health check.
func (c *Client) Conn() grpc.ClientConnInterface { return c.conn }

// selfMethods are the vault calls the workflow makes as itself. The vault
// refuses an actor on them from the workflow and acts as its own
// system:workflow actor instead (CallerPolicy in internal/vault/grpcsvc).
var selfMethods = map[string]bool{
	vaultv1.VaultService_GetSecret_FullMethodName:           true,
	vaultv1.VaultService_ListSecretTypes_FullMethodName:     true,
	vaultv1.VaultService_GetSecretRuleset_FullMethodName:    true,
	vaultv1.VaultService_SetSecretRuleset_FullMethodName:    true,
	vaultv1.VaultService_MoveFolder_FullMethodName:          true,
	vaultv1.VaultService_UpdateSecret_FullMethodName:        true,
	vaultv1.VaultService_EnqueueRotation_FullMethodName:     true,
	vaultv1.VaultService_GetSecuritySettings_FullMethodName: true,
}

// asSelf drops the actor from a self method's request. The workflow code
// still builds its legacy system actor for a vault running with
// authentication disabled (local development), where nothing identifies the
// caller; with a workload token the vault knows it is the workflow.
func asSelf(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if m, ok := req.(proto.Message); ok && selfMethods[method] {
		c := proto.Clone(m)
		r := c.ProtoReflect()
		if fd := r.Descriptor().Fields().ByName("actor"); fd != nil {
			r.Clear(fd)
		}
		req = c
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

// Dial connects to VAULT_ADDR (env, default localhost:9091) over plaintext
// gRPC with the OTel client stats handler. With WORKLOAD_TOKEN_FILE set it
// sends the workflow's workload token on every call and calls the self
// methods as itself.
func Dial() (*Client, error) {
	addr := env("VAULT_ADDR", defaultAddr)
	auth, err := server.ClientAuth(os.Getenv)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler()}
	if len(auth) > 0 {
		opts = append(append(opts, auth...), grpc.WithChainUnaryInterceptor(asSelf))
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, VaultServiceClient: vaultv1.NewVaultServiceClient(conn)}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
