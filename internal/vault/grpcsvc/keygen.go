// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RSA modulus sizes for the two RSA keyFormat options.
const (
	rsa4096Bits = 4096
	rsa2048Bits = 2048
)

// generateKeyPair generates a fresh SSH keypair using crypto/rand for exactly
// the four formats offered by the UI's keyFormat select (type-ssh-key,
// builtins.go). The private key is returned as an OpenSSH PEM (unencrypted —
// any passphrase is applied by the caller/UI, never by this helper), the
// public key as an authorized_keys line. The returned private key material
// MUST NEVER be logged.
func generateKeyPair(format string) (privateKeyPEM string, publicKeyAuthorized string, err error) {
	var block *pem.Block
	var pub any

	switch format {
	case "Ed25519":
		pubKey, privKey, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return "", "", fmt.Errorf("keygen: generate ed25519: %w", genErr)
		}
		block, err = ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return "", "", fmt.Errorf("keygen: marshal ed25519 private key: %w", err)
		}
		pub = pubKey
	case "RSA 4096":
		privKey, genErr := rsa.GenerateKey(rand.Reader, rsa4096Bits)
		if genErr != nil {
			return "", "", fmt.Errorf("keygen: generate rsa-4096: %w", genErr)
		}
		block, err = ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return "", "", fmt.Errorf("keygen: marshal rsa-4096 private key: %w", err)
		}
		pub = &privKey.PublicKey
	case "RSA 2048":
		privKey, genErr := rsa.GenerateKey(rand.Reader, rsa2048Bits)
		if genErr != nil {
			return "", "", fmt.Errorf("keygen: generate rsa-2048: %w", genErr)
		}
		block, err = ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return "", "", fmt.Errorf("keygen: marshal rsa-2048 private key: %w", err)
		}
		pub = &privKey.PublicKey
	case "ECDSA P-256":
		privKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return "", "", fmt.Errorf("keygen: generate ecdsa p-256: %w", genErr)
		}
		block, err = ssh.MarshalPrivateKey(privKey, "")
		if err != nil {
			return "", "", fmt.Errorf("keygen: marshal ecdsa p-256 private key: %w", err)
		}
		pub = &privKey.PublicKey
	default:
		return "", "", fmt.Errorf("keygen: unsupported format %q", format)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("keygen: derive public key: %w", err)
	}

	return string(pem.EncodeToMemory(block)), string(ssh.MarshalAuthorizedKey(sshPub)), nil
}

// GenerateKeyPair generates a fresh server-side SSH keypair for one of the
// keyFormat options offered by type-ssh-key (Ed25519, RSA 4096, RSA 2048,
// ECDSA P-256). The response carries the private key in plaintext — the same
// pattern as RevealSecretField — protected in transit by the gRPC/TLS
// channel, not by an additional application-layer seal. The key material is
// never logged, and only the requested format (never the key itself) is
// recorded in the audit trail.
func (s *Server) GenerateKeyPair(ctx context.Context, req *vaultv1.GenerateKeyPairRequest) (*vaultv1.GenerateKeyPairResponse, error) {
	format := req.GetFormat()
	switch format {
	case "Ed25519", "RSA 4096", "RSA 2048", "ECDSA P-256":
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key format %q", format)
	}

	priv, pub, err := generateKeyPair(format)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate keypair: %v", err)
	}

	s.emitAttrs(ctx, req.GetActor().GetUserId(), "keypair.generate", "", true, map[string]string{"format": format})

	return &vaultv1.GenerateKeyPairResponse{PrivateKey: priv, PublicKey: pub}, nil
}
