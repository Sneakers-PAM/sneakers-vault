// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
)

// keyPairFormats mirrors the exact keyFormat select options seeded for
// type-ssh-key (builtins.go) and their expected authorized_keys algo name.
var keyPairFormats = []struct {
	format string
	algo   string
}{
	{"Ed25519", ssh.KeyAlgoED25519},
	{"RSA 4096", ssh.KeyAlgoRSA},
	{"RSA 2048", ssh.KeyAlgoRSA},
	{"ECDSA P-256", ssh.KeyAlgoECDSA256},
}

func TestGenerateKeyPairFormats(t *testing.T) {
	for _, tc := range keyPairFormats {
		t.Run(tc.format, func(t *testing.T) {
			priv, pub, err := generateKeyPair(tc.format)
			if err != nil {
				t.Fatalf("generateKeyPair(%q): %v", tc.format, err)
			}

			if !strings.Contains(priv, "PRIVATE KEY") {
				t.Fatalf("private key does not contain PRIVATE KEY marker: %q", priv)
			}
			signer, err := ssh.ParsePrivateKey([]byte(priv))
			if err != nil {
				t.Fatalf("ssh.ParsePrivateKey: %v", err)
			}

			pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}
			if pubKey.Type() != tc.algo {
				t.Fatalf("public key type = %q, want %q", pubKey.Type(), tc.algo)
			}

			// The public key returned alongside the private key must correspond
			// to it: the signer derived from the private key must marshal to
			// the same bytes as the parsed authorized-keys public key.
			if !bytes.Equal(signer.PublicKey().Marshal(), pubKey.Marshal()) {
				t.Fatalf("public key does not correspond to private key for format %q", tc.format)
			}

			// Randomness: a second generation must differ from the first.
			priv2, pub2, err := generateKeyPair(tc.format)
			if err != nil {
				t.Fatalf("generateKeyPair(%q) #2: %v", tc.format, err)
			}
			if priv2 == priv {
				t.Fatalf("two generations produced identical private keys for format %q", tc.format)
			}
			if pub2 == pub {
				t.Fatalf("two generations produced identical public keys for format %q", tc.format)
			}
		})
	}
}

func TestGenerateKeyPairUnsupportedFormat(t *testing.T) {
	if _, _, err := generateKeyPair("DSA 1024"); err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if _, _, err := generateKeyPair(""); err == nil {
		t.Fatal("expected error for empty format, got nil")
	}
}

func TestServerGenerateKeyPairValidFormat(t *testing.T) {
	s := newServer(t)
	for _, tc := range keyPairFormats {
		t.Run(tc.format, func(t *testing.T) {
			resp, err := s.GenerateKeyPair(context.Background(), &vaultv1.GenerateKeyPairRequest{
				Actor:  &vaultv1.ActorContext{UserId: "user-carol"},
				Format: tc.format,
			})
			if err != nil {
				t.Fatalf("GenerateKeyPair(%q): %v", tc.format, err)
			}
			if resp.GetPrivateKey() == "" {
				t.Fatal("private key is empty")
			}
			if resp.GetPublicKey() == "" {
				t.Fatal("public key is empty")
			}
		})
	}
}

func TestServerGenerateKeyPairUnknownFormat(t *testing.T) {
	s := newServer(t)
	_, err := s.GenerateKeyPair(context.Background(), &vaultv1.GenerateKeyPairRequest{
		Actor:  &vaultv1.ActorContext{UserId: "user-carol"},
		Format: "DSA 1024",
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

func TestServerGenerateKeyPairEmptyFormat(t *testing.T) {
	s := newServer(t)
	_, err := s.GenerateKeyPair(context.Background(), &vaultv1.GenerateKeyPairRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}
