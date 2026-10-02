// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
)

// generateEncryptedEd25519 returns an OpenSSH-PEM private key encrypted under
// passphrase, plus its corresponding authorized_keys public key line —
// exercising the ssh.PassphraseMissingError path verifyKeyPair must handle.
func generateEncryptedEd25519(t *testing.T, passphrase string) (privPEM, pubAuthorized string) {
	t.Helper()
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privKey, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(block)), string(ssh.MarshalAuthorizedKey(sshPub))
}

func TestVerifyKeyPairMatchingPair(t *testing.T) {
	priv, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	if err := verifyKeyPair(priv, pub, ""); err != nil {
		t.Fatalf("verifyKeyPair(matching pair) = %v, want nil", err)
	}
}

func TestVerifyKeyPairMismatchedPair(t *testing.T) {
	priv, _, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair #1: %v", err)
	}
	_, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair #2: %v", err)
	}
	err = verifyKeyPair(priv, pub, "")
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

func TestVerifyKeyPairOnlyPrivatePresent(t *testing.T) {
	priv, _, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	if err := verifyKeyPair(priv, "", ""); err != nil {
		t.Fatalf("verifyKeyPair(only private) = %v, want nil", err)
	}
}

func TestVerifyKeyPairOnlyPublicPresent(t *testing.T) {
	_, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	if err := verifyKeyPair("", pub, ""); err != nil {
		t.Fatalf("verifyKeyPair(only public) = %v, want nil", err)
	}
}

func TestVerifyKeyPairNeitherPresent(t *testing.T) {
	if err := verifyKeyPair("", "", ""); err != nil {
		t.Fatalf("verifyKeyPair(neither) = %v, want nil", err)
	}
}

func TestVerifyKeyPairGarbagePrivateKeyWithPublicKey(t *testing.T) {
	_, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	err = verifyKeyPair("not a private key", pub, "")
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

func TestVerifyKeyPairGarbagePublicKeyWithPrivateKey(t *testing.T) {
	priv, _, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	err = verifyKeyPair(priv, "not a public key", "")
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

func TestVerifyKeyPairPassphraseEncryptedNoPassphraseSkips(t *testing.T) {
	priv, pub := generateEncryptedEd25519(t, "correct-horse")
	if err := verifyKeyPair(priv, pub, ""); err != nil {
		t.Fatalf("verifyKeyPair(encrypted, no passphrase) = %v, want nil (skipped)", err)
	}
}

func TestVerifyKeyPairPassphraseEncryptedCorrectPassphraseMatches(t *testing.T) {
	priv, pub := generateEncryptedEd25519(t, "correct-horse")
	if err := verifyKeyPair(priv, pub, "correct-horse"); err != nil {
		t.Fatalf("verifyKeyPair(encrypted, correct passphrase) = %v, want nil", err)
	}
}

func TestVerifyKeyPairPassphraseEncryptedWrongPassphraseFails(t *testing.T) {
	priv, pub := generateEncryptedEd25519(t, "correct-horse")
	err := verifyKeyPair(priv, pub, "wrong-passphrase")
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

func TestVerifyKeyPairPassphraseEncryptedMismatchedPubWithPassphrase(t *testing.T) {
	priv, _ := generateEncryptedEd25519(t, "correct-horse")
	_, otherPub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	err = verifyKeyPair(priv, otherPub, "correct-horse")
	if code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", code(err))
	}
}

// TestCreateSecretRejectsMismatchedSSHKeyPair proves the authoritative
// server-side check rejects a create carrying a private key and a
// public key that don't correspond, even though both parse fine individually.
func TestCreateSecretRejectsMismatchedSSHKeyPair(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)

	priv, _, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair #1: %v", err)
	}
	_, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair #2: %v", err)
	}

	_, err = s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "bad-pair", FolderId: fid, TypeId: "type-ssh-key",
		Fields: map[string]string{
			"username":   "deploy",
			"keyFormat":  "Ed25519",
			"privateKey": priv,
			"publicKey":  pub,
		},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("CreateSecret(mismatched key pair) code = %v, want InvalidArgument", code(err))
	}
}

// TestCreateSecretAcceptsMatchingSSHKeyPair is the control: a genuinely
// corresponding pair must not be rejected by the new check.
func TestCreateSecretAcceptsMatchingSSHKeyPair(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)

	priv, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}

	_, err = s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "good-pair", FolderId: fid, TypeId: "type-ssh-key",
		Fields: map[string]string{
			"username":   "deploy",
			"keyFormat":  "Ed25519",
			"privateKey": priv,
			"publicKey":  pub,
		},
	})
	if err != nil {
		t.Fatalf("CreateSecret(matching key pair): %v", err)
	}
}

// TestUpdateSecretRejectsMismatchedSSHKeyPair proves the same authoritative
// check runs on the re-sealed "merged" plaintext an update produces, not just
// on a fresh create.
func TestUpdateSecretRejectsMismatchedSSHKeyPair(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)

	priv, pub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "good-pair", FolderId: fid, TypeId: "type-ssh-key",
		Fields: map[string]string{
			"username":   "deploy",
			"keyFormat":  "Ed25519",
			"privateKey": priv,
			"publicKey":  pub,
		},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	_, otherPub, err := generateKeyPair("Ed25519")
	if err != nil {
		t.Fatalf("generateKeyPair #2: %v", err)
	}
	_, err = s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: created.GetSecret().GetId(),
		Fields: map[string]string{"publicKey": otherPub},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("UpdateSecret(mismatched key pair) code = %v, want InvalidArgument", code(err))
	}
}
