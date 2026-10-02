// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SSH key-material field keys, as seeded for type-ssh-key (builtins.go:
// username/keyFormat/publicKey/privateKey/passphrase/notes). The field-kind
// system has no marker distinguishing "this SENSITIVE field is key material"
// from any other sensitive field (type-docusign-ssh-keys and type-ssl-cert
// both also key their private key material "privateKey"), so — like
// heartbeat.go's RevealForHeartbeat, which already reads fields["privateKey"]
// and fields["passphrase"] directly — key-pair verification identifies the
// relevant fields by these fixed, conventional keys rather than by kind.
const (
	fieldSSHPrivateKey = "privateKey"
	fieldSSHPublicKey  = "publicKey"
	fieldSSHPassphrase = "passphrase"
)

// verifyKeyPair is the authoritative, server-side counterpart to the
// client-side (advisory-only, bypassable) JS check that an SSH private key
// and public key submitted together actually correspond. priv/pub are
// the raw field values (OpenSSH PEM / authorized_keys line); passphrase is
// the sibling passphrase field's value, if any.
//
// It returns nil — "nothing definitively wrong" — when:
//   - priv or pub is empty: there is nothing to cross-check.
//   - priv is passphrase-protected and passphrase is empty: it cannot be
//     opened to compare, and a valid encrypted key must never be blocked
//     just because we can't verify it.
//
// It returns a gRPC InvalidArgument (message never contains key material)
// when pub doesn't parse, priv doesn't parse (and isn't merely
// passphrase-locked), a given passphrase fails to decrypt priv, or priv and
// pub parse fine individually but priv's derived public key doesn't match
// pub.
func verifyKeyPair(priv, pub, passphrase string) error {
	if priv == "" || pub == "" {
		return nil
	}

	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		return status.Error(codes.InvalidArgument, "public key is not a valid SSH authorized-keys entry")
	}

	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return status.Error(codes.InvalidArgument, "private key is not a valid SSH private key")
		}
		if passphrase == "" {
			// Encrypted and we have no passphrase to open it with: skip rather
			// than reject — we cannot prove a mismatch, and must not block a
			// legitimately encrypted key.
			return nil
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(priv), []byte(passphrase))
		if err != nil {
			return status.Error(codes.InvalidArgument, "private key could not be decrypted with the provided passphrase")
		}
	}

	if !bytes.Equal(signer.PublicKey().Marshal(), parsedPub.Marshal()) {
		return status.Error(codes.InvalidArgument, "public key does not match the private key")
	}
	return nil
}

// verifyKeyPairFields runs verifyKeyPair over a secret's about-to-be-stored
// plaintext field map — req.GetFields() for CreateSecret, the merged
// (patched-over-stored) map for UpdateSecret — so both save paths get the
// same authoritative cross-check before sealing.
func verifyKeyPairFields(fields map[string]string) error {
	return verifyKeyPair(fields[fieldSSHPrivateKey], fields[fieldSSHPublicKey], fields[fieldSSHPassphrase])
}
