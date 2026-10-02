// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import "errors"

// StaticKEK is a development KEK provider that wraps DEKs with a single
// in-memory AES-256 key. It is a stand-in for an HSM/KMS-backed provider; all
// implement KEKProvider and are swapped by config. NOT for production use.
type StaticKEK struct {
	key []byte
	ref string
}

// NewStaticKEK builds a dev KEK from a 32-byte key.
func NewStaticKEK(key []byte) (*StaticKEK, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: static KEK requires a 32-byte key")
	}
	return &StaticKEK{key: key, ref: "dev-static-v1"}, nil
}

// NewRandomKEK generates an ephemeral (process-lifetime) dev KEK. Secrets
// sealed with it can't be opened after a restart — fine for local/dev only.
func NewRandomKEK() (*StaticKEK, error) {
	k, err := randBytes(32)
	if err != nil {
		return nil, err
	}
	return &StaticKEK{key: k, ref: "dev-random-v1"}, nil
}

// WrapDEK seals the DEK under the KEK (nonce prepended to the ciphertext).
func (s *StaticKEK) WrapDEK(dek []byte) ([]byte, string, error) {
	gcm, err := newGCM(s.key)
	if err != nil {
		return nil, "", err
	}
	nonce, err := randBytes(gcm.NonceSize())
	if err != nil {
		return nil, "", err
	}
	return gcm.Seal(nonce, nonce, dek, nil), s.ref, nil
}

// UnwrapDEK reverses WrapDEK.
func (s *StaticKEK) UnwrapDEK(wrapped []byte, _ string) ([]byte, error) {
	gcm, err := newGCM(s.key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("crypto: wrapped DEK too short")
	}
	return gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
}
