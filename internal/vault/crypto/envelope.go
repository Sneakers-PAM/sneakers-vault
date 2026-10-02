// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package crypto provides per-secret envelope encryption: each secret's fields
// are sealed under a fresh data-encryption key (DEK), and that DEK is wrapped by
// a key-encryption key (KEK) held behind a pluggable provider (a dev in-memory
// key now; an HSM/KMS via PKCS#11 later — same interface). The app never
// persists a raw DEK or the KEK.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KEKProvider wraps and unwraps DEKs. Implementations keep the KEK material
// themselves (dev: in memory; prod: HSM/KMS) and are swapped by config.
type KEKProvider interface {
	// WrapDEK encrypts a raw DEK and returns the wrapped bytes plus a key
	// reference identifying which KEK version wrapped it (for rotation).
	WrapDEK(dek []byte) (wrapped []byte, keyRef string, err error)
	// UnwrapDEK reverses WrapDEK for the KEK named by keyRef.
	UnwrapDEK(wrapped []byte, keyRef string) ([]byte, error)
}

// Sealed is one AES-256-GCM ciphertext with its nonce.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// Record is a secret's encrypted field set: one wrapped DEK, and each field
// value sealed under it. This is what a repository persists — never plaintext.
type Record struct {
	WrappedDEK []byte
	KeyRef     string
	Fields     map[string]Sealed
}

// ErrFieldNotFound is returned by Open when the record has no such field.
var ErrFieldNotFound = errors.New("crypto: field not found")

// Envelope performs per-secret envelope encryption against a KEK provider.
type Envelope struct{ kek KEKProvider }

// New returns an Envelope backed by the given KEK provider.
func New(kek KEKProvider) *Envelope { return &Envelope{kek: kek} }

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandKey generates a fresh 32-byte key, suitable as a new KeyringKEK working
// generation's raw material before it is wrapped under the root KEK.
func RandKey() ([]byte, error) {
	return randBytes(32)
}

// Seal encrypts every field under a fresh 256-bit DEK (field key bound as AAD)
// and wraps the DEK with the KEK.
func (e *Envelope) Seal(fields map[string]string) (Record, error) {
	dek, err := randBytes(32)
	if err != nil {
		return Record{}, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Fields: make(map[string]Sealed, len(fields))}
	for k, v := range fields {
		nonce, err := randBytes(gcm.NonceSize())
		if err != nil {
			return Record{}, err
		}
		rec.Fields[k] = Sealed{Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, []byte(v), []byte(k))}
	}
	wrapped, ref, err := e.kek.WrapDEK(dek)
	if err != nil {
		return Record{}, err
	}
	rec.WrappedDEK, rec.KeyRef = wrapped, ref
	return rec, nil
}

// Open decrypts a single field. Use this on reveal so only the requested value
// is ever materialised.
func (e *Envelope) Open(rec Record, field string) (string, error) {
	sealed, ok := rec.Fields[field]
	if !ok {
		return "", ErrFieldNotFound
	}
	gcm, err := e.unwrapGCM(rec)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte(field))
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt %q: %w", field, err)
	}
	return string(pt), nil
}

// OpenAll decrypts every field — used to re-seal a record on update.
func (e *Envelope) OpenAll(rec Record) (map[string]string, error) {
	gcm, err := e.unwrapGCM(rec)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rec.Fields))
	for k, s := range rec.Fields {
		pt, err := gcm.Open(nil, s.Nonce, s.Ciphertext, []byte(k))
		if err != nil {
			return nil, fmt.Errorf("crypto: decrypt %q: %w", k, err)
		}
		out[k] = string(pt)
	}
	return out, nil
}

// RewrapDEK unwraps a record's DEK by its current KeyRef and re-wraps it under
// the provider's active KEK, returning a record with new WrappedDEK/KeyRef and
// identical Fields. Used by KEK rotation; never touches field ciphertext.
func (e *Envelope) RewrapDEK(rec Record) (Record, error) {
	dek, err := e.kek.UnwrapDEK(rec.WrappedDEK, rec.KeyRef)
	if err != nil {
		return Record{}, err
	}
	wrapped, ref, err := e.kek.WrapDEK(dek)
	if err != nil {
		return Record{}, err
	}
	out := rec
	out.WrappedDEK, out.KeyRef = wrapped, ref
	return out, nil
}

func (e *Envelope) unwrapGCM(rec Record) (cipher.AEAD, error) {
	dek, err := e.kek.UnwrapDEK(rec.WrappedDEK, rec.KeyRef)
	if err != nil {
		return nil, err
	}
	return newGCM(dek)
}
