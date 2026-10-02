// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/sha256"
	"errors"
	"sync"
)

// WorkingKey is one versioned 32-byte working KEK.
type WorkingKey struct {
	Ref string
	Key []byte
}

// KeyringKEK is a KEKProvider backed by a set of versioned working KEKs (one
// active) whose raw material is held in memory after being unwrapped under a
// root KEK at load. WrapDEK uses the active version; UnwrapDEK selects by ref.
type KeyringKEK struct {
	root      KEKProvider
	mu        sync.RWMutex
	keys      map[string][]byte // ref -> raw 32-byte working key
	activeRef string
}

// NewKeyringKEK builds a keyring from already-unwrapped working keys, backed
// by root as the KEK that wraps the working keys themselves at rest.
func NewKeyringKEK(root KEKProvider, working []WorkingKey, activeRef string) (*KeyringKEK, error) {
	if root == nil {
		return nil, errors.New("crypto: keyring requires a root KEK")
	}
	kr := &KeyringKEK{root: root, keys: make(map[string][]byte, len(working)), activeRef: activeRef}
	for _, w := range working {
		if len(w.Key) != 32 {
			return nil, errors.New("crypto: working KEK must be 32 bytes")
		}
		kr.keys[w.Ref] = w.Key
	}
	if _, ok := kr.keys[activeRef]; !ok {
		return nil, errors.New("crypto: active ref not in keyring")
	}
	return kr, nil
}

// ActiveRef returns the ref of the working KEK currently used by WrapDEK.
func (k *KeyringKEK) ActiveRef() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeRef
}

// Add registers a working key already persisted to the DB (in-memory update
// after keyring_store.InsertActive). makeActive points WrapDEK at it.
func (k *KeyringKEK) Add(w WorkingKey, makeActive bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[w.Ref] = w.Key
	if makeActive {
		k.activeRef = w.Ref
	}
}

// Has reports whether ref is already registered in the keyring (used by
// reconcileKeyring to find which persisted generations a replica hasn't
// picked up yet, without re-unwrapping ones it already has).
func (k *KeyringKEK) Has(ref string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.keys[ref]
	return ok
}

// SetActive points WrapDEK at ref, an already-registered working key (added
// via Add). Fails closed — returns an error, leaving activeRef unchanged —
// if ref is not present, so a caller (e.g. reconcileKeyring) can never point
// WrapDEK at a ref this keyring cannot also unwrap.
func (k *KeyringKEK) SetActive(ref string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[ref]; !ok {
		return errors.New("crypto: cannot make unknown ref active: " + ref)
	}
	k.activeRef = ref
	return nil
}

// WrapDEK seals dek under the active working KEK.
func (k *KeyringKEK) WrapDEK(dek []byte) ([]byte, string, error) {
	k.mu.RLock()
	activeRef := k.activeRef
	key, ok := k.keys[activeRef]
	k.mu.RUnlock()
	if !ok {
		return nil, "", errors.New("crypto: active working KEK missing")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, "", err
	}
	nonce, err := randBytes(gcm.NonceSize())
	if err != nil {
		return nil, "", err
	}
	return gcm.Seal(nonce, nonce, dek, nil), activeRef, nil
}

// UnwrapDEK reverses WrapDEK for the working KEK named by keyRef. Fails
// closed if keyRef is not present in the ring.
func (k *KeyringKEK) UnwrapDEK(wrapped []byte, keyRef string) ([]byte, error) {
	k.mu.RLock()
	key, ok := k.keys[keyRef]
	k.mu.RUnlock()
	if !ok {
		return nil, errors.New("crypto: no working KEK for ref " + keyRef)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, errors.New("crypto: wrapped DEK too short")
	}
	return gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
}

// NewStaticKEKFromSeed derives a StaticKEK from a public seed (dev root + tests).
func NewStaticKEKFromSeed(seed string) (*StaticKEK, error) {
	k := sha256.Sum256([]byte(seed))
	return NewStaticKEK(k[:])
}
