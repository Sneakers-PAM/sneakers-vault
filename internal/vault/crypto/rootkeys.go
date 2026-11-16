// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// RootRef names a root key without revealing it: "root-" and the first eight
// hex digits of a hash of the key. Working keys on that root carry it in their
// root_ref, so a vault holding two root keys can tell which one wraps which.
func RootRef(key []byte) string {
	h := sha256.Sum256(append([]byte("sneakers-root-ref\x00"), key...))
	return "root-" + hex.EncodeToString(h[:4])
}

// RootKEKs is the root KEK provider while a root key is being replaced: it
// holds the current root and, optionally, the previous one. It wraps only under
// the current root. It unwraps by the ref a working key carries: the current
// root's ref means the current root, any other ref means the previous root
// (the unrotated "root-v1" and the previous root's own ref both land there).
// With no previous root every ref opens under the current one, as a single
// root always has. A key that the chosen root cannot open is an error, never
// retried under the other root.
type RootKEKs struct {
	current    KEKProvider
	currentRef string
	previous   KEKProvider
}

// NewRootKEKs builds the provider. previous may be nil.
func NewRootKEKs(current KEKProvider, currentRef string, previous KEKProvider) *RootKEKs {
	return &RootKEKs{current: current, currentRef: currentRef, previous: previous}
}

// WrapDEK wraps under the current root and returns its ref.
func (r *RootKEKs) WrapDEK(dek []byte) ([]byte, string, error) {
	wrapped, _, err := r.current.WrapDEK(dek)
	return wrapped, r.currentRef, err
}

// UnwrapDEK opens a key under the root its ref names.
func (r *RootKEKs) UnwrapDEK(wrapped []byte, ref string) ([]byte, error) {
	if r.previous == nil || ref == r.currentRef {
		return r.current.UnwrapDEK(wrapped, ref)
	}
	return r.previous.UnwrapDEK(wrapped, ref)
}

// OnCurrent reports whether ref names the current root.
func (r *RootKEKs) OnCurrent(ref string) bool { return ref == r.currentRef }

// CurrentRef is the ref of the current root.
func (r *RootKEKs) CurrentRef() string { return r.currentRef }

// Current is the current root alone, for reading a key back without the previous root.
func (r *RootKEKs) Current() KEKProvider { return r.current }

// Previous is the previous root, nil when none is held.
func (r *RootKEKs) Previous() KEKProvider { return r.previous }

// RotationState is where a root key replacement stands.
type RotationState string

// The states the vault reports. None means no previous root key is set.
const (
	RotationNone       RotationState = "none"
	RotationInProgress RotationState = "in-progress"
	RotationVerified   RotationState = "verified"
	RotationFailed     RotationState = "failed"
)
