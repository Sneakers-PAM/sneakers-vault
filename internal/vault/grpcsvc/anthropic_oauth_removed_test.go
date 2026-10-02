// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// anthropicOAuthExtID is an extension pack the catalogue must not offer;
// anthropicTokenID is the separate built-in token type.
const (
	anthropicOAuthExtID = "type-anthropic-oauth"
	anthropicTokenID    = "type-anthropic-token"
)

// TestAnthropicOAuthExtensionRemoved proves the "Anthropic OAuth Token" pack is
// absent from every seeded surface (extension catalogue and built-in
// types) so it can no longer be imported or installed.
func TestAnthropicOAuthExtensionRemoved(t *testing.T) {
	if containsTypeID(ExtensionCatalog(), anthropicOAuthExtID) {
		t.Errorf("%s must not be in ExtensionCatalog()", anthropicOAuthExtID)
	}
	if containsTypeID(BuiltinTypes(), anthropicOAuthExtID) {
		t.Errorf("%s must not be a built-in type", anthropicOAuthExtID)
	}
}

// TestAnthropicTokenTypeIntact proves the distinct "Anthropic Token" built-in (a
// fixed sk-ant-oa… secret) keeps its shape.
func TestAnthropicTokenTypeIntact(t *testing.T) {
	var tok *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == anthropicTokenID {
			tok = b
		}
	}
	if tok == nil {
		t.Fatalf("%s must remain a built-in type", anthropicTokenID)
	}
	if tok.GetName() != "Anthropic Token" {
		t.Errorf("name = %q, want %q", tok.GetName(), "Anthropic Token")
	}
	if tok.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
		t.Errorf("origin = %v, want SYSTEM", tok.GetOrigin())
	}
	// The single fixed "token" field with its sk-ant-oa pattern is the defining
	// shape; a regression that swapped it for the OAuth shape would break here.
	var token *vaultv1.SecretFieldDef
	for _, f := range tok.GetFields() {
		if f.GetKey() == "token" {
			token = f
		}
	}
	if token == nil {
		t.Fatalf("%s must keep its 'token' field", anthropicTokenID)
	}
	if !token.GetRequired() || !token.GetSensitive() {
		t.Errorf("token field required=%v sensitive=%v, want both true", token.GetRequired(), token.GetSensitive())
	}
	if token.GetPattern() != `^sk-ant-oa` {
		t.Errorf("token pattern = %q, want %q", token.GetPattern(), `^sk-ant-oa`)
	}
}
