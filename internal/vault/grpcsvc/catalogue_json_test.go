// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"os"
	"testing"
)

// cataloguePath is the generated JSON copy of the built-in catalogue. Other
// repos vendor it at a pinned commit (the MCP server lists SELECT options
// from it). Regenerate with UPDATE_CATALOGUE=1 go test ./internal/vault/grpcsvc -run TestCatalogueJSONIsCurrent.
const cataloguePath = "../../../gen/catalogue/types.json"

func TestCatalogueJSONIsCurrent(t *testing.T) {
	want, err := CatalogueJSON()
	if err != nil {
		t.Fatalf("CatalogueJSON: %v", err)
	}
	if os.Getenv("UPDATE_CATALOGUE") == "1" {
		if err := os.WriteFile(cataloguePath, want, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	got, err := os.ReadFile(cataloguePath)
	if err != nil {
		t.Fatalf("read %s: %v", cataloguePath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: regenerate it with UPDATE_CATALOGUE=1 go test ./internal/vault/grpcsvc -run TestCatalogueJSONIsCurrent", cataloguePath)
	}
}

func TestCatalogueJSONCarriesSelectOptions(t *testing.T) {
	b, err := CatalogueJSON()
	if err != nil {
		t.Fatalf("CatalogueJSON: %v", err)
	}
	for _, s := range []string{`"id": "type-ssh-key"`, `"key": "keyFormat"`, `"kind": "SELECT"`, `"RSA 4096"`, `"origin": "EXTENSION"`} {
		if !bytes.Contains(b, []byte(s)) {
			t.Fatalf("catalogue JSON lacks %s", s)
		}
	}
}
