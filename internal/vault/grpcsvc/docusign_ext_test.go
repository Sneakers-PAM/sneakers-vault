// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// docusignExtID is the catalogued Docusign app-auth extension pack.
const docusignExtID = "type-docusign-ssh-keys"

// TestDocusignExtensionCatalogued proves the Docusign App SSH Keys pack ships in
// the importable extension catalogue (origin EXTENSION) and is NOT installed as
// a usable built-in type by default — importing it is what installs it.
func TestDocusignExtensionCatalogued(t *testing.T) {
	var ext *vaultv1.SecretType
	for _, e := range ExtensionCatalog() {
		if e.GetId() == docusignExtID {
			ext = e
		}
	}
	if ext == nil {
		t.Fatalf("%s not in ExtensionCatalog()", docusignExtID)
	}
	if ext.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION {
		t.Errorf("origin = %v, want EXTENSION", ext.GetOrigin())
	}
	if ext.GetVendor() != "Docusign" {
		t.Errorf("vendor = %q, want Docusign", ext.GetVendor())
	}
	// Additive to the catalogue only: it must not be pre-installed as a built-in.
	for _, b := range BuiltinTypes() {
		if b.GetId() == docusignExtID {
			t.Fatalf("%s must be importable, not a pre-installed built-in type", docusignExtID)
		}
	}

	want := map[string]struct {
		kind      vaultv1.FieldKind
		sensitive bool
		required  bool
	}{
		"integrationKey": {vaultv1.FieldKind_FIELD_KIND_TEXT, false, true},
		"userId":         {vaultv1.FieldKind_FIELD_KIND_TEXT, false, true},
		"apiAccountId":   {vaultv1.FieldKind_FIELD_KIND_TEXT, false, true},
		"baseUri":        {vaultv1.FieldKind_FIELD_KIND_TEXT, false, false},
		// Same field key + kind as type-ssh-key's private key so the staff editor
		// renders it in the multi-line SENSITIVE key-material textarea.
		"privateKey": {vaultv1.FieldKind_FIELD_KIND_SENSITIVE, true, true},
	}
	got := map[string]*vaultv1.SecretFieldDef{}
	for _, f := range ext.GetFields() {
		got[f.GetKey()] = f
	}
	if len(got) != len(want) {
		t.Errorf("field count = %d, want %d", len(got), len(want))
	}
	for k, w := range want {
		f := got[k]
		if f == nil {
			t.Errorf("missing field %q", k)
			continue
		}
		if f.GetKind() != w.kind {
			t.Errorf("%s.kind = %v, want %v", k, f.GetKind(), w.kind)
		}
		if f.GetSensitive() != w.sensitive {
			t.Errorf("%s.sensitive = %v, want %v", k, f.GetSensitive(), w.sensitive)
		}
		if f.GetRequired() != w.required {
			t.Errorf("%s.required = %v, want %v", k, f.GetRequired(), w.required)
		}
	}
}

// TestDocusignExtensionListableAndImportable proves the seeded vault offers the
// Docusign pack via ListAvailableExtensions until imported, and that importing
// it installs an EXTENSION-origin type that then drops out of the available
// list (matching the shipped AWS/Azure/GCP packs' behaviour).
func TestDocusignExtensionListableAndImportable(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	actor := &vaultv1.ActorContext{UserId: "user-admin", IsRoot: true, IsSiteAdmin: true}

	avail, err := s.ListAvailableExtensions(ctx, &vaultv1.ListAvailableExtensionsRequest{})
	if err != nil {
		t.Fatalf("ListAvailableExtensions: %v", err)
	}
	if !containsTypeID(avail.GetExtensions(), docusignExtID) {
		t.Fatalf("%s not offered by ListAvailableExtensions", docusignExtID)
	}

	imp, err := s.ImportExtension(ctx, &vaultv1.ImportExtensionRequest{Actor: actor, Id: docusignExtID})
	if err != nil {
		t.Fatalf("ImportExtension: %v", err)
	}
	if imp.GetType().GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION {
		t.Errorf("imported origin = %v, want EXTENSION", imp.GetType().GetOrigin())
	}

	// Now installed as a real type...
	types, err := s.ListSecretTypes(ctx, &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	if !containsTypeID(types.GetTypes(), docusignExtID) {
		t.Errorf("%s not installed after import", docusignExtID)
	}
	// ...and no longer offered for import.
	avail2, err := s.ListAvailableExtensions(ctx, &vaultv1.ListAvailableExtensionsRequest{})
	if err != nil {
		t.Fatalf("ListAvailableExtensions (2nd): %v", err)
	}
	if containsTypeID(avail2.GetExtensions(), docusignExtID) {
		t.Errorf("%s still offered after import", docusignExtID)
	}
	// Re-import is rejected — additive install, never a duplicate.
	if _, err := s.ImportExtension(ctx, &vaultv1.ImportExtensionRequest{Actor: actor, Id: docusignExtID}); err == nil {
		t.Error("second ImportExtension should fail (already installed)")
	}
}

func containsTypeID(types []*vaultv1.SecretType, id string) bool {
	for _, t := range types {
		if t.GetId() == id {
			return true
		}
	}
	return false
}
