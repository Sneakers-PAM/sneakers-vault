// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

const githubAppTypeID = "type-github-app"

// TestGitHubAppBuiltinCatalogued pins the GitHub App type's schema: its fields
// in order, with their kinds and flags. The private key is a sensitive
// MULTILINE field so a PEM keeps its line breaks when typed into the editor.
func TestGitHubAppBuiltinCatalogued(t *testing.T) {
	var typ *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == githubAppTypeID {
			typ = b
		}
	}
	if typ == nil {
		t.Fatalf("%s not in BuiltinTypes()", githubAppTypeID)
	}
	if typ.GetName() != "GitHub App" {
		t.Errorf("name = %q, want %q", typ.GetName(), "GitHub App")
	}
	if typ.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
		t.Errorf("origin = %v, want SYSTEM", typ.GetOrigin())
	}
	if typ.GetHeartbeat() || typ.GetRotation() || typ.GetCheckout() {
		t.Errorf("heartbeat/rotation/checkout = %v/%v/%v, want all false",
			typ.GetHeartbeat(), typ.GetRotation(), typ.GetCheckout())
	}

	var (
		text  = vaultv1.FieldKind_FIELD_KIND_TEXT
		multi = vaultv1.FieldKind_FIELD_KIND_MULTILINE
		sens  = vaultv1.FieldKind_FIELD_KIND_SENSITIVE
	)
	want := []struct {
		key       string
		label     string
		kind      vaultv1.FieldKind
		required  bool
		sensitive bool
		pattern   string
	}{
		{"description", "Description", multi, false, false, ""},
		{"appId", "App ID", text, true, false, `^\d+$`},
		{"clientId", "Client ID", text, false, false, ""},
		{"clientSecret", "Client Secret", sens, false, true, ""},
		{"installationId", "Installation ID", text, false, false, `^\d+$`},
		{"privateKey", "Private Key (PEM)", multi, true, true, ""},
		{"webhookSecret", "Webhook Secret", sens, false, true, ""},
		{"ownerOrg", "Owner Org", text, true, false, ""},
		{"notes", "Notes", multi, false, false, ""},
	}
	fields := typ.GetFields()
	if len(fields) != len(want) {
		t.Fatalf("fields = %d, want %d", len(fields), len(want))
	}
	for i, w := range want {
		f := fields[i]
		if f.GetKey() != w.key || f.GetLabel() != w.label || f.GetKind() != w.kind ||
			f.GetRequired() != w.required || f.GetSensitive() != w.sensitive || f.GetPattern() != w.pattern {
			t.Errorf("field %d = {%s %q %v required=%v sensitive=%v pattern=%q}, want {%s %q %v required=%v sensitive=%v pattern=%q}",
				i, f.GetKey(), f.GetLabel(), f.GetKind(), f.GetRequired(), f.GetSensitive(), f.GetPattern(),
				w.key, w.label, w.kind, w.required, w.sensitive, w.pattern)
		}
		if f.GetSuperSensitive() || f.GetRotates() {
			t.Errorf("field %s: superSensitive/rotates = %v/%v, want false", w.key, f.GetSuperSensitive(), f.GetRotates())
		}
	}
}

// TestGitHubAppAppendedLast keeps the catalogue additive: the new type goes
// after every type that shipped before it.
func TestGitHubAppAppendedLast(t *testing.T) {
	all := BuiltinTypes()
	if got := all[len(all)-1].GetId(); got != githubAppTypeID {
		t.Fatalf("last built-in = %s, want %s", got, githubAppTypeID)
	}
	if got := all[len(all)-2].GetId(); got != sslCertTypeID {
		t.Fatalf("second-to-last built-in = %s, want %s", got, sslCertTypeID)
	}
}
