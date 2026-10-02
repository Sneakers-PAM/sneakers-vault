// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// The Active Directory type carries an optional, non-sensitive NetBIOS domain
// right after the FQDN domain, so DOMAIN\user can be built from the secret.
func TestActiveDirectoryBuiltinHasOptionalNetbios(t *testing.T) {
	var ad *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == "type-active-directory" {
			ad = b
		}
	}
	if ad == nil {
		t.Fatal("type-active-directory not in BuiltinTypes()")
	}
	fields := ad.GetFields()
	idx := -1
	for i, f := range fields {
		if f.GetKey() == "netbios" {
			idx = i
		}
	}
	if idx < 1 || fields[idx-1].GetKey() != "domain" {
		t.Fatalf("netbios must follow domain; field keys %v", fieldKeys(ad))
	}
	nb := fields[idx]
	if nb.GetLabel() != "NetBIOS domain" || nb.GetKind() != vaultv1.FieldKind_FIELD_KIND_TEXT {
		t.Fatalf("netbios label/kind = %q/%v, want %q/TEXT", nb.GetLabel(), nb.GetKind(), "NetBIOS domain")
	}
	if nb.GetRequired() || nb.GetSensitive() || nb.GetSuperSensitive() || nb.GetRotates() {
		t.Fatalf("netbios must be optional and not sensitive: %+v", nb)
	}
}

func fieldKeys(t *vaultv1.SecretType) []string {
	out := make([]string, 0, len(t.GetFields()))
	for _, f := range t.GetFields() {
		out = append(out, f.GetKey())
	}
	return out
}
