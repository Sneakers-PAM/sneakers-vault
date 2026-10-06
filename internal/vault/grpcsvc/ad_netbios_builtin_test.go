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

// The Active Directory type carries an optional logon format (NETBIOS or UPN)
// and an optional UPN suffix after the NetBIOS domain, so consumers can present
// the logon name the domain expects. Unset means the consumer's default.
func TestActiveDirectoryBuiltinHasOptionalLogonFormat(t *testing.T) {
	var ad *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == "type-active-directory" {
			ad = b
		}
	}
	if ad == nil {
		t.Fatal("type-active-directory not in BuiltinTypes()")
	}
	byKey := map[string]int{}
	for i, f := range ad.GetFields() {
		byKey[f.GetKey()] = i
	}
	nb, ok1 := byKey["netbios"]
	lf, ok2 := byKey["logonFormat"]
	us, ok3 := byKey["upnSuffix"]
	if !ok1 || !ok2 || !ok3 || lf != nb+1 || us != lf+1 {
		t.Fatalf("logonFormat and upnSuffix must follow netbios; field keys %v", fieldKeys(ad))
	}
	f := ad.GetFields()[lf]
	if f.GetLabel() != "Logon format" || f.GetKind() != vaultv1.FieldKind_FIELD_KIND_SELECT {
		t.Fatalf("logonFormat label/kind = %q/%v", f.GetLabel(), f.GetKind())
	}
	if got := f.GetOptions(); len(got) != 2 || got[0] != ADLogonFormatNetbios || got[1] != ADLogonFormatUPN {
		t.Fatalf("logonFormat options = %v, want [%s %s]", got, ADLogonFormatNetbios, ADLogonFormatUPN)
	}
	if f.GetDefaultValue() != "" {
		t.Fatalf("logonFormat must have no default so existing secrets keep today's behaviour, got %q", f.GetDefaultValue())
	}
	u := ad.GetFields()[us]
	if u.GetLabel() != "UPN suffix" || u.GetKind() != vaultv1.FieldKind_FIELD_KIND_TEXT {
		t.Fatalf("upnSuffix label/kind = %q/%v", u.GetLabel(), u.GetKind())
	}
	for _, g := range []*vaultv1.SecretFieldDef{f, u} {
		if g.GetRequired() || g.GetSensitive() || g.GetSuperSensitive() || g.GetRotates() {
			t.Fatalf("%s must be optional and not sensitive: %+v", g.GetKey(), g)
		}
	}
}
