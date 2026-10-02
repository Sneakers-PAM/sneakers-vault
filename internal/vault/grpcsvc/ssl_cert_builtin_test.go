// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
)

// sslCertTypeID is the built-in SSL/PKI Certificate secret type.
const sslCertTypeID = "type-ssl-cert"

// TestSSLCertBuiltinCatalogued proves the SSL/PKI Certificate type ships as a
// pre-installed built-in (origin SYSTEM, no heartbeat/rotation) and that its
// field keys are exactly certsvc's exported Field* constants, so the type
// schema and certsvc's ImportFields/ExportBytes map keys can never drift.
func TestSSLCertBuiltinCatalogued(t *testing.T) {
	var typ *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == sslCertTypeID {
			typ = b
		}
	}
	if typ == nil {
		t.Fatalf("%s not in BuiltinTypes()", sslCertTypeID)
	}
	if typ.GetName() != "SSL/PKI Certificate" {
		t.Errorf("name = %q, want %q", typ.GetName(), "SSL/PKI Certificate")
	}
	if typ.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
		t.Errorf("origin = %v, want SYSTEM", typ.GetOrigin())
	}
	if typ.GetHeartbeat() {
		t.Error("heartbeat = true, want false")
	}
	if typ.GetRotation() {
		t.Error("rotation = true, want false")
	}

	got := map[string]*vaultv1.SecretFieldDef{}
	for _, f := range typ.GetFields() {
		got[f.GetKey()] = f
	}

	// certificate: multiline, present.
	cert := got[certsvc.FieldCertificate]
	if cert == nil {
		t.Fatalf("missing field %q", certsvc.FieldCertificate)
	}
	if cert.GetKind() != vaultv1.FieldKind_FIELD_KIND_MULTILINE {
		t.Errorf("%s.kind = %v, want MULTILINE", certsvc.FieldCertificate, cert.GetKind())
	}

	// privateKey: SENSITIVE kind, sensitive AND super-sensitive, exactly like
	// type-ssh-key's private key field (plus the extra double-reveal gate).
	pk := got[certsvc.FieldPrivateKey]
	if pk == nil {
		t.Fatalf("missing field %q", certsvc.FieldPrivateKey)
	}
	if pk.GetKind() != vaultv1.FieldKind_FIELD_KIND_SENSITIVE {
		t.Errorf("%s.kind = %v, want SENSITIVE", certsvc.FieldPrivateKey, pk.GetKind())
	}
	if !pk.GetSensitive() {
		t.Errorf("%s.sensitive = false, want true", certsvc.FieldPrivateKey)
	}
	if !pk.GetSuperSensitive() {
		t.Errorf("%s.superSensitive = false, want true", certsvc.FieldPrivateKey)
	}

	// chain: multiline, present.
	chain := got[certsvc.FieldChain]
	if chain == nil {
		t.Fatalf("missing field %q", certsvc.FieldChain)
	}
	if chain.GetKind() != vaultv1.FieldKind_FIELD_KIND_MULTILINE {
		t.Errorf("%s.kind = %v, want MULTILINE", certsvc.FieldChain, chain.GetKind())
	}

	// The nine derived metadata fields certsvc.ImportFields populates on
	// import must all be present, using certsvc's own constants (never
	// hardcoded strings) so the schema can't silently drift from certsvc.
	metadata := []string{
		certsvc.FieldSubject,
		certsvc.FieldIssuer,
		certsvc.FieldSANs,
		certsvc.FieldSerialNumber,
		certsvc.FieldFingerprintSHA256,
		certsvc.FieldNotBefore,
		certsvc.FieldNotAfter,
		certsvc.FieldKeyAlgorithm,
		certsvc.FieldKeyBits,
	}
	for _, key := range metadata {
		if got[key] == nil {
			t.Errorf("missing metadata field %q", key)
		}
	}

	// hasPrivateKey/isCA: the two derived booleans persisted by certsvc on
	// import so GetSecretFields — which only echoes stored
	// keys — can actually return them. Neither is sensitive: they're booleans
	// derived from (not copies of) the key material/cert itself.
	for _, key := range []string{certsvc.FieldHasPrivateKey, certsvc.FieldIsCA} {
		f := got[key]
		if f == nil {
			t.Fatalf("missing field %q", key)
		}
		if f.GetKind() != vaultv1.FieldKind_FIELD_KIND_BOOLEAN {
			t.Errorf("%s.kind = %v, want BOOLEAN", key, f.GetKind())
		}
		if f.GetRequired() {
			t.Errorf("%s.required = true, want false", key)
		}
		if f.GetSensitive() {
			t.Errorf("%s.sensitive = true, want false", key)
		}
	}

	// notes: mirrors every other builtin's trailing free-text field, and
	// aligns type-ssl-cert with the UI mock's seedSecretTypes, which already
	// has one.
	if notes := got["notes"]; notes == nil {
		t.Error("missing field \"notes\"")
	} else if notes.GetKind() != vaultv1.FieldKind_FIELD_KIND_MULTILINE {
		t.Errorf("notes.kind = %v, want MULTILINE", notes.GetKind())
	}

	// Total field count: certificate + privateKey + chain + 9 metadata fields
	// + hasPrivateKey + isCA + notes.
	wantCount := 3 + len(metadata) + 3
	if len(got) != wantCount {
		t.Errorf("field count = %d, want %d", len(got), wantCount)
	}
}

// TestSSLCertBuiltinAdditive proves adding the SSL/PKI Certificate builtin did
// not disturb the pre-existing type-ssh-key builtin (catalogue lifecycle rule
// additive only).
func TestSSLCertBuiltinAdditive(t *testing.T) {
	var ssh *vaultv1.SecretType
	for _, b := range BuiltinTypes() {
		if b.GetId() == "type-ssh-key" {
			ssh = b
		}
	}
	if ssh == nil {
		t.Fatal("type-ssh-key must remain a built-in type")
	}
	if !ssh.GetHeartbeat() || !ssh.GetCheckout() {
		t.Errorf("type-ssh-key heartbeat=%v checkout=%v, want both true", ssh.GetHeartbeat(), ssh.GetCheckout())
	}
	var pk *vaultv1.SecretFieldDef
	for _, f := range ssh.GetFields() {
		if f.GetKey() == "privateKey" {
			pk = f
		}
	}
	if pk == nil {
		t.Fatal("type-ssh-key must keep its privateKey field")
	}
	if pk.GetKind() != vaultv1.FieldKind_FIELD_KIND_SENSITIVE || !pk.GetSensitive() {
		t.Errorf("type-ssh-key privateKey kind=%v sensitive=%v, want SENSITIVE/true", pk.GetKind(), pk.GetSensitive())
	}
}
