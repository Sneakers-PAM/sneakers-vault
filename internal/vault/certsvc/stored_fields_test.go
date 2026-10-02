// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certsvc

import (
	"errors"
	"testing"
	"time"
)

func TestStoredFieldsMeta_DerivesMetadataFromStoredPEM(t *testing.T) {
	tc := makeTestChain(t)
	derived, meta, err := StoredFieldsMeta(map[string]string{
		FieldCertificate: string(tc.leafPEM()),
		FieldPrivateKey:  string(tc.keyPEM(t)),
		FieldChain:       string(tc.intermPEM()),
	})
	if err != nil {
		t.Fatalf("StoredFieldsMeta: %v", err)
	}
	for _, k := range []string{FieldCertificate, FieldPrivateKey, FieldChain} {
		if _, ok := derived[k]; ok {
			t.Fatalf("derived fields must not carry the PEM field %q", k)
		}
	}
	if derived[FieldSubject] != "CN=leaf.example.com" || derived[FieldHasPrivateKey] != "true" || derived[FieldIsCA] != "false" {
		t.Fatalf("derived = %v", derived)
	}
	if !meta.NotAfter.Equal(tc.LeafCert.NotAfter) || derived[FieldNotAfter] != tc.LeafCert.NotAfter.Format(time.RFC3339) {
		t.Fatalf("NotAfter = %v / %q", meta.NotAfter, derived[FieldNotAfter])
	}
}

func TestStoredFieldsMeta_CertOnly(t *testing.T) {
	tc := makeTestChain(t)
	derived, _, err := StoredFieldsMeta(map[string]string{FieldCertificate: string(tc.leafPEM())})
	if err != nil {
		t.Fatalf("StoredFieldsMeta: %v", err)
	}
	if derived[FieldHasPrivateKey] != "false" {
		t.Fatalf("hasPrivateKey = %q", derived[FieldHasPrivateKey])
	}
}

func TestStoredFieldsMeta_Refusals(t *testing.T) {
	tc := makeTestChain(t)
	cert, key := string(tc.leafPEM()), string(tc.keyPEM(t))
	cases := []struct {
		name   string
		fields map[string]string
		want   error
	}{
		{"no certificate", map[string]string{FieldPrivateKey: key}, ErrInvalidCertificate},
		{"certificate is not PEM", map[string]string{FieldCertificate: "nope"}, ErrInvalidCertificate},
		{"certificate field holds only a key", map[string]string{FieldCertificate: key}, ErrInvalidCertificate},
		{"certificate field also holds the key", map[string]string{FieldCertificate: cert + key}, ErrInvalidCertificate},
		{"key is not PEM", map[string]string{FieldCertificate: cert, FieldPrivateKey: "nope"}, ErrInvalidPrivateKey},
		{"key field holds a certificate", map[string]string{FieldCertificate: cert, FieldPrivateKey: cert}, ErrInvalidPrivateKey},
		{"chain is not PEM", map[string]string{FieldCertificate: cert, FieldChain: "nope"}, ErrInvalidChain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := StoredFieldsMeta(c.fields); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}
