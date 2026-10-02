// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certsvc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	certkit "github.com/Bugs5382/go-certkit"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// testChain is a generated leaf + intermediate + their RSA keys, used as
// input to every round-trip test below.
type testChain struct {
	LeafCert   *x509.Certificate
	LeafKey    *rsa.PrivateKey
	IntermCert *x509.Certificate
}

func makeTestChain(t *testing.T) testChain {
	t.Helper()

	intermKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intermTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermDER, err := x509.CreateCertificate(rand.Reader, intermTmpl, intermTmpl, &intermKey.PublicKey, intermKey)
	if err != nil {
		t.Fatalf("create intermediate certificate: %v", err)
	}
	intermCert, err := x509.ParseCertificate(intermDER)
	if err != nil {
		t.Fatalf("parse intermediate certificate: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com", "www.leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermCert, &leafKey.PublicKey, intermKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return testChain{LeafCert: leafCert, LeafKey: leafKey, IntermCert: intermCert}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func (tc testChain) leafPEM() []byte   { return pemBlock("CERTIFICATE", tc.LeafCert.Raw) }
func (tc testChain) intermPEM() []byte { return pemBlock("CERTIFICATE", tc.IntermCert.Raw) }

func (tc testChain) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(tc.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	return pemBlock("PRIVATE KEY", der)
}

// bundle builds the certkit.Bundle for tc, with a 2-certificate chain
// (the intermediate, twice) so chain round-trip through the string "chain"
// field is exercised with more than one block.
func (tc testChain) bundle(t *testing.T) certkit.Bundle {
	t.Helper()
	return certkit.Bundle{
		LeafPEM:  tc.leafPEM(),
		KeyPEM:   tc.keyPEM(t),
		ChainPEM: [][]byte{tc.intermPEM(), tc.intermPEM()},
	}
}

func makeTestJKS(t *testing.T, tc testChain, storePassphrase string) []byte {
	t.Helper()

	keyDER, err := x509.MarshalPKCS8PrivateKey(tc.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}

	ks := keystore.New()

	pke := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   keyDER,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: tc.LeafCert.Raw},
			{Type: "X509", Content: tc.IntermCert.Raw},
		},
	}
	if err := ks.SetPrivateKeyEntry("server-cert", pke, []byte(storePassphrase)); err != nil {
		t.Fatalf("SetPrivateKeyEntry: %v", err)
	}

	tce := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X509", Content: tc.IntermCert.Raw},
	}
	if err := ks.SetTrustedCertificateEntry("ca-cert", tce); err != nil {
		t.Fatalf("SetTrustedCertificateEntry: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassphrase)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	return buf.Bytes()
}

func TestImportFields_PKCS12RoundTrip(t *testing.T) {
	tc := makeTestChain(t)
	p12, err := certkit.Export(tc.bundle(t), certkit.PKCS12, "p12-pass")
	if err != nil {
		t.Fatalf("certkit.Export(PKCS12): %v", err)
	}

	fields, meta, aliases, err := ImportFields(p12, "p12-pass", "")
	if err != nil {
		t.Fatalf("ImportFields() error = %v", err)
	}
	if aliases != nil {
		t.Fatalf("aliases = %v, want nil for a single-entry PKCS#12", aliases)
	}

	if !strings.Contains(fields[FieldCertificate], "BEGIN CERTIFICATE") {
		t.Errorf("fields[certificate] does not look like a PEM certificate: %q", fields[FieldCertificate])
	}
	if !strings.Contains(fields[FieldPrivateKey], "PRIVATE KEY") {
		t.Errorf("fields[privateKey] does not look like a PEM key: %q", fields[FieldPrivateKey])
	}
	if n := strings.Count(fields[FieldChain], "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("fields[chain] has %d certificate blocks, want 2: %q", n, fields[FieldChain])
	}

	if fields[FieldSubject] != meta.Subject {
		t.Errorf("fields[subject] = %q, want meta.Subject %q", fields[FieldSubject], meta.Subject)
	}
	if meta.Subject != tc.LeafCert.Subject.String() {
		t.Errorf("meta.Subject = %q, want %q", meta.Subject, tc.LeafCert.Subject.String())
	}
	if fields[FieldSANs] != "leaf.example.com,www.leaf.example.com" {
		t.Errorf("fields[sans] = %q, want %q", fields[FieldSANs], "leaf.example.com,www.leaf.example.com")
	}
	if fields[FieldKeyAlgorithm] != "RSA" {
		t.Errorf("fields[keyAlgorithm] = %q, want RSA", fields[FieldKeyAlgorithm])
	}
	if fields[FieldKeyBits] != "2048" {
		t.Errorf("fields[keyBits] = %q, want 2048", fields[FieldKeyBits])
	}
	if fields[FieldSerialNumber] != tc.LeafCert.SerialNumber.String() {
		t.Errorf("fields[serialNumber] = %q, want %q", fields[FieldSerialNumber], tc.LeafCert.SerialNumber.String())
	}
	if _, err := time.Parse(time.RFC3339, fields[FieldNotBefore]); err != nil {
		t.Errorf("fields[notBefore] = %q not RFC3339: %v", fields[FieldNotBefore], err)
	}
	if _, err := time.Parse(time.RFC3339, fields[FieldNotAfter]); err != nil {
		t.Errorf("fields[notAfter] = %q not RFC3339: %v", fields[FieldNotAfter], err)
	}
	if fields[FieldHasPrivateKey] != "true" {
		t.Errorf("fields[hasPrivateKey] = %q, want %q", fields[FieldHasPrivateKey], "true")
	}
	if fields[FieldIsCA] != "false" {
		t.Errorf("fields[isCA] = %q, want %q (leaf cert)", fields[FieldIsCA], "false")
	}
}

// TestImportFields_CertOnlyHasPrivateKeyFalse proves hasPrivateKey reflects
// the absence of key material for a cert-only import, not just its presence
// (TestImportFields_PKCS12RoundTrip only covers the key-bearing case).
func TestImportFields_CertOnlyHasPrivateKeyFalse(t *testing.T) {
	tc := makeTestChain(t)

	fields, _, aliases, err := ImportFields(tc.leafPEM(), "", "")
	if err != nil {
		t.Fatalf("ImportFields() error = %v", err)
	}
	if aliases != nil {
		t.Fatalf("aliases = %v, want nil", aliases)
	}
	if fields[FieldHasPrivateKey] != "false" {
		t.Errorf("fields[hasPrivateKey] = %q, want %q (cert-only import)", fields[FieldHasPrivateKey], "false")
	}
	if fields[FieldPrivateKey] != "" {
		t.Errorf("fields[privateKey] = %q, want empty for a cert-only import", fields[FieldPrivateKey])
	}
}

func TestImportFields_WrongPassphrase(t *testing.T) {
	tc := makeTestChain(t)
	p12, err := certkit.Export(tc.bundle(t), certkit.PKCS12, "correct-pass")
	if err != nil {
		t.Fatalf("certkit.Export(PKCS12): %v", err)
	}

	_, _, _, err = ImportFields(p12, "wrong-pass", "")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("ImportFields() error = %v, want ErrWrongPassphrase", err)
	}
}

func TestImportFields_MultipleAliasesJKS(t *testing.T) {
	tc := makeTestChain(t)
	jks := makeTestJKS(t, tc, "changeit1")

	fields, meta, aliases, err := ImportFields(jks, "changeit1", "")
	if err != nil {
		t.Fatalf("ImportFields() error = %v, want nil (multi-entry is not an error)", err)
	}
	if fields != nil {
		t.Errorf("fields = %v, want nil for a multi-alias container", fields)
	}
	if meta.Subject != "" {
		t.Errorf("meta = %+v, want zero value for a multi-alias container", meta)
	}

	got := append([]string(nil), aliases...)
	sort.Strings(got)
	want := []string{"ca-cert", "server-cert"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("aliases = %v, want %v", aliases, want)
	}

	// Re-import selecting one alias explicitly must succeed and return no
	// aliases.
	fields, _, aliases, err = ImportFields(jks, "changeit1", "server-cert")
	if err != nil {
		t.Fatalf("ImportFields(alias=server-cert) error = %v", err)
	}
	if aliases != nil {
		t.Fatalf("aliases = %v, want nil once an alias is selected", aliases)
	}
	if !strings.Contains(fields[FieldPrivateKey], "PRIVATE KEY") {
		t.Errorf("fields[privateKey] for server-cert entry is empty")
	}
}

func TestExportBytes_PEMCert(t *testing.T) {
	tc := makeTestChain(t)
	fields := map[string]string{FieldCertificate: string(tc.leafPEM())}

	data, filename, contentType, err := ExportBytes(fields, "pem-cert", "")
	if err != nil {
		t.Fatalf("ExportBytes() error = %v", err)
	}
	if filename != "certificate.crt" {
		t.Errorf("filename = %q, want certificate.crt", filename)
	}
	if contentType != "application/x-pem-file" {
		t.Errorf("contentType = %q, want application/x-pem-file", contentType)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Export output is not a PEM certificate: %q", data)
	}
	got, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse exported certificate: %v", err)
	}
	if got.SerialNumber.Cmp(tc.LeafCert.SerialNumber) != 0 {
		t.Errorf("exported certificate serial = %v, want %v", got.SerialNumber, tc.LeafCert.SerialNumber)
	}
}

func TestExportBytes_NoPrivateKeySentinel(t *testing.T) {
	tc := makeTestChain(t)
	fields := map[string]string{FieldCertificate: string(tc.leafPEM())} // no privateKey field

	for _, format := range []string{"pkcs12", "jks", "pem", "pem-key"} {
		_, _, _, err := ExportBytes(fields, format, "some-pass")
		if !errors.Is(err, ErrNoPrivateKey) {
			t.Errorf("ExportBytes(format=%s) error = %v, want ErrNoPrivateKey", format, err)
		}
	}
}

func TestExportBytes_UnsupportedFormat(t *testing.T) {
	tc := makeTestChain(t)
	fields := map[string]string{FieldCertificate: string(tc.leafPEM())}

	if _, _, _, err := ExportBytes(fields, "not-a-format", ""); err == nil {
		t.Fatal("ExportBytes(unsupported format) error = nil, want a non-nil error")
	}
}

func TestImportExportRoundTrip_PEMBundleWithChain(t *testing.T) {
	tc := makeTestChain(t)

	// Import a PEM bundle (leaf + key + a 2-certificate chain) built directly
	// from the test fixtures, independent of the export path.
	var pemInput []byte
	pemInput = append(pemInput, tc.leafPEM()...)
	pemInput = append(pemInput, tc.keyPEM(t)...)
	pemInput = append(pemInput, tc.intermPEM()...)
	pemInput = append(pemInput, tc.intermPEM()...)

	fields, _, aliases, err := ImportFields(pemInput, "", "")
	if err != nil {
		t.Fatalf("ImportFields() error = %v", err)
	}
	if aliases != nil {
		t.Fatalf("aliases = %v, want nil", aliases)
	}
	if n := strings.Count(fields[FieldChain], "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("fields[chain] has %d certificate blocks, want 2", n)
	}

	// Export it back out as a fresh PEM bundle and confirm the chain survived
	// the fields round trip (not just truncated to its first block).
	data, filename, contentType, err := ExportBytes(fields, "pem", "new-pass")
	if err != nil {
		t.Fatalf("ExportBytes() error = %v", err)
	}
	if filename != "certificate.pem" || contentType != "application/x-pem-file" {
		t.Errorf("filename/contentType = %q/%q, want certificate.pem/application/x-pem-file", filename, contentType)
	}
	if n := strings.Count(string(data), "BEGIN CERTIFICATE"); n != 3 { // leaf + 2 chain certs
		t.Errorf("exported pem bundle has %d certificate blocks, want 3", n)
	}
	if !strings.Contains(string(data), "ENCRYPTED PRIVATE KEY") {
		t.Error("exported pem bundle key is not encrypted despite a newPassphrase")
	}

	// And it must parse back via certkit directly.
	reimported, err := certkit.Parse(data, "new-pass")
	if err != nil {
		t.Fatalf("certkit.Parse(re-exported bundle) error = %v", err)
	}
	if reimported.Meta.Subject != tc.LeafCert.Subject.String() {
		t.Errorf("re-imported subject = %q, want %q", reimported.Meta.Subject, tc.LeafCert.Subject.String())
	}
	if len(reimported.ChainPEM) != 2 {
		t.Errorf("re-imported chain len = %d, want 2", len(reimported.ChainPEM))
	}
}
