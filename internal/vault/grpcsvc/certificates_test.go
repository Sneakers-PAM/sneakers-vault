// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"time"

	certkit "github.com/Bugs5382/go-certkit"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"google.golang.org/grpc/codes"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
)

// certTestChain is a generated self-signed leaf certificate + RSA key, used
// as fixture input for the ImportCertificate/ExportCertificate tests below.
// It intentionally duplicates (rather than imports) certsvc_test.go's
// testChain, which lives in package certsvc and is unexported there.
type certTestChain struct {
	LeafCert *x509.Certificate
	LeafKey  *rsa.PrivateKey
}

func makeCertTestChain(t *testing.T) certTestChain {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certTestChain{LeafCert: cert, LeafKey: key}
}

func (tc certTestChain) leafPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.LeafCert.Raw})
}

func (tc certTestChain) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(tc.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func (tc certTestChain) bundle(t *testing.T) certkit.Bundle {
	t.Helper()
	return certkit.Bundle{LeafPEM: tc.leafPEM(), KeyPEM: tc.keyPEM(t)}
}

// makeCertTestP12 exports tc as a passphrase-protected PKCS#12 archive.
func makeCertTestP12(t *testing.T, tc certTestChain, passphrase string) []byte {
	t.Helper()
	p12, err := certkit.Export(tc.bundle(t), certkit.PKCS12, passphrase)
	if err != nil {
		t.Fatalf("certkit.Export(PKCS12): %v", err)
	}
	return p12
}

// makeCertTestJKS builds a two-alias JKS keystore (a private-key entry and a
// separate trusted-certificate entry), so ImportFields reports multiple
// aliases and requires the caller to pick one.
func makeCertTestJKS(t *testing.T, tc certTestChain, storePassphrase string) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(tc.LeafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	ks := keystore.New()
	pke := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: tc.LeafCert.Raw}},
	}
	if err := ks.SetPrivateKeyEntry("server-cert", pke, []byte(storePassphrase)); err != nil {
		t.Fatalf("SetPrivateKeyEntry: %v", err)
	}
	tce := keystore.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  keystore.Certificate{Type: "X509", Content: tc.LeafCert.Raw},
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

// newCertTestServer builds a mem-backed Server (random KEK, capturing
// auditor) with a shared folder owned (RACI) by user-carol — mirrors
// newRotationServer's shape minus the pool-backed rotation/version stores,
// which ImportCertificate/ExportCertificate never touch.
func newCertTestServer(t *testing.T) (*Server, *capAudit, string) {
	t.Helper()
	ca := &capAudit{}
	s := newServer(t)
	s.audit = ca
	fid := newSharedFolder(t, s)
	return s, ca, fid
}

func TestImportCertificate_CreatesTypeSSLCertSecret(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)
	p12 := makeCertTestP12(t, tc, "changeit")

	wantFields, wantMeta, wantAliases, err := certsvc.ImportFields(p12, "changeit", "")
	if err != nil || wantAliases != nil {
		t.Fatalf("fixture ImportFields() error = %v, aliases = %v", err, wantAliases)
	}

	resp, err := s.ImportCertificate(ctx, &vaultv1.ImportCertificateRequest{
		Actor: carol, FolderId: fid, Name: "leaf-cert", FileBytes: p12, Passphrase: "changeit",
	})
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	if resp.GetAliases() != nil {
		t.Fatalf("aliases = %v, want nil for a single-entry PKCS#12", resp.GetAliases())
	}
	sec := resp.GetSecret()
	if sec == nil {
		t.Fatal("secret = nil, want a created secret")
	}
	if sec.GetTypeId() != certSecretTypeID {
		t.Errorf("secret.typeId = %q, want %q", sec.GetTypeId(), certSecretTypeID)
	}
	if sec.GetFolderId() != fid || sec.GetName() != "leaf-cert" {
		t.Errorf("secret folder/name = %q/%q, want %q/%q", sec.GetFolderId(), sec.GetName(), fid, "leaf-cert")
	}

	// The stored fields must match what certsvc.ImportFields itself produced
	// from the same bytes.
	rec, ok := s.records[sec.GetId()]
	if !ok {
		t.Fatal("no encrypted record stored for the created secret")
	}
	got, err := s.crypt.OpenAll(rec)
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	if !stringMapsEqual(got, wantFields) {
		t.Errorf("stored fields = %v, want %v", got, wantFields)
	}
	// hasPrivateKey/isCA: this fixture carries a key and is a
	// leaf (not a CA), so both must reflect that.
	if got[certsvc.FieldHasPrivateKey] != "true" {
		t.Errorf("stored fields[hasPrivateKey] = %q, want %q", got[certsvc.FieldHasPrivateKey], "true")
	}
	if got[certsvc.FieldIsCA] != "false" {
		t.Errorf("stored fields[isCA] = %q, want %q (leaf cert)", got[certsvc.FieldIsCA], "false")
	}

	// ExpiresAt must be populated from the parsed cert's NotAfter (same
	// RFC3339 string GetSecretStats/the Secrets-list "Expires" column expect)
	// so an imported cert shows up in expiry accounting without a manual edit.
	if sec.GetExpiresAt() != wantMeta.NotAfter.Format(time.RFC3339) {
		t.Errorf("secret.expiresAt = %q, want %q", sec.GetExpiresAt(), wantMeta.NotAfter.Format(time.RFC3339))
	}

	// CertMeta round-trips from certkit.Meta.
	meta := resp.GetMeta()
	if meta == nil {
		t.Fatal("meta = nil")
	}
	if meta.GetSubject() != wantMeta.Subject {
		t.Errorf("meta.subject = %q, want %q", meta.GetSubject(), wantMeta.Subject)
	}
	if meta.GetSerialNumber() != wantMeta.SerialNumber {
		t.Errorf("meta.serialNumber = %q, want %q", meta.GetSerialNumber(), wantMeta.SerialNumber)
	}
	if meta.GetKeyAlgorithm() != "RSA" || meta.GetKeyBits() != 2048 {
		t.Errorf("meta.keyAlgorithm/keyBits = %q/%d, want RSA/2048", meta.GetKeyAlgorithm(), meta.GetKeyBits())
	}
	if _, err := time.Parse(time.RFC3339, meta.GetNotBefore()); err != nil {
		t.Errorf("meta.notBefore = %q not RFC3339: %v", meta.GetNotBefore(), err)
	}
	// The response meta reports key presence so the UI can seed the
	// export-disable state without a reload — this import carries a key.
	if !meta.GetHasPrivateKey() {
		t.Error("meta.hasPrivateKey = false, want true for a key-bearing import")
	}

	// certificate.import audited, sensitive (key material), subject = the
	// created secret's id.
	ev := ca.find("certificate.import")
	if ev == nil {
		t.Fatal("no certificate.import audit event emitted")
	}
	if !ev.Sensitive {
		t.Error("certificate.import must be marked sensitive")
	}
	if ev.ActorUserID != "user-carol" || ev.Subject != sec.GetId() {
		t.Errorf("audit actor/subject = %q/%q, want user-carol/%q", ev.ActorUserID, ev.Subject, sec.GetId())
	}
}

// TestImportCertificate_CertOnlyHasPrivateKeyFalse proves hasPrivateKey is
// persisted as "false" (not just left absent) for a cert-only import, so the
// staff UI can disable key-only export for these secrets.
func TestImportCertificate_CertOnlyHasPrivateKeyFalse(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)

	resp, err := s.ImportCertificate(ctx, &vaultv1.ImportCertificateRequest{
		Actor: carol, FolderId: fid, Name: "cert-only", FileBytes: tc.leafPEM(),
	})
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	sec := resp.GetSecret()
	if sec == nil {
		t.Fatal("secret = nil, want a created secret")
	}

	fieldsResp, err := s.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: carol, Id: sec.GetId()})
	if err != nil {
		t.Fatalf("GetSecretFields: %v", err)
	}
	if got := fieldsResp.GetFields()[certsvc.FieldHasPrivateKey]; got != "false" {
		t.Errorf("GetSecretFields()[hasPrivateKey] = %q, want %q", got, "false")
	}
	// And the import response meta agrees — no key -> hasPrivateKey false,
	// so the UI immediately disables key-bearing export formats.
	if resp.GetMeta().GetHasPrivateKey() {
		t.Error("meta.hasPrivateKey = true, want false for a cert-only import")
	}
}

func TestImportCertificate_MultiAliasJKSReturnsAliasesNoSecretCreated(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)
	jks := makeCertTestJKS(t, tc, "changeit")
	before := len(s.secrets)

	resp, err := s.ImportCertificate(ctx, &vaultv1.ImportCertificateRequest{
		Actor: carol, FolderId: fid, Name: "multi-alias", FileBytes: jks, Passphrase: "changeit",
	})
	if err != nil {
		t.Fatalf("ImportCertificate() error = %v, want nil (multi-entry is not an error)", err)
	}
	if resp.GetSecret() != nil {
		t.Fatalf("secret = %v, want nil when aliases are returned", resp.GetSecret())
	}
	got := append([]string(nil), resp.GetAliases()...)
	sort.Strings(got)
	want := []string{"ca-cert", "server-cert"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("aliases = %v, want %v", resp.GetAliases(), want)
	}
	if len(s.secrets) != before {
		t.Fatalf("secrets count = %d, want unchanged %d (no secret created)", len(s.secrets), before)
	}
	if ev := ca.find("certificate.import"); ev != nil {
		t.Fatal("certificate.import must not be audited when no secret was created")
	}
}

func TestImportCertificate_NonOwnerDenied(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	stranger := &vaultv1.ActorContext{UserId: "user-nobody"}
	tc := makeCertTestChain(t)
	p12 := makeCertTestP12(t, tc, "changeit")
	before := len(s.secrets)

	resp, err := s.ImportCertificate(ctx, &vaultv1.ImportCertificateRequest{
		Actor: stranger, FolderId: fid, Name: "leaf-cert", FileBytes: p12, Passphrase: "changeit",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got resp=%v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatal("no response on denial")
	}
	if len(s.secrets) != before {
		t.Fatalf("secrets count = %d, want unchanged %d", len(s.secrets), before)
	}
	if ev := ca.find("certificate.import"); ev != nil {
		t.Fatal("denied import must not emit certificate.import")
	}
}

// importedCertSecret imports tc as carol and returns the created secret id.
func importedCertSecret(t *testing.T, s *Server, fid string, tc certTestChain, fileBytes []byte, passphrase string) string {
	t.Helper()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	resp, err := s.ImportCertificate(context.Background(), &vaultv1.ImportCertificateRequest{
		Actor: carol, FolderId: fid, Name: "leaf-cert", FileBytes: fileBytes, Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("ImportCertificate: %v", err)
	}
	return resp.GetSecret().GetId()
}

func TestExportCertificate_PemCertReExportsStoredLeaf(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)
	secID := importedCertSecret(t, s, fid, tc, makeCertTestP12(t, tc, "changeit"), "changeit")

	resp, err := s.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{
		Actor: carol, SecretId: secID, Format: "pem-cert",
	})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	block, _ := pem.Decode(resp.GetFileBytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("export output is not a PEM certificate: %q", resp.GetFileBytes())
	}
	got, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse exported certificate: %v", err)
	}
	if got.SerialNumber.Cmp(tc.LeafCert.SerialNumber) != 0 {
		t.Errorf("exported serial = %v, want %v", got.SerialNumber, tc.LeafCert.SerialNumber)
	}
	if resp.GetFilename() != "certificate.crt" {
		t.Errorf("filename = %q, want certificate.crt", resp.GetFilename())
	}

	ev := ca.find("certificate.export")
	if ev == nil {
		t.Fatal("no certificate.export audit event emitted")
	}
	if ev.Sensitive {
		t.Error("cert-only export must not be marked sensitive")
	}
	if ev.Subject != secID {
		t.Errorf("audit subject = %q, want %q", ev.Subject, secID)
	}
}

func TestExportCertificate_KeyBearingSuccessAuditSensitive(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // RACI owner → reveal(read)-eligible
	tc := makeCertTestChain(t)
	secID := importedCertSecret(t, s, fid, tc, makeCertTestP12(t, tc, "changeit"), "changeit")

	resp, err := s.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{
		Actor: carol, SecretId: secID, Format: "pkcs12", NewPassphrase: "changeit",
	})
	if err != nil {
		t.Fatalf("ExportCertificate: %v", err)
	}
	if len(resp.GetFileBytes()) == 0 {
		t.Fatal("file_bytes is empty, want a PKCS#12 archive")
	}
	if resp.GetFilename() != "certificate.p12" {
		t.Errorf("filename = %q, want certificate.p12", resp.GetFilename())
	}

	// The exported archive must decode (under the new passphrase) back to a
	// bundle carrying the stored leaf + its private key.
	got, err := certkit.Parse(resp.GetFileBytes(), "changeit")
	if err != nil {
		t.Fatalf("certkit.Parse(exported pkcs12): %v", err)
	}
	if len(got.KeyPEM) == 0 {
		t.Fatal("exported pkcs12 carries no private key")
	}
	if got.Meta.SerialNumber != tc.LeafCert.SerialNumber.String() {
		t.Errorf("exported serial = %q, want %q", got.Meta.SerialNumber, tc.LeafCert.SerialNumber.String())
	}

	// The security-relevant assertion: a key-bearing export audits at reveal
	// weight (Sensitive == true), unlike the cert-only case.
	ev := ca.find("certificate.export")
	if ev == nil {
		t.Fatal("no certificate.export audit event emitted")
	}
	if !ev.Sensitive {
		t.Error("key-bearing export must be marked sensitive")
	}
	if ev.ActorUserID != "user-carol" || ev.Subject != secID {
		t.Errorf("audit actor/subject = %q/%q, want user-carol/%q", ev.ActorUserID, ev.Subject, secID)
	}
}

func TestExportCertificate_NonManagerDeniedKeyBearingFormat(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	tc := makeCertTestChain(t)
	secID := importedCertSecret(t, s, fid, tc, makeCertTestP12(t, tc, "changeit"), "changeit")
	stranger := &vaultv1.ActorContext{UserId: "user-nobody"}

	resp, err := s.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{
		Actor: stranger, SecretId: secID, Format: "pkcs12", NewPassphrase: "new-pass",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got resp=%v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatal("no response on denial")
	}
	if ev := ca.find("certificate.export"); ev != nil {
		t.Fatal("denied export must not emit certificate.export")
	}
}

func TestExportCertificate_PKCS12NoPrivateKeyMapsToFailedPrecondition(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)

	// Import a cert-only PEM (no private key block at all).
	certOnlyPEM := tc.leafPEM()
	secID := importedCertSecret(t, s, fid, tc, certOnlyPEM, "")

	resp, err := s.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{
		Actor: carol, SecretId: secID, Format: "pkcs12", NewPassphrase: "new-pass",
	})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got resp=%v err=%v", resp, err)
	}
}

func TestExportCertificate_PKCS12EmptyPassphraseRejected(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	tc := makeCertTestChain(t)
	secID := importedCertSecret(t, s, fid, tc, makeCertTestP12(t, tc, "changeit"), "changeit")

	resp, err := s.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{
		Actor: carol, SecretId: secID, Format: "pkcs12", NewPassphrase: "",
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got resp=%v err=%v", resp, err)
	}
}

// ---- ReplaceCertificate -------------------------------------------------

// makeCertTestChainNamed builds a self-signed leaf certificate + RSA key like
// makeCertTestChain, but with a caller-chosen CommonName/serial so
// TestReplaceCertificate_* can tell an "old" cert's stored fields apart from a
// "new" uploaded one — makeCertTestChain always mints the same CommonName and
// serial number, which would make subject/serial/fingerprint assertions
// meaningless across a replace.
func makeCertTestChainNamed(t *testing.T, cn string, serial int64) certTestChain {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certTestChain{LeafCert: cert, LeafKey: key}
}

// grantReadOnly gives userID RACI read (C) — but NOT author (R) — on fid, via
// folder owner carol. Used to build a "can read, cannot manage" actor for the
// PermissionDenied test, distinct from a stranger with no access at all.
func grantReadOnly(t *testing.T, s *Server, fid, userID string) {
	t.Helper()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: userID,
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(read-only grant): %v", err)
	}
}

func TestReplaceCertificate_OwnerReplacesInPlacePreservesIDAndSharing(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID := importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")

	// Sharing/RACI grant that must survive the replace: user-reader gets read.
	grantReadOnly(t, s, fid, "user-reader")

	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	newP12 := makeCertTestP12(t, newTC, "newpass")
	wantFields, wantMeta, wantAliases, err := certsvc.ImportFields(newP12, "newpass", "")
	if err != nil || wantAliases != nil {
		t.Fatalf("fixture ImportFields() error = %v, aliases = %v", err, wantAliases)
	}

	resp, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: carol, SecretId: secID, FileBytes: newP12, Passphrase: "newpass",
	})
	if err != nil {
		t.Fatalf("ReplaceCertificate: %v", err)
	}
	if resp.GetAliases() != nil {
		t.Fatalf("aliases = %v, want nil for a single-entry PKCS#12", resp.GetAliases())
	}
	sec := resp.GetSecret()
	if sec == nil {
		t.Fatal("secret = nil, want the updated secret")
	}
	if sec.GetId() != secID {
		t.Errorf("secret.id = %q, want unchanged %q", sec.GetId(), secID)
	}
	if sec.GetFolderId() != fid {
		t.Errorf("secret.folderId = %q, want unchanged %q", sec.GetFolderId(), fid)
	}

	// Stored fields must now match the NEW file's ImportFields output, not the
	// old one — proving an in-place overwrite, not a merge.
	rec, ok := s.records[secID]
	if !ok {
		t.Fatal("no encrypted record for the secret after replace")
	}
	got, err := s.crypt.OpenAll(rec)
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	if !stringMapsEqual(got, wantFields) {
		t.Errorf("stored fields = %v, want %v (the new file's fields)", got, wantFields)
	}
	if got[certsvc.FieldSubject] == oldTC.LeafCert.Subject.CommonName {
		t.Error("stored subject still matches the OLD certificate; not replaced")
	}
	if got[certsvc.FieldSerialNumber] == oldTC.LeafCert.SerialNumber.String() {
		t.Error("stored serialNumber still matches the OLD certificate; not replaced")
	}

	// ExpiresAt updated from the new cert's NotAfter.
	if sec.GetExpiresAt() != wantMeta.NotAfter.Format(time.RFC3339) {
		t.Errorf("secret.expiresAt = %q, want %q", sec.GetExpiresAt(), wantMeta.NotAfter.Format(time.RFC3339))
	}

	// CertMeta in the response reflects the NEW certificate.
	meta := resp.GetMeta()
	if meta == nil {
		t.Fatal("meta = nil")
	}
	if meta.GetSerialNumber() != wantMeta.SerialNumber {
		t.Errorf("meta.serialNumber = %q, want %q", meta.GetSerialNumber(), wantMeta.SerialNumber)
	}
	if meta.GetFingerprintSha256() == "" {
		t.Error("meta.fingerprintSha256 is empty")
	}
	// The replace response reports key presence too, so the UI refreshes
	// the export-disable state without a reload — the replacement carries a key.
	if !meta.GetHasPrivateKey() {
		t.Error("meta.hasPrivateKey = false, want true for a key-bearing replace")
	}

	// Sharing/RACI grant made before the replace must still be in effect
	// afterward — this is the "sharing/RACI unchanged" assertion.
	if !s.canRead(&vaultv1.ActorContext{UserId: "user-reader"}, sec) {
		t.Error("user-reader's pre-existing read grant did not survive the replace")
	}

	// certificate.replace audited, sensitive (key material overwritten).
	ev := ca.find("certificate.replace")
	if ev == nil {
		t.Fatal("no certificate.replace audit event emitted")
	}
	if !ev.Sensitive {
		t.Error("certificate.replace must be marked sensitive")
	}
	if ev.ActorUserID != "user-carol" || ev.Subject != secID {
		t.Errorf("audit actor/subject = %q/%q, want user-carol/%q", ev.ActorUserID, ev.Subject, secID)
	}
}

// TestReplaceCertificate_PreservesNotesAndNonCertFields locks in the data-loss
// guard: because ReplaceCertificate rotates in place through UpdateSecret's
// field-MERGE path (not a full field-set replace), a user-entered field the new
// cert upload knows nothing about — here "notes" — must survive the rotation
// untouched, while the certificate material itself is overwritten. A future
// refactor to a full-replace path would silently wipe such fields on every
// rotation; this test fails if that regresses.
func TestReplaceCertificate_PreservesNotesAndNonCertFields(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID := importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")

	// Set a user-entered field (the built-in type-ssl-cert "notes" field) via
	// UpdateSecret's own merge path, exactly as the staff UI would.
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, Fields: map[string]string{"notes": "renew via ACME each Jan"},
	}); err != nil {
		t.Fatalf("UpdateSecret(set notes): %v", err)
	}

	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	newP12 := makeCertTestP12(t, newTC, "newpass")
	wantFields, _, _, err := certsvc.ImportFields(newP12, "newpass", "")
	if err != nil {
		t.Fatalf("fixture ImportFields(new): %v", err)
	}
	if _, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: carol, SecretId: secID, FileBytes: newP12, Passphrase: "newpass",
	}); err != nil {
		t.Fatalf("ReplaceCertificate: %v", err)
	}

	rec, ok := s.records[secID]
	if !ok {
		t.Fatal("no encrypted record after replace")
	}
	got, err := s.crypt.OpenAll(rec)
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}

	// The user-entered field survived the rotation unchanged.
	if got["notes"] != "renew via ACME each Jan" {
		t.Errorf("notes = %q, want %q (must survive a cert replace)", got["notes"], "renew via ACME each Jan")
	}
	// The certificate material was overwritten with the NEW cert (matching what
	// certsvc.ImportFields produced from the new file).
	if got[certsvc.FieldSubject] != wantFields[certsvc.FieldSubject] {
		t.Errorf("subject = %q, want the new cert's %q", got[certsvc.FieldSubject], wantFields[certsvc.FieldSubject])
	}
	if got[certsvc.FieldSerialNumber] != newTC.LeafCert.SerialNumber.String() {
		t.Errorf("serialNumber = %q, want new cert's %q", got[certsvc.FieldSerialNumber], newTC.LeafCert.SerialNumber.String())
	}
	if got[certsvc.FieldPrivateKey] != wantFields[certsvc.FieldPrivateKey] {
		t.Error("privateKey does not match the new cert's key after replace")
	}
	if got[certsvc.FieldPrivateKey] == string(oldTC.keyPEM(t)) {
		t.Error("privateKey still matches the OLD cert's key; not replaced")
	}
}

func TestReplaceCertificate_NonManagerReadOnlyDenied(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID := importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")
	grantReadOnly(t, s, fid, "user-reader")
	reader := &vaultv1.ActorContext{UserId: "user-reader"}

	before, ok := s.records[secID]
	if !ok {
		t.Fatal("missing pre-replace record")
	}
	beforeFields, err := s.crypt.OpenAll(before)
	if err != nil {
		t.Fatalf("OpenAll (before): %v", err)
	}

	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	resp, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: reader, SecretId: secID, FileBytes: makeCertTestP12(t, newTC, "newpass"), Passphrase: "newpass",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got resp=%v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatal("no response on denial")
	}

	after, ok := s.records[secID]
	if !ok {
		t.Fatal("missing post-attempt record")
	}
	afterFields, err := s.crypt.OpenAll(after)
	if err != nil {
		t.Fatalf("OpenAll (after): %v", err)
	}
	if !stringMapsEqual(beforeFields, afterFields) {
		t.Errorf("secret fields changed on a denied replace: before=%v after=%v", beforeFields, afterFields)
	}
	if ev := ca.find("certificate.replace"); ev != nil {
		t.Fatal("denied replace must not emit certificate.replace")
	}
}

func TestReplaceCertificate_MultiAliasJKSReturnsAliasesSecretUnchanged(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID := importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")

	before, ok := s.records[secID]
	if !ok {
		t.Fatal("missing pre-replace record")
	}
	beforeFields, err := s.crypt.OpenAll(before)
	if err != nil {
		t.Fatalf("OpenAll (before): %v", err)
	}
	beforeSec := s.findSecret(secID)
	beforeExpiresAt := beforeSec.GetExpiresAt()

	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	jks := makeCertTestJKS(t, newTC, "changeit")

	resp, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: carol, SecretId: secID, FileBytes: jks, Passphrase: "changeit",
	})
	if err != nil {
		t.Fatalf("ReplaceCertificate() error = %v, want nil (multi-entry is not an error)", err)
	}
	if resp.GetSecret() != nil {
		t.Fatalf("secret = %v, want nil when aliases are returned", resp.GetSecret())
	}
	got := append([]string(nil), resp.GetAliases()...)
	sort.Strings(got)
	want := []string{"ca-cert", "server-cert"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("aliases = %v, want %v", resp.GetAliases(), want)
	}

	after, ok := s.records[secID]
	if !ok {
		t.Fatal("missing post-attempt record")
	}
	afterFields, err := s.crypt.OpenAll(after)
	if err != nil {
		t.Fatalf("OpenAll (after): %v", err)
	}
	if !stringMapsEqual(beforeFields, afterFields) {
		t.Errorf("secret fields changed despite multi-alias response: before=%v after=%v", beforeFields, afterFields)
	}
	if got := s.findSecret(secID).GetExpiresAt(); got != beforeExpiresAt {
		t.Errorf("secret.expiresAt = %q, want unchanged %q", got, beforeExpiresAt)
	}
	if ev := ca.find("certificate.replace"); ev != nil {
		t.Fatal("multi-alias replace must not emit certificate.replace")
	}
}

func TestReplaceCertificate_NonCertSecretInvalidArgument(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "not-a-cert", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "P@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	tc := makeCertTestChain(t)

	resp, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: carol, SecretId: created.GetSecret().GetId(),
		FileBytes: makeCertTestP12(t, tc, "changeit"), Passphrase: "changeit",
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got resp=%v err=%v", resp, err)
	}
}

func TestReplaceCertificate_WrongPassphraseInvalidArgument(t *testing.T) {
	s, ca, fid := newCertTestServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID := importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")

	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	p12 := makeCertTestP12(t, newTC, "correct-pass")

	resp, err := s.ReplaceCertificate(ctx, &vaultv1.ReplaceCertificateRequest{
		Actor: carol, SecretId: secID, FileBytes: p12, Passphrase: "wrong-pass",
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got resp=%v err=%v", resp, err)
	}
	if ev := ca.find("certificate.replace"); ev != nil {
		t.Fatal("failed replace must not emit certificate.replace")
	}
}
