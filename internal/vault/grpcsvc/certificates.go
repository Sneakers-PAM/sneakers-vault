// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	certkit "github.com/Bugs5382/go-certkit"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// certSecretTypeID is the built-in SSL/PKI Certificate secret type,
// installed by BuiltinTypes (builtins.go). Deliberately its own constant
// (rather than reusing ssl_cert_builtin_test.go's sslCertTypeID) so this
// production file never collides with that test-only declaration; both must
// stay literally "type-ssl-cert".
const certSecretTypeID = "type-ssl-cert" // #nosec G101 -- a secret-type id, not a credential

// keyBearingExportFormats are the certsvc export formats that embed the
// private key. Exporting one of these is gated on the SAME capability
// RevealSecretField uses to gate a private-key reveal — canRead (this
// vault's v1 authz model treats reveal and read as one action, RACI C; see
// GetMyAccess/GetMySecretAccess's "v1: reveal == read" comment). pem-fullchain
// is certificate + chain ONLY (no key), so despite the "pem-" prefix it is
// NOT listed here and only needs the cert-only (read) gate.
var keyBearingExportFormats = map[string]bool{
	"pkcs12": true, "jks": true, "pem": true, "pem-key": true,
}

// encryptingKeystoreFormats are the export formats that always package their
// output as a keystore container. ExportCertificate refuses to produce one of
// these unencrypted (empty new_passphrase) so an unprotected keystore is
// never emitted. pem/pem-key MAY be exported in plaintext on request — that
// trade-off is surfaced by the UI, not enforced here.
var encryptingKeystoreFormats = map[string]bool{
	"pkcs12": true, "jks": true,
}

// certMetaFromCertkit maps a parsed certkit.Meta onto the contract's CertMeta
// wire type (RFC3339 timestamps, safeconv-clamped key size). hasPrivateKey is
// not carried on certkit.Meta — it comes from the ImportFields output (whether
// the parsed container yielded a private key) so the response tells the UI
// whether key-bearing export formats are available.
func certMetaFromCertkit(m certkit.Meta, hasPrivateKey bool) *vaultv1.CertMeta {
	return &vaultv1.CertMeta{
		Subject:           m.Subject,
		Issuer:            m.Issuer,
		Sans:              append([]string(nil), m.SANs...),
		NotBefore:         m.NotBefore.Format(time.RFC3339),
		NotAfter:          m.NotAfter.Format(time.RFC3339),
		SerialNumber:      m.SerialNumber,
		FingerprintSha256: m.FingerprintSHA256,
		KeyAlgorithm:      m.KeyAlgorithm,
		KeyBits:           safeconv.Int32(m.KeyBits),
		IsCa:              m.IsCA,
		HasPrivateKey:     hasPrivateKey,
	}
}

// certExpiresAt derives the Secret.ExpiresAt string from a parsed certkit.Meta
// the same way ImportCertificate and ReplaceCertificate both need: RFC3339,
// zero-guarded so an unparsed/absent NotAfter never persists as a bogus
// "epoch" expiry.
func certExpiresAt(meta certkit.Meta) string {
	if meta.NotAfter.IsZero() {
		return ""
	}
	return meta.NotAfter.Format(time.RFC3339)
}

// ImportCertificate parses an uploaded certificate/key container (PKCS#12,
// PEM, DER, PKCS#7, or JKS/JCEKS — see certsvc.ImportFields) and, on success,
// creates it as a type-ssl-cert secret through the normal CreateSecret path
// so envelope encryption, version-ledger append, and HA cache invalidation
// all apply exactly as they do for any other secret creation.
func (s *Server) ImportCertificate(ctx context.Context, req *vaultv1.ImportCertificateRequest) (*vaultv1.ImportCertificateResponse, error) {
	if req.GetFolderId() == "" || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "folder and name are required")
	}
	// Create-under-folder capability (RACI R/Author) — the same gate
	// CreateSecret itself enforces below; checked up front so an actor without
	// it gets PermissionDenied before any effort is spent parsing the upload.
	s.mu.RLock()
	allowed := s.canManage(req.GetActor(), req.GetFolderId())
	s.mu.RUnlock()
	if !allowed {
		return nil, status.Error(codes.PermissionDenied, "not permitted to import a certificate into this folder")
	}

	fields, meta, aliases, err := certsvc.ImportFields(req.GetFileBytes(), req.GetPassphrase(), req.GetAlias())
	// A multi-entry container with no alias chosen is NOT an error: certsvc
	// returns err==nil with fields/meta zeroed and aliases populated. Aliases
	// must be checked BEFORE err — treating err==nil here as "imported" would
	// silently create a secret with no certificate/key fields at all.
	if len(aliases) > 0 {
		return &vaultv1.ImportCertificateResponse{Aliases: aliases}, nil
	}
	if err != nil {
		if errors.Is(err, certsvc.ErrWrongPassphrase) {
			return nil, status.Error(codes.InvalidArgument, "wrong passphrase")
		}
		return nil, status.Errorf(codes.InvalidArgument, "parse certificate: %v", err)
	}

	// ExpiresAt drives the Secrets-list "Expires" column and the dashboard's
	// expiring/expired stats (GetSecretStats, stats.go) exactly like any
	// manually-entered secret expiry — same RFC3339 string, same field.
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: req.GetActor(), Name: req.GetName(), FolderId: req.GetFolderId(),
		TypeId: certSecretTypeID, Fields: fields, ExpiresAt: certExpiresAt(meta),
	})
	if err != nil {
		return nil, err
	}

	// CreateSecret already emitted "secret.create"; certificate.import is the
	// domain-specific event layered on top — sensitive, since key material was
	// just brought into the vault.
	s.emit(ctx, req.GetActor().GetUserId(), "certificate.import", created.GetSecret().GetId(), true)

	return &vaultv1.ImportCertificateResponse{Secret: created.GetSecret(), Meta: certMetaFromCertkit(meta, fields[certsvc.FieldHasPrivateKey] == "true")}, nil
}

// ExportCertificate assembles a type-ssl-cert secret's fields into a
// downloadable container (PKCS#12, PEM variants, DER, PKCS#7, or JKS — see
// certsvc.ExportBytes). Formats that embed the private key require the same
// capability RevealSecretField requires to reveal that key; cert-only formats
// need only read. In this vault's v1 authz model those are literally the same
// gate (canRead — reveal == read, RACI C), so both branches call it; the split
// is kept explicit for when the two capabilities diverge, and so each denial
// reads correctly for the format that triggered it.
func (s *Server) ExportCertificate(ctx context.Context, req *vaultv1.ExportCertificateRequest) (*vaultv1.ExportCertificateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if sec.GetTypeId() != certSecretTypeID {
		return nil, status.Error(codes.InvalidArgument, "secret is not an SSL/PKI certificate")
	}

	keyBearing := keyBearingExportFormats[req.GetFormat()]
	if keyBearing {
		if !s.canRead(req.GetActor(), sec) {
			return nil, status.Error(codes.PermissionDenied, "not permitted to reveal this secret's private key")
		}
	} else if !s.canRead(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to read this secret")
	}

	// Never emit an unprotected keystore: pkcs12/jks always encrypt, so a
	// missing new_passphrase must fail here rather than pass "" through to
	// certkit and produce a bare keystore.
	if encryptingKeystoreFormats[req.GetFormat()] && req.GetNewPassphrase() == "" {
		return nil, status.Error(codes.InvalidArgument, "passphrase required for pkcs12/jks export")
	}

	rec, ok := s.records[sec.Id]
	if !ok {
		return nil, errNotFound("secret value")
	}
	fields, err := s.crypt.OpenAll(rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open: %v", err)
	}

	data, filename, contentType, err := certsvc.ExportBytes(fields, req.GetFormat(), req.GetNewPassphrase())
	if err != nil {
		if errors.Is(err, certsvc.ErrNoPrivateKey) {
			return nil, status.Error(codes.FailedPrecondition, "secret has no private key")
		}
		return nil, status.Errorf(codes.InvalidArgument, "export: %v", err)
	}

	// Same access-accounting as RevealSecretField/CopySecret: bump the
	// dashboard "top accessed" counter and audit at the weight the format
	// warrants (key-bearing == a reveal; cert-only == a normal read/export).
	bumpView(sec)
	s.emit(ctx, req.GetActor().GetUserId(), "certificate.export", sec.Id, keyBearing)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "certificate.export", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))

	return &vaultv1.ExportCertificateResponse{FileBytes: data, Filename: filename, ContentType: contentType}, nil
}

// ReplaceCertificate rotates a type-ssl-cert secret's certificate/key material
// in place, alongside import/export: it parses the uploaded
// container exactly as ImportCertificate does, then overwrites the existing
// secret's fields through the internal UpdateSecret path instead of creating a
// new secret. Routing through UpdateSecret means the envelope re-seal,
// version-ledger append, and (via mutatingMethods) HA cache invalidation all
// apply exactly as they do for any other field edit — and because the secret
// itself is never replaced, its id, folder, sharing/RACI grants, and audit
// history all survive the rotation untouched.
func (s *Server) ReplaceCertificate(ctx context.Context, req *vaultv1.ReplaceCertificateRequest) (*vaultv1.ReplaceCertificateResponse, error) {
	s.mu.RLock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		s.mu.RUnlock()
		return nil, errNotFound("secret")
	}
	// Authorize BEFORE inspecting the secret any further: replace overwrites the
	// private key in place, so it must be gated at LEAST as strictly as editing
	// the secret outright — the same canManageOrOwnSecret gate UpdateSecret
	// itself enforces below (RACI Author on the folder, or folder ownership).
	// Checked ahead of the type/retired checks so an unauthorized actor gets
	// PermissionDenied without any work done and without leaking the secret's
	// type or lifecycle state.
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		s.mu.RUnlock()
		return nil, status.Error(codes.PermissionDenied, "not permitted to replace this secret's certificate")
	}
	if sec.GetTypeId() != certSecretTypeID {
		s.mu.RUnlock()
		return nil, status.Error(codes.InvalidArgument, "secret is not an SSL/PKI certificate")
	}
	if sec.GetRetired() {
		s.mu.RUnlock()
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	// Captured before releasing the lock so the UpdateSecret call below can
	// reuse them unchanged — RWMutex isn't reentrant, so the lock must be
	// released before calling another locking method, same as ImportCertificate
	// releasing before CreateSecret.
	name, targetID := sec.GetName(), sec.GetTargetId()
	s.mu.RUnlock()

	fields, meta, aliases, err := certsvc.ImportFields(req.GetFileBytes(), req.GetPassphrase(), req.GetAlias())
	// Multi-entry container, no alias chosen yet: not an error, and — unlike
	// ImportCertificate, which simply wouldn't create anything yet — the
	// existing secret must be left completely untouched until the caller
	// resubmits with a chosen alias.
	if len(aliases) > 0 {
		return &vaultv1.ReplaceCertificateResponse{Aliases: aliases}, nil
	}
	if err != nil {
		if errors.Is(err, certsvc.ErrWrongPassphrase) {
			return nil, status.Error(codes.InvalidArgument, "wrong passphrase")
		}
		return nil, status.Errorf(codes.InvalidArgument, "parse certificate: %v", err)
	}

	// Overwrite the certificate material + derived metadata in place via
	// UpdateSecret's own field-merge/re-seal/version-append path. TargetId has
	// no "empty means keep" guard in UpdateSecret (unlike Name) — it is
	// unconditionally overwritten with whatever is sent — so both are
	// explicitly resent with the secret's current values to guarantee nothing
	// else about the secret changes. FolderId/sharing/RACI are untouched
	// because DestFolderId is left empty (UpdateSecret only moves folders when
	// it's non-empty and differs from the secret's current folder).
	updated, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
		Actor: req.GetActor(), Id: req.GetSecretId(), Name: name, TargetId: targetID,
		Fields: fields, ExpiresAt: certExpiresAt(meta),
	})
	if err != nil {
		return nil, err
	}

	// UpdateSecret already emitted "secret.update" (and its own Informed
	// fan-out); certificate.replace is the domain-specific event layered on
	// top, same relationship ImportCertificate's certificate.import has to
	// CreateSecret's secret.create — sensitive, since key material was just
	// overwritten.
	s.emit(ctx, req.GetActor().GetUserId(), "certificate.replace", updated.GetSecret().GetId(), true)
	s.mu.RLock()
	chain := s.secretChain(updated.GetSecret())
	s.mu.RUnlock()
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "certificate.replace", "secret", updated.GetSecret().GetId(), updated.GetSecret().GetName(), chain)

	return &vaultv1.ReplaceCertificateResponse{Secret: updated.GetSecret(), Meta: certMetaFromCertkit(meta, fields[certsvc.FieldHasPrivateKey] == "true")}, nil
}
