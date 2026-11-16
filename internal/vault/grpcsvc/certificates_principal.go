// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/tls"
	"errors"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ReplaceCertificateForPrincipal is ReplaceCertificate for a personal token or
// a service account (#213). The human RPC gates on canManageOrOwnSecret, which
// reads a person's user id; a machine is judged by the principal rules instead:
// Author on the secret's folder chain and on its own ruleset
// (principalMutableSecret), never an admin flag. Everything after the gate
// follows the human path: certificate secrets only, the file is parsed the same
// way, the cert fields are written over the stored ones in place, a version is
// appended, and the secret keeps its id, folder, name, target and ruleset. A
// multi-entry container with no alias returns the aliases and changes nothing.
// The event names the principal kind; the file and passphrase never reach a log.
func (s *Server) ReplaceCertificateForPrincipal(ctx context.Context, req *vaultv1.ReplaceCertificateForPrincipalRequest) (*vaultv1.ReplaceCertificateForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "certificate replace"); err != nil {
		return nil, err
	}
	l := s.lg(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetSecretId(), "replace")
	if err != nil {
		l.Info("certificate replace refused", log.F("secret_id", req.GetSecretId()), log.F("principal_kind", actor.GetPrincipalKind().String()), log.F("code", status.Code(err).String()))
		return nil, err
	}
	if sec.GetTypeId() != certSecretTypeID {
		return nil, status.Error(codes.InvalidArgument, "secret is not an SSL/PKI certificate")
	}

	fields, meta, aliases, err := certsvc.ImportFields(req.GetFileBytes(), req.GetPassphrase(), req.GetAlias())
	if len(aliases) > 0 {
		l.Debug("certificate replace needs an alias", log.F("secret_id", sec.GetId()), log.F("entries", len(aliases)))
		return &vaultv1.ReplaceCertificateForPrincipalResponse{Aliases: aliases}, nil
	}
	if err != nil {
		if errors.Is(err, certsvc.ErrWrongPassphrase) {
			return nil, status.Error(codes.InvalidArgument, "wrong passphrase")
		}
		return nil, status.Errorf(codes.InvalidArgument, "parse certificate: %v", err)
	}

	// A key that does not belong to the certificate is refused before anything
	// is stored. The upload parser does not compare them, and a machine has no
	// person looking at the result, so this call checks.
	if key := fields[certsvc.FieldPrivateKey]; key != "" {
		if _, err := tls.X509KeyPair([]byte(fields[certsvc.FieldCertificate]), []byte(key)); err != nil {
			return nil, status.Error(codes.InvalidArgument, "private key does not match the certificate")
		}
	}

	if err := s.writeCertificateFields(ctx, actor, sec, fields); err != nil {
		return nil, err
	}
	sec.ExpiresAt = certExpiresAt(meta)

	s.emitAttrs(ctx, principalActorID(actor), "certificate.replace", sec.GetId(), true, principalAttrs(actor, nil))
	s.notifyInformed(ctx, principalActorID(actor), "certificate.replace", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	l.Info("certificate replaced in place", log.F("secret_id", sec.GetId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
	return &vaultv1.ReplaceCertificateForPrincipalResponse{
		Secret: s.principalSecretView(sec),
		Meta:   certMetaFromCertkit(meta, fields[certsvc.FieldHasPrivateKey] == "true"),
	}, nil
}

// writeCertificateFields lays a parsed certificate's fields over the secret's
// stored ones and, when anything changed, reseals them as a new active version.
// Fields the upload leaves empty and the record never stored are skipped, so a
// no-op mints no version. Caller holds s.mu (write).
func (s *Server) writeCertificateFields(ctx context.Context, actor *vaultv1.ActorContext, sec *vaultv1.Secret, fields map[string]string) error {
	cur := map[string]string{}
	if rec, ok := s.records[sec.GetId()]; ok {
		opened, err := s.crypt.OpenAll(rec)
		if err != nil {
			return status.Error(codes.Internal, "open existing record")
		}
		cur = opened
	}
	merged := make(map[string]string, len(cur)+len(fields))
	for k, v := range cur {
		merged[k] = v
	}
	for k, v := range fields {
		// Absent and empty read the same, so an empty value the record never
		// stored must not mint a version.
		if _, stored := cur[k]; !stored && v == "" {
			continue
		}
		merged[k] = v
	}
	// The same authoritative key-pair check every save runs.
	if err := verifyKeyPairFields(merged); err != nil {
		return err
	}
	if !stringMapsEqual(cur, merged) {
		rec, err := s.crypt.Seal(merged)
		if err != nil {
			return status.Error(codes.Internal, "seal fields")
		}
		s.records[sec.GetId()] = rec
		var ledgerNo int
		if s.vers != nil {
			ledgerNo, _ = s.vers.AppendActive(ctx, sec.GetId(), rec, principalActorID(actor))
		}
		s.markValueChanged(ctx, sec, ledgerNo)
		s.resumeHeartbeatOnValueChange(ctx, sec, principalActorID(actor), map[string]string{"reason": "credential_updated"})
	}
	return nil
}
