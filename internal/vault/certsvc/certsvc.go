// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package certsvc wraps github.com/Bugs5382/go-certkit to translate between
// the raw certificate/key container formats a user uploads or downloads
// (PKCS#12, PEM, DER, PKCS#7, JKS/JCEKS) and the plain string-field map the
// vault secret store persists. It has no dependency on the vault gRPC
// contract or store — it only knows how to parse an uploaded file into fields
// and assemble fields back into an exportable file.
package certsvc

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	certkit "github.com/Bugs5382/go-certkit"
)

// ErrWrongPassphrase is returned when the supplied passphrase fails to
// decrypt an encrypted private key, PKCS#12 archive or JKS/JCEKS keystore. It
// wraps certkit.ErrWrongPassphrase so callers only need to know this
// package's sentinel.
var ErrWrongPassphrase = errors.New("certsvc: wrong passphrase")

// ErrNoPrivateKey is returned by ExportBytes when the requested format
// requires a private key (PKCS#12, JKS, PEM bundle, PEM key-only) but fields
// carries none. It wraps certkit.ErrNoPrivateKey.
var ErrNoPrivateKey = errors.New("certsvc: no private key")

// Field names used in the fields map produced by ImportFields and consumed
// by ExportBytes.
const (
	FieldCertificate       = "certificate"
	FieldPrivateKey        = "privateKey"
	FieldChain             = "chain"
	FieldSubject           = "subject"
	FieldIssuer            = "issuer"
	FieldSANs              = "sans"
	FieldSerialNumber      = "serialNumber"
	FieldFingerprintSHA256 = "fingerprintSha256"
	FieldNotBefore         = "notBefore"
	FieldNotAfter          = "notAfter"
	FieldKeyAlgorithm      = "keyAlgorithm"
	FieldKeyBits           = "keyBits"
	FieldHasPrivateKey     = "hasPrivateKey"
	FieldIsCA              = "isCA"
)

// ImportFields parses fileBytes (in any container format go-certkit
// recognizes: PKCS#12, PEM, DER, PKCS#7 or JKS/JCEKS) into the string fields
// the vault secret store persists, plus the parsed certkit.Meta.
//
// passphrase decrypts an encrypted private key, PKCS#12 archive or JKS/JCEKS
// keystore; pass "" when the input is not encrypted.
//
// alias selects a single entry of a multi-alias JKS/JCEKS keystore (via
// certkit.ParseEntry); pass "" to use certkit.Parse, which succeeds directly
// for single-entry containers.
//
// If the container holds more than one distinct entry and alias is empty,
// ImportFields returns no error: fields and meta are zero, and aliases lists
// the entries the caller must choose from (re-call with one of them as
// alias).
func ImportFields(fileBytes []byte, passphrase, alias string) (map[string]string, certkit.Meta, []string, error) {
	bundle, err := parseBundle(fileBytes, passphrase, alias)
	if err != nil {
		var multi *certkit.ErrMultipleEntries
		if errors.As(err, &multi) {
			return nil, certkit.Meta{}, multi.Aliases, nil
		}
		if errors.Is(err, certkit.ErrWrongPassphrase) {
			return nil, certkit.Meta{}, nil, ErrWrongPassphrase
		}
		return nil, certkit.Meta{}, nil, err
	}
	return fieldsFromBundle(bundle), bundle.Meta, nil, nil
}

// parseBundle dispatches to certkit.ParseEntry when alias is given, otherwise
// certkit.Parse.
func parseBundle(fileBytes []byte, passphrase, alias string) (certkit.Bundle, error) {
	if alias != "" {
		return certkit.ParseEntry(fileBytes, passphrase, alias)
	}
	return certkit.Parse(fileBytes, passphrase)
}

// fieldsFromBundle flattens a parsed Bundle into the string map the vault
// secret store persists: the three PEM fields, the stringified Meta, and two
// booleans (as "true"/"false") derived from the bundle itself so the staff UI
// can tell key-bearing from cert-only secrets and CA from leaf certs without
// ever seeing the private key material — GetSecretFields only ever echoes
// stored, non-sensitive keys, so these must be persisted here to be readable
// at all.
func fieldsFromBundle(b certkit.Bundle) map[string]string {
	return map[string]string{
		FieldCertificate:       string(b.LeafPEM),
		FieldPrivateKey:        string(b.KeyPEM),
		FieldChain:             joinChainPEM(b.ChainPEM),
		FieldSubject:           b.Meta.Subject,
		FieldIssuer:            b.Meta.Issuer,
		FieldSANs:              strings.Join(b.Meta.SANs, ","),
		FieldSerialNumber:      b.Meta.SerialNumber,
		FieldFingerprintSHA256: b.Meta.FingerprintSHA256,
		FieldNotBefore:         b.Meta.NotBefore.Format(time.RFC3339),
		FieldNotAfter:          b.Meta.NotAfter.Format(time.RFC3339),
		FieldKeyAlgorithm:      b.Meta.KeyAlgorithm,
		FieldKeyBits:           strconv.Itoa(b.Meta.KeyBits),
		FieldHasPrivateKey:     strconv.FormatBool(len(b.KeyPEM) > 0),
		FieldIsCA:              strconv.FormatBool(b.Meta.IsCA),
	}
}

// joinChainPEM concatenates a Bundle's chain PEM blocks (each already
// newline-terminated by pem.Encode) with a newline separator into the single
// "chain" field string.
func joinChainPEM(chainPEM [][]byte) string {
	if len(chainPEM) == 0 {
		return ""
	}
	parts := make([]string, len(chainPEM))
	for i, c := range chainPEM {
		parts[i] = string(c)
	}
	return strings.Join(parts, "\n")
}

// ExportBytes assembles fields (as produced by ImportFields, or edited/typed
// in by hand) into the requested container format, returning the encoded
// bytes, a suggested filename and its content type.
//
// format is one of: pkcs12, pem, pem-cert, pem-key, pem-fullchain, der,
// pkcs7, jks.
//
// newPassphrase protects the output for formats that support encryption
// (PKCS#12 and JKS always; the private key of pem/pem-key otherwise); it is
// ignored by the cert-only formats (pem-cert, pem-fullchain, der, pkcs7).
//
// Exporting a key-bearing format from fields with no privateKey returns
// ErrNoPrivateKey.
func ExportBytes(fields map[string]string, format, newPassphrase string) ([]byte, string, string, error) {
	f, ok := certkitFormat(format)
	if !ok {
		return nil, "", "", fmt.Errorf("certsvc: unsupported export format %q", format)
	}

	data, err := certkit.Export(bundleFromFields(fields), f, newPassphrase)
	if err != nil {
		if errors.Is(err, certkit.ErrNoPrivateKey) {
			return nil, "", "", ErrNoPrivateKey
		}
		return nil, "", "", err
	}

	filename, contentType := exportMeta(f)
	return data, filename, contentType, nil
}

// bundleFromFields rebuilds a certkit.Bundle from the string fields map.
func bundleFromFields(fields map[string]string) certkit.Bundle {
	return certkit.Bundle{
		LeafPEM:  []byte(fields[FieldCertificate]),
		KeyPEM:   []byte(fields[FieldPrivateKey]),
		ChainPEM: splitChainPEM(fields[FieldChain]),
	}
}

// splitChainPEM decodes a "chain" field string back into the individual
// PEM-encoded certificate blocks certkit.Bundle.ChainPEM expects, one []byte
// per certificate. It scans for PEM block markers rather than trusting the
// newline separator ImportFields joined with, so it round-trips a chain
// field regardless of how it was reformatted (e.g. by a UI textarea) between
// import and export.
func splitChainPEM(chain string) [][]byte {
	if chain == "" {
		return nil
	}
	var out [][]byte
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, pem.EncodeToMemory(block))
	}
	return out
}

// certkitFormat maps the export format string to its certkit.Format enum
// value.
func certkitFormat(format string) (certkit.Format, bool) {
	switch format {
	case certkit.PKCS12.String():
		return certkit.PKCS12, true
	case certkit.PEMBundle.String():
		return certkit.PEMBundle, true
	case certkit.PEMCertOnly.String():
		return certkit.PEMCertOnly, true
	case certkit.PEMKeyOnly.String():
		return certkit.PEMKeyOnly, true
	case certkit.PEMFullchain.String():
		return certkit.PEMFullchain, true
	case certkit.DER.String():
		return certkit.DER, true
	case certkit.PKCS7.String():
		return certkit.PKCS7, true
	case certkit.JKS.String():
		return certkit.JKS, true
	default:
		return 0, false
	}
}

// exportMeta returns the suggested filename and MIME content type for an
// export Format.
func exportMeta(f certkit.Format) (filename, contentType string) {
	switch f {
	case certkit.PKCS12:
		return "certificate.p12", "application/x-pkcs12"
	case certkit.PEMBundle:
		return "certificate.pem", "application/x-pem-file"
	case certkit.PEMCertOnly:
		return "certificate.crt", "application/x-pem-file"
	case certkit.PEMKeyOnly:
		return "private-key.pem", "application/x-pem-file"
	case certkit.PEMFullchain:
		return "fullchain.pem", "application/x-pem-file"
	case certkit.DER:
		return "certificate.der", "application/pkix-cert"
	case certkit.PKCS7:
		return "certificate.p7b", "application/x-pkcs7-certificates"
	case certkit.JKS:
		return "certificate.jks", "application/octet-stream"
	default:
		return "certificate.bin", "application/octet-stream"
	}
}

// ErrInvalidCertificate, ErrInvalidPrivateKey and ErrInvalidChain are returned
// by StoredFieldsMeta when the named stored field does not parse as that kind
// of PEM material. They never carry the material itself.
var (
	ErrInvalidCertificate = errors.New("certsvc: certificate field does not hold a PEM certificate")
	ErrInvalidPrivateKey  = errors.New("certsvc: privateKey field does not hold an unencrypted PEM private key")
	ErrInvalidChain       = errors.New("certsvc: chain field does not hold PEM certificates")
)

// StoredFieldsMeta parses certificate material already held in string fields
// (certificate, optional privateKey, optional chain) with the same parser
// ImportFields uses for an upload, and returns the derived metadata fields an
// import would persist alongside them (subject, issuer, ..., hasPrivateKey,
// isCA), plus the parsed Meta. The PEM fields themselves are not returned, so
// the caller keeps the stored values as they are. There is no passphrase: an
// encrypted key is refused.
func StoredFieldsMeta(fields map[string]string) (map[string]string, certkit.Meta, error) {
	leaf, err := certkit.Parse([]byte(fields[FieldCertificate]), "")
	// The certificate field is not sensitive, so key material there is refused.
	if err != nil || len(leaf.LeafPEM) == 0 || len(leaf.KeyPEM) > 0 {
		return nil, certkit.Meta{}, ErrInvalidCertificate
	}
	if k := fields[FieldPrivateKey]; k != "" {
		kb, err := certkit.Parse([]byte(k), "")
		if err != nil || len(kb.KeyPEM) == 0 || len(kb.LeafPEM) > 0 {
			return nil, certkit.Meta{}, ErrInvalidPrivateKey
		}
		leaf.KeyPEM = kb.KeyPEM
	}
	if c := fields[FieldChain]; c != "" {
		cb, err := certkit.Parse([]byte(c), "")
		if err != nil || len(cb.LeafPEM) == 0 || len(cb.KeyPEM) > 0 {
			return nil, certkit.Meta{}, ErrInvalidChain
		}
	}
	derived := fieldsFromBundle(leaf)
	for _, k := range []string{FieldCertificate, FieldPrivateKey, FieldChain} {
		delete(derived, k)
	}
	return derived, leaf.Meta, nil
}
