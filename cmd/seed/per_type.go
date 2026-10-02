// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// sampleValue returns a plausible display value for one field.
func sampleValue(f *vaultv1.SecretFieldDef) string {
	byKey := map[string]string{
		"url": "https://example.com/login", "domain": "corp.example.com", "host": "host01.example.com",
		"server": "db01.example.com", "machine": "WORKSTATION01", "database": "appdb", "port": "5432",
		"username": "sampleuser", "account": "sampleuser", "service": "GitHub", "engine": "PostgreSQL",
		"realm": "EXAMPLE.COM", "cardNumber": "4111 1111 1111 1111", "iban": "GB33BUKB20201555555555",
		"routingNumber": "021000021", "accountNumber": "000123456789", "cvv": "123", "pin": "4826",
		"combination": "12-34-56", "licensee": "Example Corp", "expiry": "12/28",
	}
	switch f.GetKind() {
	case vaultv1.FieldKind_FIELD_KIND_PASSWORD:
		return "S@mpleP@ssw0rd!"
	case vaultv1.FieldKind_FIELD_KIND_SENSITIVE:
		switch f.GetKey() {
		case "privateKey":
			return "-----BEGIN OPENSSH PRIVATE KEY-----\nc2FtcGxlIGtleSBtYXRlcmlhbCAtIG5vdCByZWFsIC0gZm9yIGRpc3BsYXkgb25seQ==\n-----END OPENSSH PRIVATE KEY-----" // gitleaks:allow -- a display placeholder, not a key
		case "passphrase":
			return "sample-passphrase"
		default:
			return "tok_sample_0123456789abcdef"
		}
	case vaultv1.FieldKind_FIELD_KIND_MULTILINE:
		if f.GetKey() == "publicKey" {
			return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISampleSamplePublicKeyForDisplayOnly sample@sneakers"
		}
		if f.GetKey() == "codes" {
			return "1111-2222\n3333-4444\n5555-6666"
		}
		return "Sample text for review — not a real secret."
	case vaultv1.FieldKind_FIELD_KIND_BOOLEAN:
		return "false"
	case vaultv1.FieldKind_FIELD_KIND_SELECT:
		if f.GetDefaultValue() != "" {
			return f.GetDefaultValue()
		}
		if len(f.GetOptions()) > 0 {
			return f.GetOptions()[0]
		}
		return ""
	case vaultv1.FieldKind_FIELD_KIND_FILE:
		return "sample.txt"
	default: // TEXT
		if v, ok := byKey[f.GetKey()]; ok {
			return v
		}
		return "sample-" + f.GetKey()
	}
}

// seedPerType creates one sample secret of every SYSTEM secret type in a target
// folder, via the vault's own gRPC API (so values are sealed exactly like a real
// create). DEV/QA-ONLY — for eyeballing how each type renders. Re-running makes
// another set. Env: VAULT_ADDR (default vault:9091), SEED_FOLDER, SEED_USER.
func seedPerType(ctx context.Context) error {
	logger := log.New("seedsecrets")
	addr := env("VAULT_ADDR", "vault:9091")
	folder := env("SEED_FOLDER", "folder-personal-turing")
	user := env("SEED_USER", "user-turing")

	conn := dial(addr)
	defer func() { _ = conn.Close() }()
	c := vaultv1.NewVaultServiceClient(conn)
	actor := &vaultv1.ActorContext{UserId: user, IsSiteAdmin: true}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	tr, err := c.ListSecretTypes(ctx, &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		return fmt.Errorf("list types: %w", err)
	}
	var made int
	for _, t := range tr.GetTypes() {
		if t.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
			continue // skip importable extensions
		}
		fields := map[string]string{}
		for _, f := range t.GetFields() {
			fields[f.GetKey()] = sampleValue(f)
		}
		resp, err := c.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
			Actor: actor, Name: t.GetName() + " (sample)", FolderId: folder, TypeId: t.GetId(), Fields: fields,
		})
		if err != nil {
			logger.Error().Err(err).Str("type", t.GetId()).Msg("create failed")
			continue
		}
		made++
		fmt.Printf("  created %-28s -> %s\n", t.GetName(), resp.GetSecret().GetId())
	}
	logger.Info().Int("created", made).Str("folder", folder).Msg("seedsecrets done")
	return nil
}
