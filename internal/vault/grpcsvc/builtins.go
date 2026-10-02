// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
)

// BuiltinTypes returns the full built-in secret-type catalogue that ships with
// Sneakers. It mirrors the web UI's mock secret-type catalogue
// one-for-one so mock and live render identically. Every entry is read-only at
// runtime (origin SYSTEM, or an imported EXTENSION pack) — no one can edit
// or delete them. seed() installs these into a fresh vault; cmd/seed upserts them
// into an existing one (which then hydrates them on restart).
func BuiltinTypes() []*vaultv1.SecretType {
	// Field-kind / origin shorthands keep the catalogue readable (matches the
	// txt/pwd/ext idiom used elsewhere in seed()).
	var (
		text  = vaultv1.FieldKind_FIELD_KIND_TEXT
		pass  = vaultv1.FieldKind_FIELD_KIND_PASSWORD
		multi = vaultv1.FieldKind_FIELD_KIND_MULTILINE
		sel   = vaultv1.FieldKind_FIELD_KIND_SELECT
		sens  = vaultv1.FieldKind_FIELD_KIND_SENSITIVE // fixed secret value: masked/revealed, never generated/rotated
		boolK = vaultv1.FieldKind_FIELD_KIND_BOOLEAN
		sys   = vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM
	)
	// desc/notes mirror the mock's shared DESC/NOTES field consts. Fresh copies
	// (not a shared pointer) so no type can alias another's field object.
	desc := func() *vaultv1.SecretFieldDef {
		return &vaultv1.SecretFieldDef{Key: "description", Label: "Description", Kind: multi}
	}
	notes := func() *vaultv1.SecretFieldDef {
		return &vaultv1.SecretFieldDef{Key: "notes", Label: "Notes", Kind: multi}
	}

	// The four types the vault has always seeded, kept verbatim from seed()'s
	// original inline definitions (they intentionally diverge from the mock in a
	// couple of spots — e.g. no Description field on Password/SSH Key).
	pw := &vaultv1.SecretType{
		Id: "type-password", Name: "Password", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM,
		Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
			{Key: "password", Label: "Password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Required: true, Sensitive: true},
			{Key: "notes", Label: "Notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		},
	}
	ad := &vaultv1.SecretType{
		Id: "type-windows-domain", Name: "Windows Domain Account", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM,
		Heartbeat: true, Checkout: true, Rotation: true,
		Fields: []*vaultv1.SecretFieldDef{
			{Key: "domain", Label: "Domain", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
			{Key: "username", Label: "Username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
			{Key: "password", Label: "Password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Required: true, Sensitive: true, Rotates: true},
		},
	}
	// SSH private-key account: heartbeat-validated + checkout-able. Fields
	// mirror the UI mock's type-ssh-key exactly (username/keyFormat/publicKey/
	// privateKey/passphrase/notes) so mock and live render identically.
	sshKey := &vaultv1.SecretType{
		Id: "type-ssh-key", Name: "SSH Key", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM,
		Heartbeat: true, Checkout: true,
		Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
			{Key: "keyFormat", Label: "Key Format", Kind: vaultv1.FieldKind_FIELD_KIND_SELECT,
				Options: []string{"Ed25519", "RSA 4096", "RSA 2048", "ECDSA P-256"}, DefaultValue: "Ed25519", Required: true},
			{Key: "publicKey", Label: "Public Key", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
			// Key material is SENSITIVE, not a password: masked/revealed but never
			// generated, rotated, or policy-checked like an account password.
			{Key: "privateKey", Label: "Private Key", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Required: true, Sensitive: true},
			{Key: "passphrase", Label: "Passphrase", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true},
			{Key: "notes", Label: "Notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		},
	}

	// TLS/PKI certificate + private key pair. Field keys reuse certsvc's
	// exported Field* constants (never hardcoded strings) so this schema and
	// certsvc's ImportFields/ExportBytes map keys can never drift. Key material
	// is SENSITIVE + SuperSensitive — same kind as type-ssh-key's private key,
	// plus the extra double-reveal gate high-value fields (bank/PIN/etc.) use.
	// The nine metadata fields plus the two derived booleans below are parsed
	// out of the uploaded container by certsvc on import; the proto's
	// SecretFieldDef has no read-only/display flag and no other builtin marks
	// a field derived, so the text ones are plain, non-required TEXT fields
	// like every other builtin's informational fields (e.g. type-ssh-key's
	// publicKey). Heartbeat/rotation are OFF — there is no connector-driven
	// rotation flow for arbitrary certs.
	sslCert := &vaultv1.SecretType{
		Id: "type-ssl-cert", Name: "SSL/PKI Certificate", Origin: sys,
		Fields: []*vaultv1.SecretFieldDef{
			{Key: certsvc.FieldCertificate, Label: "Certificate", Kind: multi, Required: true},
			{Key: certsvc.FieldPrivateKey, Label: "Private Key", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true, SuperSensitive: true},
			{Key: certsvc.FieldChain, Label: "Chain", Kind: multi},
			{Key: certsvc.FieldSubject, Label: "Subject", Kind: text},
			{Key: certsvc.FieldIssuer, Label: "Issuer", Kind: text},
			{Key: certsvc.FieldSANs, Label: "Subject Alternative Names", Kind: text},
			{Key: certsvc.FieldSerialNumber, Label: "Serial Number", Kind: text},
			{Key: certsvc.FieldFingerprintSHA256, Label: "Fingerprint (SHA-256)", Kind: text},
			{Key: certsvc.FieldNotBefore, Label: "Not Before", Kind: text},
			{Key: certsvc.FieldNotAfter, Label: "Not After", Kind: text},
			{Key: certsvc.FieldKeyAlgorithm, Label: "Key Algorithm", Kind: text},
			{Key: certsvc.FieldKeyBits, Label: "Key Size (bits)", Kind: text},
			// Two derived booleans certsvc.ImportFields persists alongside the
			// metadata above: without a stored field,
			// GetSecretFields (which only echoes stored keys) has nothing to
			// return, so the staff UI could never tell a key-bearing secret from
			// a cert-only one, or a CA cert from a leaf, without this.
			{Key: certsvc.FieldHasPrivateKey, Label: "Private Key Present", Kind: boolK},
			{Key: certsvc.FieldIsCA, Label: "CA Certificate", Kind: boolK},
			notes(),
		},
	}

	// Full catalogue, in the mock's declaration order. The three kept-verbatim
	// types above are slotted into their original positions; the rest are
	// transcribed from the UI mock catalogue faithfully (fields, labels, options,
	// required/sensitive flags). Every entry is origin SYSTEM — importable
	// EXTENSION packs live in ExtensionCatalog, not here.
	return []*vaultv1.SecretType{
		pw,
		{Id: "type-secure-note", Name: "Secure Note", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "note", Label: "Note", Kind: multi, Required: true, Sensitive: true},
		}},
		{Id: "type-web-password", Name: "Web Password", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "url", Label: "URL", Kind: text, Required: true},
			{Key: "username", Label: "Username", Kind: text, Required: true},
			{Key: "password", Label: "Password", Kind: pass, Required: true, Sensitive: true},
			notes(),
		}},
		sshKey,
		{Id: "type-api-token", Name: "API Token", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "scheme", Label: "Scheme", Kind: sel,
				Options: []string{"Bearer", "OAuth", "Custom header"}, DefaultValue: "Bearer"},
			// A token is a fixed secret value, not a generatable password.
			{Key: "token", Label: "Token", Kind: sens, Required: true, Sensitive: true},
			{Key: "endpoint", Label: "Endpoint / API URL", Kind: text},
			notes(),
		}},
		// OAuth 2.0 application — the client (id + secret), the tokens it obtains
		// (access + refresh), and its redirect/callback URL. Client secret + tokens
		// are fixed secret values (SENSITIVE), never generated/rotated.
		{Id: "type-oauth", Name: "OAuth Application", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "clientId", Label: "Client ID", Kind: text, Required: true},
			{Key: "clientSecret", Label: "Client Secret", Kind: sens, Required: true, Sensitive: true},
			{Key: "redirectUrl", Label: "Redirect URL", Kind: text},
			{Key: "accessToken", Label: "Access Token", Kind: sens, Sensitive: true},
			{Key: "refreshToken", Label: "Refresh Token", Kind: sens, Sensitive: true},
			notes(),
		}},
		// MFA recovery / backup codes — the one-time codes a site issues so you
		// can still get in if you lose your authenticator.
		{Id: "type-recovery-codes", Name: "Recovery / Backup Codes", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "service", Label: "Service / Site", Kind: text, Required: true},
			{Key: "account", Label: "Account / Username", Kind: text},
			{Key: "codes", Label: "Recovery / Backup Codes", Kind: multi, Required: true, Sensitive: true},
			notes(),
		}},
		{Id: "type-database-account", Name: "Database Account", Origin: sys, Heartbeat: true, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "engine", Label: "Engine", Kind: sel,
				Options: []string{"PostgreSQL", "MySQL / MariaDB", "SQL Server", "Oracle", "MongoDB", "Other"}, DefaultValue: "PostgreSQL"},
			{Key: "server", Label: "Server", Kind: text, Required: true},
			{Key: "port", Label: "Port", Kind: text},
			{Key: "database", Label: "Database", Kind: text},
			{Key: "username", Label: "Username", Kind: text, Required: true},
			{Key: "password", Label: "Password", Kind: pass, Required: true, Sensitive: true, Rotates: true},
			notes(),
		}},
		// Password-authenticated SSH account. Heartbeat + rotation are OFF (the
		// connector doesn't agentlessly rotate Unix passwords); the user can still
		// associate a target and open a password SSH session. The password stays a
		// generatable field but is never auto-rotated.
		{Id: "type-unix-ssh", Name: "Password Account (SSH)", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "host", Label: "Host", Kind: text, Required: true},
			{Key: "username", Label: "Username", Kind: text, Required: true},
			{Key: "password", Label: "Password", Kind: pass, Required: true, Sensitive: true},
			notes(),
		}},
		{Id: "type-windows-local", Name: "Windows Account (Local)", Origin: sys, Heartbeat: true, Checkout: true, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "machine", Label: "Machine", Kind: text, Required: true},
			{Key: "username", Label: "Username", Kind: text, Required: true},
			{Key: "password", Label: "Password", Kind: pass, Required: true, Sensitive: true, Rotates: true},
			notes(),
		}},
		ad,
		{Id: "type-active-directory", Name: "Active Directory Account", Origin: sys, Heartbeat: true, Checkout: true, Rotation: true, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "domain", Label: "Domain (FQDN)", Kind: text, Required: true},
			// Optional so secrets saved before it existed stay valid; the down-level
			// DOMAIN\user logon name is built from it.
			{Key: "netbios", Label: "NetBIOS domain", Kind: text},
			{Key: "username", Label: "Account Name", Kind: text, Required: true},
			{Key: "password", Label: "Password", Kind: pass, Required: true, Sensitive: true, Rotates: true},
			// Flags for the privileged account Sneakers uses to perform AD rotation.
			{Key: "serviceAccount", Label: "Service account", Kind: boolK},
			{Key: "gmsa", Label: "gMSA account", Kind: boolK},
			notes(),
		}},
		{Id: "type-bank-account", Name: "Bank Account", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "bank", Label: "Bank name", Kind: text},
			{Key: "accountNumber", Label: "Account number", Kind: sens, Required: true, Sensitive: true, SuperSensitive: true, Pattern: `^\d{4,17}$`, MaxLength: 17},
			{Key: "routingNumber", Label: "Routing number", Kind: sens, Sensitive: true, SuperSensitive: true, Pattern: `^\d{9}$`, MaxLength: 9},
			{Key: "onlineUsername", Label: "Online username", Kind: text},
			{Key: "onlinePassword", Label: "Online password", Kind: sens, Sensitive: true, SuperSensitive: true},
			notes(),
		}},
		{Id: "type-credit-card", Name: "Credit Card", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "cardholder", Label: "Cardholder", Kind: text},
			// Digits with optional grouping spaces; 23 chars fits 19 digits + spaces.
			{Key: "number", Label: "Card number", Kind: sens, Required: true, Sensitive: true, SuperSensitive: true, Pattern: `^[0-9 ]{13,23}$`, MaxLength: 23},
			{Key: "expiry", Label: "Expiry (MM/YY or MM/YYYY)", Kind: text, Pattern: `^(0[1-9]|1[0-2])\/([0-9]{2}|[0-9]{4})$`, MaxLength: 7},
			{Key: "cvv", Label: "CVV", Kind: sens, Sensitive: true, SuperSensitive: true, Pattern: `^[0-9]{3,4}$`, MaxLength: 4},
			notes(),
		}},
		{Id: "type-license-key", Name: "License Key", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "product", Label: "Product", Kind: text, Required: true},
			{Key: "licenseKey", Label: "License key", Kind: sens, Required: true, Sensitive: true},
			notes(),
		}},
		{Id: "type-combination-lock", Name: "Combination Lock", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "location", Label: "Location", Kind: text},
			{Key: "combination", Label: "Combination", Kind: sens, Required: true, Sensitive: true},
			notes(),
		}},
		{Id: "type-pin", Name: "PIN", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "pin", Label: "PIN", Kind: sens, Required: true, Sensitive: true, SuperSensitive: true, Pattern: `^\d{3,12}$`, MaxLength: 12},
			notes(),
		}},
		{Id: "type-ssn", Name: "Social Security Number", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "holderName", Label: "Holder name", Kind: text},
			{Key: "ssn", Label: "SSN", Kind: sens, Required: true, Sensitive: true, SuperSensitive: true, Pattern: `^\d{3}-?\d{2}-?\d{4}$`, MaxLength: 11},
			notes(),
		}},
		{Id: "type-contact", Name: "Contact", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "fullName", Label: "Full name", Kind: text, Required: true},
			{Key: "email", Label: "Email", Kind: sens, Sensitive: true, Pattern: `^[^@\s]+@[^@\s]+\.[^@\s]+$`, MaxLength: 254},
			{Key: "phone", Label: "Phone", Kind: sens, Sensitive: true, Pattern: `^[0-9+()\-.\s]{7,20}$`, MaxLength: 20},
			{Key: "addressLine1", Label: "Address line 1", Kind: text},
			{Key: "addressLine2", Label: "Address line 2 (apt/unit)", Kind: text},
			{Key: "city", Label: "City", Kind: text},
			{Key: "state", Label: "State", Kind: text},
			{Key: "zip", Label: "ZIP", Kind: text},
			notes(),
		}},
		// Anthropic API token — a single fixed secret string, NOT the OAuth
		// client/refresh shape (that's the separate type-oauth). Always begins
		// "sk-ant-oa".
		{Id: "type-anthropic-token", Name: "Anthropic Token", Origin: sys, Fields: []*vaultv1.SecretFieldDef{
			desc(),
			{Key: "token", Label: "Token", Kind: sens, Required: true, Sensitive: true, Pattern: `^sk-ant-oa`},
			notes(),
		}},
		// Appended (catalogue lifecycle rule: additive only, never
		// reordered/altered above this point).
		sslCert,
	}
}

// ExtensionCatalog returns the importable extension packs (origin EXTENSION).
// These are NOT installed as usable types — they are registered so an admin can
// import one, at which point it becomes a read-only extension type. seed()
// registers them into a fresh vault; cmd/seed upserts them into an existing one's
// extension_catalog table (which then hydrates on restart).
func ExtensionCatalog() []*vaultv1.SecretType {
	txt := vaultv1.FieldKind_FIELD_KIND_TEXT
	pwd := vaultv1.FieldKind_FIELD_KIND_PASSWORD
	// Key material is SENSITIVE, not a password: masked/revealed, never
	// generated or rotated — same kind type-ssh-key uses for its private key.
	sens := vaultv1.FieldKind_FIELD_KIND_SENSITIVE
	ext := vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION
	return []*vaultv1.SecretType{
		{Id: "ext-aws-iam-key", Name: "Amazon IAM Access Key", Origin: ext, Vendor: "Amazon Web Services", Fields: []*vaultv1.SecretFieldDef{
			{Key: "accountId", Label: "Account ID", Kind: txt},
			{Key: "accessKeyId", Label: "Access Key ID", Kind: txt, Required: true},
			{Key: "secretAccessKey", Label: "Secret Access Key", Kind: pwd, Required: true, Sensitive: true},
		}},
		{Id: "ext-azure-ad", Name: "Microsoft Azure AD Account", Origin: ext, Vendor: "Microsoft Azure", Fields: []*vaultv1.SecretFieldDef{
			{Key: "tenantId", Label: "Tenant ID", Kind: txt, Required: true},
			{Key: "appId", Label: "Application (client) ID", Kind: txt, Required: true},
			{Key: "clientSecret", Label: "Client secret", Kind: pwd, Required: true, Sensitive: true},
		}},
		{Id: "ext-gcp-sa-key", Name: "Google Cloud Service Account Key", Origin: ext, Vendor: "Google Cloud", Fields: []*vaultv1.SecretFieldDef{
			{Key: "project", Label: "Project ID", Kind: txt, Required: true},
			{Key: "clientEmail", Label: "Service account email", Kind: txt, Required: true},
			{Key: "keyJson", Label: "Key (JSON)", Kind: pwd, Required: true, Sensitive: true},
		}},
		// Docusign app (JWT) authentication — the Integration Key + impersonated
		// User ID + API Account ID + the RSA key pair's private key that a Docusign
		// app uses to mint JWT grants. The private key uses field key "privateKey"
		// so the staff secret editor renders it in its multi-line SENSITIVE
		// textarea (SecretEditorPage keys the key-material box on that field).
		{Id: "type-docusign-ssh-keys", Name: "Docusign App SSH Keys", Origin: ext, Vendor: "Docusign", Fields: []*vaultv1.SecretFieldDef{
			{Key: "integrationKey", Label: "Integration Key (Client ID)", Kind: txt, Required: true},
			{Key: "userId", Label: "User ID (Impersonated user GUID)", Kind: txt, Required: true},
			{Key: "apiAccountId", Label: "API Account ID", Kind: txt, Required: true},
			{Key: "baseUri", Label: "Base URI", Kind: txt, DefaultValue: "account-d.docusign.com"},
			{Key: "privateKey", Label: "RSA Private Key", Kind: sens, Required: true, Sensitive: true},
		}},
	}
}

// BuiltinConnections is the shared set of default connections every vault ships
// with — the protocol templates a target binds to (SSH/WinRM/LDAPS). Without at
// least one, no target can be created, so these are seeded, not optional.
func BuiltinConnections() []*vaultv1.Connection {
	return []*vaultv1.Connection{
		{Id: "conn-ssh-default", Name: "Default SSH", Protocol: "ssh", Port: 22, UseTls: false, Description: "Standard SSH to Unix/Linux hosts."},
		{Id: "conn-winrm-default", Name: "Default WinRM", Protocol: "winrm", Port: 5986, UseTls: true, Description: "WinRM over HTTPS to Windows hosts."},
		{Id: "conn-ldaps", Name: "Directory (LDAPS)", Protocol: "ldap", Port: 636, UseTls: true, Description: "Active Directory / LDAP over TLS."},
	}
}
