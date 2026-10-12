// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A SELECT field's value must be one of its type's options, on every create
// and update path (human and principal). A case variant that maps to exactly
// one option is stored in the option's canonical case. Stored values that
// predate the check are read back as they are.

type selectFixture struct {
	s      *Server
	folder string
}

func newSelectFixture(t *testing.T) selectFixture {
	t.Helper()
	s := newServer(t)
	f := mutFolder(t, s, "Select")
	grantGroup(t, s, orgCarol, f, "R")
	return selectFixture{s: s, folder: f}
}

func dbFields(over map[string]string) map[string]string {
	all := map[string]string{"server": "db.example.org", "username": "app", "password": "Init1alP@ss-2026"}
	for k, v := range over {
		all[k] = v
	}
	return all
}

func sshFields(over map[string]string) map[string]string {
	all := map[string]string{"username": "deploy", "privateKey": "placeholder-key-material"}
	for k, v := range over {
		all[k] = v
	}
	return all
}

func (fx selectFixture) create(typeID string, fields map[string]string) (string, error) {
	c, err := fx.s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "sel", FolderId: fx.folder, TypeId: typeID, Fields: fields,
	})
	return c.GetSecret().GetId(), err
}

func (fx selectFixture) createAsPrincipal(typeID string, fields map[string]string) (string, error) {
	c, err := fx.s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Name: "sel", FolderId: fx.folder, TypeId: typeID, Fields: fields,
	})
	return c.GetSecret().GetId(), err
}

func (fx selectFixture) fields(t *testing.T, id string) map[string]string {
	t.Helper()
	r, err := fx.s.GetSecretFields(context.Background(), &vaultv1.GetSecretFieldsRequest{Actor: orgCarol, Id: id})
	if err != nil {
		t.Fatalf("GetSecretFields: %v", err)
	}
	return r.GetFields()
}

// wantSelectRefusal checks the coded refusal: InvalidArgument, the reason, the
// field named in message and metadata, and every allowed option listed.
func wantSelectRefusal(t *testing.T, err error, reason, field string, allowed []string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (%v), want InvalidArgument", status.Code(err), err)
	}
	st, _ := status.FromError(err)
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok && i.GetDomain() == errorDomain {
			info = i
		}
	}
	if info == nil || info.GetReason() != reason {
		t.Fatalf("error info = %v, want reason %s", info, reason)
	}
	if info.GetMetadata()["field"] != field {
		t.Fatalf("metadata field = %q, want %q", info.GetMetadata()["field"], field)
	}
	if got := info.GetMetadata()["allowed"]; got != strings.Join(allowed, "|") {
		t.Fatalf("metadata allowed = %q, want %q", got, strings.Join(allowed, "|"))
	}
	msg := st.Message()
	if !strings.Contains(msg, `"`+field+`"`) {
		t.Fatalf("message %q does not name field %q", msg, field)
	}
	for _, o := range allowed {
		if !strings.Contains(msg, `"`+o+`"`) {
			t.Fatalf("message %q does not list option %q", msg, o)
		}
	}
}

var (
	engineOptions    = []string{"PostgreSQL", "MySQL / MariaDB", "SQL Server", "Oracle", "MongoDB", "Other"}
	keyFormatOptions = []string{"Ed25519", "RSA 4096", "RSA 2048", "ECDSA P-256"}
)

func TestCreateAcceptsAnOption(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-database-account", dbFields(map[string]string{"engine": "SQL Server"}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := fx.fields(t, id)["engine"]; got != "SQL Server" {
		t.Fatalf("engine = %q, want SQL Server", got)
	}
}

func TestCreateRefusesAValueOutsideTheOptions(t *testing.T) {
	fx := newSelectFixture(t)
	before := len(fx.s.secrets)
	_, err := fx.create("type-database-account", dbFields(map[string]string{"engine": "postgres"}))
	wantSelectRefusal(t, err, ReasonFieldValueNotAllowed, "engine", engineOptions)
	if len(fx.s.secrets) != before {
		t.Fatal("a refused create stored a secret")
	}
	_, err = fx.createAsPrincipal("type-database-account", dbFields(map[string]string{"engine": "postgres"}))
	wantSelectRefusal(t, err, ReasonFieldValueNotAllowed, "engine", engineOptions)
}

func TestCreateRefusesAMissingRequiredSelect(t *testing.T) {
	fx := newSelectFixture(t)
	_, err := fx.create("type-ssh-key", sshFields(nil))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "keyFormat", keyFormatOptions)
	_, err = fx.create("type-ssh-key", sshFields(map[string]string{"keyFormat": ""}))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "keyFormat", keyFormatOptions)
	_, err = fx.createAsPrincipal("type-ssh-key", sshFields(nil))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "keyFormat", keyFormatOptions)
}

func TestCreateAcceptsAnEmptyOptionalSelect(t *testing.T) {
	fx := newSelectFixture(t)
	if _, err := fx.create("type-database-account", dbFields(nil)); err != nil {
		t.Fatalf("missing optional select: %v", err)
	}
	id, err := fx.create("type-database-account", dbFields(map[string]string{"engine": ""}))
	if err != nil {
		t.Fatalf("empty optional select: %v", err)
	}
	if got := fx.fields(t, id)["engine"]; got != "" {
		t.Fatalf("engine = %q, want empty", got)
	}
}

func TestCreateStoresACaseVariantInTheOptionsCase(t *testing.T) {
	fx := newSelectFixture(t)
	for _, c := range []struct{ typeID, key, in, want string }{
		{"type-ssh-key", "keyFormat", "ED25519", "Ed25519"},
		{"type-ssh-key", "keyFormat", "rsa 4096", "RSA 4096"},
		{"type-database-account", "engine", "postgresql", "PostgreSQL"},
		{"type-active-directory", "logonFormat", "upn", ADLogonFormatUPN},
		{"type-api-token", "scheme", "BEARER", "Bearer"},
	} {
		fields := map[string]string{c.key: c.in}
		switch c.typeID {
		case "type-ssh-key":
			fields = sshFields(fields)
		case "type-database-account":
			fields = dbFields(fields)
		case "type-active-directory":
			fields["domain"], fields["username"], fields["password"] = "ad.example.org", "svc", "Init1alP@ss-2026"
		case "type-api-token":
			fields["token"] = "placeholder-token"
		}
		id, err := fx.create(c.typeID, fields)
		if err != nil {
			t.Fatalf("%s %s=%q: %v", c.typeID, c.key, c.in, err)
		}
		if got := fx.fields(t, id)[c.key]; got != c.want {
			t.Fatalf("%s %s stored %q, want %q", c.typeID, c.key, got, c.want)
		}
	}
	id, err := fx.createAsPrincipal("type-ssh-key", sshFields(map[string]string{"keyFormat": "ecdsa p-256"}))
	if err != nil {
		t.Fatalf("principal case variant: %v", err)
	}
	if got := fx.fields(t, id)["keyFormat"]; got != "ECDSA P-256" {
		t.Fatalf("principal keyFormat stored %q, want ECDSA P-256", got)
	}
}

// An option list where two options differ only in case: the exact option
// wins, and a variant that could be either is refused.
func TestCaseVariantMatchingTwoOptionsIsRefused(t *testing.T) {
	fx := newSelectFixture(t)
	fx.s.types = append(fx.s.types, &vaultv1.SecretType{
		Id: "type-custom-tier", Name: "Tier", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM,
		Fields: []*vaultv1.SecretFieldDef{
			{Key: "tier", Label: "Tier", Kind: vaultv1.FieldKind_FIELD_KIND_SELECT, Options: []string{"gold", "GOLD", "Silver"}},
		},
	})
	if _, err := fx.create("type-custom-tier", map[string]string{"tier": "GOLD"}); err != nil {
		t.Fatalf("exact option: %v", err)
	}
	_, err := fx.create("type-custom-tier", map[string]string{"tier": "Gold"})
	wantSelectRefusal(t, err, ReasonFieldValueNotAllowed, "tier", []string{"gold", "GOLD", "Silver"})
}

func TestUpdateChecksSelectValues(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-database-account", dbFields(map[string]string{"engine": "PostgreSQL"}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	update := func(fields map[string]string) error {
		_, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{Actor: orgCarol, Id: id, Name: "renamed", Fields: fields})
		return err
	}
	wantSelectRefusal(t, update(map[string]string{"engine": "postgres"}), ReasonFieldValueNotAllowed, "engine", engineOptions)
	if got := fx.findName(id); got != "sel" {
		t.Fatalf("a refused update renamed the secret to %q", got)
	}
	if err := update(map[string]string{"engine": "mongodb"}); err != nil {
		t.Fatalf("case variant: %v", err)
	}
	if got := fx.fields(t, id)["engine"]; got != "MongoDB" {
		t.Fatalf("engine = %q, want MongoDB", got)
	}
	if err := update(map[string]string{"engine": ""}); err != nil {
		t.Fatalf("clearing an optional select: %v", err)
	}

	sid, err := fx.create("type-ssh-key", sshFields(map[string]string{"keyFormat": "Ed25519"}))
	if err != nil {
		t.Fatalf("create ssh: %v", err)
	}
	_, err = fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{Actor: orgCarol, Id: sid, Fields: map[string]string{"keyFormat": ""}})
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "keyFormat", keyFormatOptions)
	if got := fx.fields(t, sid)["keyFormat"]; got != "Ed25519" {
		t.Fatalf("keyFormat = %q after a refused clear, want Ed25519", got)
	}
}

func TestPrincipalUpdateChecksSelectValues(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-api-token", map[string]string{"token": "placeholder-token", "scheme": "Bearer"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	upd := func(fields map[string]string) error {
		_, err := fx.s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
			Actor: agentGroupActor("sa-1"), Id: id, Fields: fields,
		})
		return err
	}
	wantSelectRefusal(t, upd(map[string]string{"scheme": "Basic"}), ReasonFieldValueNotAllowed, "scheme", []string{"Bearer", "OAuth", "Custom header"})
	if err := upd(map[string]string{"scheme": "custom HEADER"}); err != nil {
		t.Fatalf("case variant: %v", err)
	}
	if got := fx.fields(t, id)["scheme"]; got != "Custom header" {
		t.Fatalf("scheme = %q, want Custom header", got)
	}
}

// storeRaw seals fields straight into a secret's record, standing in for a row
// written before the check existed.
func (fx selectFixture) storeRaw(t *testing.T, id string, fields map[string]string) {
	t.Helper()
	rec, err := fx.s.crypt.Seal(fields)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	fx.s.records[id] = rec
}

func (fx selectFixture) findName(id string) string { return fx.s.findSecret(id).GetName() }

func TestStoredValueOutsideTheOptionsReadsBackAndMustBeFixedOnSave(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-database-account", dbFields(map[string]string{"engine": "PostgreSQL", "notes": "n1"}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fx.storeRaw(t, id, dbFields(map[string]string{"engine": "postgres", "notes": "n1"}))

	if got := fx.fields(t, id)["engine"]; got != "postgres" {
		t.Fatalf("read back engine = %q, want the stored postgres", got)
	}
	// A machine change to another field leaves the stored value alone.
	if _, err := fx.s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Fields: map[string]string{"description": "d1"},
	}); err != nil {
		t.Fatalf("unrelated principal update: %v", err)
	}
	// The editor re-sends every field: saving the stored value is refused.
	resend := fx.fields(t, id)
	resend["notes"] = "n2"
	_, err = fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{Actor: orgCarol, Id: id, Fields: resend})
	wantSelectRefusal(t, err, ReasonFieldValueNotAllowed, "engine", engineOptions)
	if got := fx.fields(t, id)["notes"]; got != "n1" {
		t.Fatalf("notes = %q after a refused save, want n1", got)
	}
	resend["engine"] = "PostgreSQL"
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{Actor: orgCarol, Id: id, Fields: resend}); err != nil {
		t.Fatalf("save with a valid choice: %v", err)
	}
	got := fx.fields(t, id)
	if got["engine"] != "PostgreSQL" || got["notes"] != "n2" {
		t.Fatalf("after fix engine=%q notes=%q, want PostgreSQL/n2", got["engine"], got["notes"])
	}
}

func TestRetypeChecksSelectValues(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-password", map[string]string{"username": "app", "password": "Init1alP@ss-2026"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	retype := func(scheme string) error {
		_, err := fx.s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
			Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-api-token",
			FieldMapping: map[string]string{"password": "token", "username": "endpoint"},
			Fields:       map[string]string{"scheme": scheme},
		})
		return err
	}
	wantSelectRefusal(t, retype("Basic"), ReasonFieldValueNotAllowed, "scheme", []string{"Bearer", "OAuth", "Custom header"})
	if err := retype("oauth"); err != nil {
		t.Fatalf("retype with a case variant: %v", err)
	}
	if got := fx.fields(t, id)["scheme"]; got != "OAuth" {
		t.Fatalf("scheme = %q, want OAuth", got)
	}
}
