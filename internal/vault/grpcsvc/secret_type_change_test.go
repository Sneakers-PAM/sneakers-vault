// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
)

// A person's type change shares the machine path's rules; the only difference
// is that a person may drop checkout from a plain checkout type. The preview
// runs the same rules, writes nothing and returns keys only.

var (
	personDave = &vaultv1.ActorContext{UserId: "user-dave", GroupNames: []string{"g-agents"}}
	sshHost    = map[string]string{"host": "host.example.test"}
)

func checkoutOnlyType(t *testing.T, s *Server) string {
	t.Helper()
	const id = "type-org-checked-out"
	addType(s, &vaultv1.SecretType{Id: id, Name: "Checked-out password", Checkout: true, Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
	}})
	return id
}

func errorMetadata(t *testing.T, err error) map[string]string {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetMetadata()
		}
	}
	t.Fatalf("no ErrorInfo on %v", err)
	return nil
}

func previewField(t *testing.T, resp *vaultv1.PreviewSecretTypeChangeResponse, from string) *vaultv1.SecretTypeChangeField {
	t.Helper()
	for _, c := range resp.GetFieldChanges() {
		if c.GetFromKey() == from {
			return c
		}
	}
	t.Fatalf("no field change for %q in %v", from, resp.GetFieldChanges())
	return nil
}

func TestChangeSecretType_PersonPasswordToPasswordAccountSSH(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	id := mutSecret(t, s, f)

	resp, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost,
	})
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	if resp.GetSecret().GetTypeId() != "type-unix-ssh" {
		t.Fatalf("type = %q", resp.GetSecret().GetTypeId())
	}
	got := openFields(t, s, id)
	if got["username"] != mutUser || got["password"] != mutPass || got["notes"] != mutNote {
		t.Fatalf("values not carried: keys %v", keysOf(got))
	}
	if strings.Join(resp.GetFieldKeys(), ",") != "host,notes,password,username" {
		t.Fatalf("field_keys = %v", resp.GetFieldKeys())
	}
	ev := ca.find("secret.type_change")
	if ev == nil {
		t.Fatal("expected a secret.type_change audit event")
	}
	if ca.find("secret.type_change.principal") != nil {
		t.Fatal("a person's change must not audit as a principal")
	}
	if !ev.Sensitive || ev.ActorUserID != "user-dave" || ev.Attributes["from_type_id"] != "type-password" ||
		ev.Attributes["to_type_id"] != "type-unix-ssh" || ev.Attributes["field_keys"] != "host,notes,password,username" {
		t.Fatalf("audit event wrong: %+v", ev)
	}
	if ev.Attributes["change_label"] == "" || ev.Attributes["change_label"] != resp.GetChangeLabel() {
		t.Fatalf("change_label: audit %q, response %q", ev.Attributes["change_label"], resp.GetChangeLabel())
	}
	if _, ok := ev.Attributes["principal_kind"]; ok {
		t.Fatal("a person's event carries no principal attributes")
	}
	for k, v := range ev.Attributes {
		for _, secret := range []string{mutUser, mutPass, mutNote} {
			if strings.Contains(v, secret) {
				t.Fatalf("audit attribute %s leaks a value", k)
			}
		}
	}
}

func TestChangeSecretType_LabelMatchesTheMachinePath(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	person := mutSecret(t, s, f)
	machine := mutSecret(t, s, f)
	mapping, extra := map[string]string{"username": "account"}, map[string]string{"url": "https://example.test"}
	addType(s, &vaultv1.SecretType{Id: "type-org-web", Name: "Web", Fields: []*vaultv1.SecretFieldDef{
		{Key: "account", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "url", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
	}})
	a, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{
		Actor: personDave, Id: person, NewTypeId: "type-org-web", FieldMapping: mapping, Fields: extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: machine, NewTypeId: "type-org-web", FieldMapping: mapping, Fields: extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.GetChangeLabel() != b.GetChangeLabel() {
		t.Fatalf("labels differ:\n%s\n%s", a.GetChangeLabel(), b.GetChangeLabel())
	}
}

func TestChangeSecretType_RefusalsCarryReasons(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-plain", Name: "Plain", Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
	}})
	addType(s, &vaultv1.SecretType{Id: "type-org-bare", Name: "Bare", Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
	}})
	addType(s, &vaultv1.SecretType{Id: "type-org-tiny", Name: "Tiny", Fields: []*vaultv1.SecretFieldDef{
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE, MaxLength: 5},
	}})
	addType(s, &vaultv1.SecretType{Id: "type-org-needs", Name: "Needs", Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		{Key: "domain", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
	}})
	cases := []struct {
		name     string
		newType  string
		mapping  map[string]string
		extra    map[string]string
		policy   vaultv1.UnmappedFieldPolicy
		wantCode codes.Code
		reason   string
		field    string
	}{
		{name: "down-classify", newType: "type-org-plain", wantCode: codes.FailedPrecondition, reason: ReasonTypeChangeLowersProtection, field: "password"},
		{name: "no notes field", newType: "type-org-bare", wantCode: codes.FailedPrecondition, reason: ReasonTypeChangeUnmappedFields, field: "notes"},
		{name: "refuse policy", newType: "type-org-tiny", policy: vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE, wantCode: codes.FailedPrecondition, reason: ReasonTypeChangeUnmappedFields, field: "username"},
		{name: "notes overflow", newType: "type-org-tiny", wantCode: codes.FailedPrecondition, reason: ReasonTypeChangeNotesTooLong, field: "username"},
		{name: "two sources one field", newType: "type-unix-ssh", mapping: map[string]string{"username": "password"}, wantCode: codes.InvalidArgument, reason: ReasonTypeChangeInvalidField, field: "password"},
		{name: "unknown mapping target", newType: "type-unix-ssh", mapping: map[string]string{"username": "nope"}, wantCode: codes.InvalidArgument, reason: ReasonTypeChangeInvalidField, field: "username"},
		{name: "required missing", newType: "type-org-needs", wantCode: codes.InvalidArgument, reason: ReasonFieldValueRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := mutSecret(t, s, f)
			_, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{
				Actor: personDave, Id: id, NewTypeId: tc.newType, FieldMapping: tc.mapping, Fields: tc.extra, UnmappedFields: tc.policy,
			})
			wantReason(t, err, tc.wantCode, tc.reason, tc.name)
			if tc.field != "" && !strings.Contains(errorMetadata(t, err)["fields"], tc.field) {
				t.Fatalf("metadata %v must name %q", errorMetadata(t, err), tc.field)
			}
			if strings.Contains(err.Error(), mutPass) || strings.Contains(err.Error(), mutUser) {
				t.Fatalf("error leaks a value: %v", err)
			}
			if s.findSecret(id).GetTypeId() != "type-password" {
				t.Fatal("a refused change must not touch the secret")
			}
			// The machine path shares the code, so it refuses alike.
			_, err = s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: tc.newType, FieldMapping: tc.mapping, Fields: tc.extra, UnmappedFields: tc.policy,
			})
			wantReason(t, err, tc.wantCode, tc.reason, tc.name+" (machine)")
			// And the preview reports it instead of failing.
			p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{
				Actor: personDave, Id: id, NewTypeId: tc.newType, FieldMapping: tc.mapping, Fields: tc.extra, UnmappedFields: tc.policy,
			})
			if err != nil {
				t.Fatalf("preview: %v", err)
			}
			if p.GetAllowed() || p.GetRefusalReason() != tc.reason || p.GetRefusalMessage() == "" {
				t.Fatalf("preview = %v, want refusal %s", p, tc.reason)
			}
		})
	}
}

func TestChangeSecretType_PersonMayDropCheckout(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	ct := checkoutOnlyType(t, s)
	id := retypeSecret(t, s, f, ct, map[string]string{"username": mutUser, "password": mutPass})

	_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
	})
	wantReason(t, err, codes.FailedPrecondition, ReasonTypeChangeCheckoutHumanOnly, "machine drops checkout")

	p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-password",
	})
	if err != nil || !p.GetAllowed() {
		t.Fatalf("preview for a person must allow it: %v %v", p, err)
	}
	if _, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-password",
	}); err != nil {
		t.Fatalf("a person may drop checkout: %v", err)
	}
	if s.findSecret(id).GetTypeId() != "type-password" || ca.find("secret.type_change") == nil {
		t.Fatal("type must change and be audited")
	}
}

func TestChangeSecretType_PersonDenials(t *testing.T) {
	cases := []struct {
		name  string
		actor *vaultv1.ActorContext
	}{
		{"no rights", &vaultv1.ActorContext{UserId: "user-nobody"}},
		{"no user", &vaultv1.ActorContext{}},
		{"service account", agentGroupActor("sa-1")},
		{"workload claiming admin", &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-evil",
			UserId: "user-carol", IsSiteAdmin: true, IsRoot: true,
		}},
		{"owner's personal token", &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, PrincipalId: "tok-1", UserId: "user-carol",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			f := authorFolder(t, s)
			id := mutSecret(t, s, f)
			_, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{Actor: tc.actor, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
			wantCode(t, err, codes.PermissionDenied)
			_, err = s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{Actor: tc.actor, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
			wantCode(t, err, codes.PermissionDenied)
			if s.findSecret(id).GetTypeId() != "type-password" || ca.find("secret.type_change") != nil {
				t.Fatal("a denied change must not change or audit anything")
			}
		})
	}
}

func TestChangeSecretType_PerSecretDenyHoldsButFolderOwnerPasses(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	id := mutSecret(t, s, f)
	denySecretAuthor(t, s, id)

	_, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
	wantCode(t, err, codes.PermissionDenied)
	if _, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{Actor: orgCarol, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost}); err != nil {
		t.Fatalf("the folder's owner may: %v", err)
	}
}

func TestChangeSecretType_PersonInputChecks(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	id := mutSecret(t, s, f)
	ctx := context.Background()

	_, err := s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id})
	wantCode(t, err, codes.InvalidArgument)
	_, err = s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: "nope", NewTypeId: "type-unix-ssh", Fields: sshHost})
	wantCode(t, err, codes.NotFound)
	_, err = s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-nope"})
	wantCode(t, err, codes.NotFound)
	_, err = s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"})
	wantCode(t, err, codes.InvalidArgument)
	_, err = s.PreviewSecretTypeChange(ctx, &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"})
	wantCode(t, err, codes.InvalidArgument)

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: orgCarol, Id: id}); err != nil {
		t.Fatal(err)
	}
	_, err = s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
	wantReason(t, err, codes.FailedPrecondition, ReasonRetired, "retired")
	_, err = s.PreviewSecretTypeChange(ctx, &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
	wantReason(t, err, codes.FailedPrecondition, ReasonRetired, "retired preview")
}

func TestPreviewSecretTypeChange_SaysWhereEachFieldGoesWithoutWriting(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-old", Name: "Old", Fields: []*vaultv1.SecretFieldDef{
		{Key: "login", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "site", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
	}})
	id := retypeSecret(t, s, f, "type-org-old", map[string]string{"login": mutUser, "password": mutPass, "site": "https://example.test", "notes": mutNote})
	before := s.findSecret(id).GetValueVersion()
	beforeRec := s.records[id]
	events := len(ca.events)

	req := &vaultv1.PreviewSecretTypeChangeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", FieldMapping: map[string]string{"login": "username"}, Fields: sshHost,
	}
	p, err := s.PreviewSecretTypeChange(context.Background(), req)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !p.GetAllowed() || p.GetRefusalReason() != "" {
		t.Fatalf("preview must allow it: %v", p)
	}
	want := map[string]struct {
		to      string
		outcome vaultv1.SecretTypeChangeFieldOutcome
	}{
		"login":    {"username", vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_RENAMED},
		"password": {"password", vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_CARRIED},
		"notes":    {"notes", vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_CARRIED},
		"site":     {"notes", vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_MOVED_TO_NOTES},
	}
	if len(p.GetFieldChanges()) != len(want) {
		t.Fatalf("field_changes = %v", p.GetFieldChanges())
	}
	for from, w := range want {
		c := previewField(t, p, from)
		if c.GetToKey() != w.to || c.GetOutcome() != w.outcome {
			t.Fatalf("%s: %v, want %v", from, c, w)
		}
	}
	if p.GetNotesFieldKey() != "notes" {
		t.Fatalf("notes_field_key = %q", p.GetNotesFieldKey())
	}
	text := prototext.Format(p)
	for _, secret := range []string{mutUser, mutPass, mutNote, "https://example.test"} {
		if strings.Contains(text, secret) {
			t.Fatalf("preview leaks a value: %s", text)
		}
	}
	sec := s.findSecret(id)
	if sec.GetTypeId() != "type-org-old" || sec.GetValueVersion() != before || len(ca.events) != events {
		t.Fatal("a preview must write nothing")
	}
	if !reflect.DeepEqual(s.records[id], beforeRec) {
		t.Fatal("a preview must not re-seal the record")
	}

	done, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", FieldMapping: req.GetFieldMapping(), Fields: sshHost,
	})
	if err != nil {
		t.Fatalf("the change a preview allowed must succeed: %v", err)
	}
	if done.GetChangeLabel() != p.GetChangeLabel() || strings.Join(done.GetFieldKeys(), ",") != strings.Join(p.GetFieldKeys(), ",") {
		t.Fatalf("preview and change disagree: %q / %q, %v / %v", p.GetChangeLabel(), done.GetChangeLabel(), p.GetFieldKeys(), done.GetFieldKeys())
	}
}

func TestPreviewSecretTypeChange_ReportsFieldsThatCannotMove(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-src", Name: "Src", Fields: []*vaultv1.SecretFieldDef{
		{Key: "token", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true},
		{Key: "site", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
	}})
	addType(s, &vaultv1.SecretType{Id: "type-org-open", Name: "Open", Fields: []*vaultv1.SecretFieldDef{
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		{Key: "domain", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
	}})
	id := retypeSecret(t, s, f, "type-org-src", map[string]string{"token": "TOK-VALUE", "site": "s", "password": mutPass})
	blocked := vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_BLOCKED

	p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-org-open"})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.GetAllowed() || p.GetRefusalReason() != ReasonTypeChangeLowersProtection {
		t.Fatalf("preview = %v", p)
	}
	if c := previewField(t, p, "token"); c.GetOutcome() != blocked || c.GetReason() != ReasonTypeChangeLowersProtection || c.GetToKey() != "" {
		t.Fatalf("token: %v", c)
	}
	if c := previewField(t, p, "password"); c.GetOutcome() != blocked || c.GetReason() != ReasonTypeChangeLowersProtection || c.GetToKey() != "password" {
		t.Fatalf("password: %v", c)
	}
	if c := previewField(t, p, "site"); c.GetOutcome() != vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_MOVED_TO_NOTES {
		t.Fatalf("site: %v", c)
	}
	if strings.Join(p.GetMissingRequiredKeys(), ",") != "domain" {
		t.Fatalf("missing_required_keys = %v", p.GetMissingRequiredKeys())
	}
	if len(p.GetFieldKeys()) != 0 || p.GetChangeLabel() != "" {
		t.Fatalf("a refused preview has no result: %v", p)
	}
	if strings.Contains(prototext.Format(p), "TOK-VALUE") {
		t.Fatal("preview leaks a value")
	}

	p, err = s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{
		Actor: personDave, Id: id, NewTypeId: "type-org-open", UnmappedFields: vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE,
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.GetRefusalReason() != ReasonTypeChangeUnmappedFields || !strings.Contains(p.GetRefusalMessage(), "site") {
		t.Fatalf("REFUSE preview = %v", p)
	}
	if c := previewField(t, p, "site"); c.GetOutcome() != blocked || c.GetReason() != ReasonTypeChangeUnmappedFields || c.GetToKey() != "" {
		t.Fatalf("site under REFUSE: %v", c)
	}
}

func TestPreviewSecretTypeChange_NotesOverflowBlocksEveryLeftover(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-tiny", Name: "Tiny", Fields: []*vaultv1.SecretFieldDef{
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE, MaxLength: 5},
	}})
	id := retypeSecret(t, s, f, "type-password", map[string]string{"username": mutUser, "password": mutPass})
	p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-org-tiny"})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.GetRefusalReason() != ReasonTypeChangeNotesTooLong {
		t.Fatalf("preview = %v", p)
	}
	if c := previewField(t, p, "username"); c.GetOutcome() != vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_BLOCKED || c.GetReason() != ReasonTypeChangeNotesTooLong {
		t.Fatalf("username: %v", c)
	}
}

func TestPreviewSecretTypeChange_AutomationMatchesTheChange(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	id := retypeSecret(t, s, f, "type-active-directory", map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass})
	attachTarget(t, s, id, tgt)

	for _, tc := range []struct {
		name    string
		newType string
		extra   map[string]string
		target  string
	}{
		{"into a type with no target", "type-password", nil, "detached"},
		{"into a rotation type keeps the target", "type-windows-domain", nil, "kept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{
				Actor: personDave, Id: id, NewTypeId: tc.newType, Fields: tc.extra,
			})
			if err != nil || !p.GetAllowed() {
				t.Fatalf("preview: %v %v", p, err)
			}
			if p.GetTarget() != tc.target || p.GetFromTargetId() != tgt {
				t.Fatalf("preview target = %q from %q", p.GetTarget(), p.GetFromTargetId())
			}
			if s.findSecret(id).GetTargetId() != tgt {
				t.Fatal("a preview must not detach the target")
			}
		})
	}

	p, err := s.PreviewSecretTypeChange(context.Background(), &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"}); err != nil {
		t.Fatal(err)
	}
	ev := ca.find("secret.type_change")
	if ev == nil {
		t.Fatal("no audit event")
	}
	if ev.Attributes["rotation"] != p.GetRotation() || ev.Attributes["heartbeat"] != p.GetHeartbeat() ||
		ev.Attributes["target"] != p.GetTarget() || ev.Attributes["from_target_id"] != p.GetFromTargetId() || ev.Attributes["target_id"] != p.GetTargetId() {
		t.Fatalf("preview %v disagrees with audit %v", p, ev.Attributes)
	}
}

// A detach clears the whole list, not just the legacy target_id alias.
func TestChangeSecretType_DetachClearsTheTargetList(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	id := retypeSecret(t, s, f, "type-active-directory", map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass})
	attachTarget(t, s, id, tgt)

	if _, err := s.ChangeSecretType(context.Background(), &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"}); err != nil {
		t.Fatal(err)
	}
	if sec := s.findSecret(id); sec.GetTargetId() != "" || len(sec.GetTargetIds()) != 0 {
		t.Fatalf("target_id=%q target_ids=%v", sec.GetTargetId(), sec.GetTargetIds())
	}
}

func TestChangeSecretType_RefusedWhileARotationIsInFlightForAPerson_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	c, err := fx.s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "ad", FolderId: fx.folder, TypeId: "type-active-directory", TargetId: fx.target,
		Fields: map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	id := c.GetSecret().GetId()
	if _, err := fx.pool.Querier().Exec(ctx, `UPDATE rotation_schedule SET claimed_until = now() + interval '5 minutes' WHERE secret_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	_, err = fx.s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"})
	wantReason(t, err, codes.FailedPrecondition, ReasonRotationInProgress, "rotation in flight")
	p, err := fx.s.PreviewSecretTypeChange(ctx, &vaultv1.PreviewSecretTypeChangeRequest{Actor: personDave, Id: id, NewTypeId: "type-password"})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.GetAllowed() || p.GetRefusalReason() != ReasonRotationInProgress || len(p.GetFieldChanges()) == 0 {
		t.Fatalf("preview = %v", p)
	}
	if fx.s.findSecret(id).GetTypeId() != "type-active-directory" || fx.rows(t, "rotation_schedule", id) != 1 {
		t.Fatal("a refused type change must leave the secret and its schedule untouched")
	}
}

func TestChangeSecretType_WritesAVersionWithTheLabel_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	id := mutSecret(t, fx.s, fx.folder)

	resp, err := fx.s.ChangeSecretType(ctx, &vaultv1.ChangeSecretTypeRequest{Actor: personDave, Id: id, NewTypeId: "type-unix-ssh", Fields: sshHost})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := fx.s.vers.List(ctx, id, fx.s.crypt)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range metas {
		if m.Active && m.ChangeLabel == resp.GetChangeLabel() && m.CreatedBy == "user-dave" {
			return
		}
	}
	t.Fatalf("no active version by user-dave labelled %q: %+v", resp.GetChangeLabel(), metas)
}
