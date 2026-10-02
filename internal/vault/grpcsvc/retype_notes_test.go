// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// ChangeSecretTypeForPrincipal's default for a value with no field under
// the new type is to append it to the new type's notes field, never to drop it.
// Sensitive values never land in a non-sensitive notes field, an over-long
// result is refused (never truncated), fieldMapping always wins, and
// unmapped_fields=REFUSE restores the fail-closed behaviour.
//
// changing INTO a rotation/heartbeat type leaves rotation opted out
// until it is explicitly enabled; once it is, the connector's claim query
// picks the secret up.

func retypeSecret(t *testing.T, s *Server, folderID, typeID string, fields map[string]string) string {
	t.Helper()
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "retype", FolderId: folderID, TypeId: typeID, Fields: fields,
	})
	if err != nil {
		t.Fatalf("CreateSecret(%s): %v", typeID, err)
	}
	return c.GetSecret().GetId()
}

func authorFolder(t *testing.T, s *Server) string {
	t.Helper()
	f := mutFolder(t, s, "F")
	grantGroup(t, s, orgCarol, f, "R")
	return f
}

func TestChangeSecretType_UnmappedValuesMoveIntoNotesByDefault(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	id := retypeSecret(t, s, f, "type-web-password", map[string]string{
		"description": "line1\nline2 \"quoted\" <b>", "url": "https://example.test/login",
		"username": mutUser, "password": mutPass, "notes": mutNote,
	})
	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
	})
	if err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	if got := strings.Join(resp.GetMovedToNotesKeys(), ","); got != "description,url" || resp.GetNotesFieldKey() != "notes" {
		t.Fatalf("moved keys = %q into %q", got, resp.GetNotesFieldKey())
	}
	got := openFields(t, s, id)
	want := mutNote + "\n\n" +
		`[moved from description]: "line1\nline2 \"quoted\" <b>"` + "\n" +
		`[moved from url]: "https://example.test/login"`
	if got["notes"] != want {
		t.Fatalf("notes =\n%s\nwant\n%s", got["notes"], want)
	}
	if got["password"] != mutPass || got["username"] != mutUser {
		t.Fatal("mapped fields must carry over unchanged")
	}
	ev := ca.find("secret.type_change.principal")
	if ev == nil || ev.Attributes["moved_to_notes_keys"] != "description,url" {
		t.Fatalf("audit = %+v", ev)
	}
	for _, v := range ev.Attributes {
		if strings.Contains(v, "example.test") || strings.Contains(v, mutPass) {
			t.Fatal("audit leaks a value")
		}
	}
}

func TestChangeSecretType_NotesFormatWithEmptyNotesAndExplicitNotesField(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	id := retypeSecret(t, s, f, "type-web-password", map[string]string{
		"url": "https://a.test", "username": "u", "password": "p",
	})
	if _, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
		Fields: map[string]string{"notes": "given by the agent"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := openFields(t, s, id)["notes"]; got != "given by the agent\n\n[moved from url]: \"https://a.test\"" {
		t.Fatalf("notes = %q", got)
	}
	id2 := retypeSecret(t, s, f, "type-web-password", map[string]string{"url": "https://b.test", "username": "u", "password": "p"})
	if _, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id2, NewTypeId: "type-password",
	}); err != nil {
		t.Fatal(err)
	}
	if got := openFields(t, s, id2)["notes"]; got != `[moved from url]: "https://b.test"` {
		t.Fatalf("notes with nothing before = %q", got)
	}
}

func TestChangeSecretType_FieldMappingWinsOverNotes(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	id := retypeSecret(t, s, f, "type-web-password", map[string]string{"url": "https://a.test", "username": "u", "password": "p"})
	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-unix-ssh",
		FieldMapping: map[string]string{"url": "host"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetMovedToNotesKeys()) != 0 || openFields(t, s, id)["host"] != "https://a.test" {
		t.Fatalf("mapping must win: moved=%v", resp.GetMovedToNotesKeys())
	}
	if _, ok := openFields(t, s, id)["notes"]; ok {
		t.Fatal("nothing should be written to notes")
	}
}

// type-secure-note's "note" is the only notes field there, and it is
// sensitive: a sensitive leftover may go there, a super-sensitive one may not.
func TestChangeSecretType_SensitiveLeftoversOnlyIntoSensitiveNotes(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-super", Name: "Super", Fields: []*vaultv1.SecretFieldDef{
		{Key: "pin", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true, SuperSensitive: true},
		{Key: "token", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true},
		{Key: "label", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
	}})
	cases := []struct {
		name     string
		fields   map[string]string
		newType  string
		mapping  map[string]string
		extra    map[string]string
		wantCode codes.Code
		wantKeys string // keys named in the error / moved
	}{
		{"sensitive leftover into non-sensitive notes is refused", map[string]string{"token": "TOK-VALUE", "label": "L"},
			"type-password", map[string]string{"label": "username"}, map[string]string{"password": "p"}, codes.FailedPrecondition, "token"},
		{"super-sensitive leftover into sensitive (not super) note is refused", map[string]string{"pin": "PIN-VALUE", "label": "L"},
			"type-secure-note", map[string]string{"label": "description"}, map[string]string{"note": "n"}, codes.FailedPrecondition, "pin"},
		{"sensitive leftover into sensitive note is allowed", map[string]string{"token": "TOK-VALUE", "label": "L"},
			"type-secure-note", map[string]string{"label": "description"}, nil, codes.OK, "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := retypeSecret(t, s, f, "type-org-super", tc.fields)
			resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: tc.newType, FieldMapping: tc.mapping, Fields: tc.extra,
			})
			if tc.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("want allowed: %v", err)
				}
				if strings.Join(resp.GetMovedToNotesKeys(), ",") != tc.wantKeys || resp.GetNotesFieldKey() != "note" {
					t.Fatalf("moved = %v into %q", resp.GetMovedToNotesKeys(), resp.GetNotesFieldKey())
				}
				if got := openFields(t, s, id)["note"]; got != `[moved from token]: "TOK-VALUE"` {
					t.Fatalf("note = %q", got)
				}
				return
			}
			wantCode(t, err, tc.wantCode)
			if !strings.Contains(err.Error(), tc.wantKeys) {
				t.Fatalf("error must name %q: %v", tc.wantKeys, err)
			}
			if strings.Contains(err.Error(), "VALUE") {
				t.Fatalf("error leaks a value: %v", err)
			}
			if s.findSecret(id).GetTypeId() != "type-org-super" {
				t.Fatal("refused change must not touch the secret")
			}
		})
	}
}

func TestChangeSecretType_NotesRefusals(t *testing.T) {
	s := newServer(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-short-notes", Name: "Short", Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE, MaxLength: 30},
	}})
	addType(s, &vaultv1.SecretType{Id: "type-org-no-notes", Name: "NoNotes", Fields: []*vaultv1.SecretFieldDef{
		{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
	}})
	cases := map[string]struct {
		newType string
		policy  vaultv1.UnmappedFieldPolicy
	}{
		"would exceed the notes max length (never truncated)": {"type-org-short-notes", vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_NOTES},
		"new type has no notes field":                         {"type-org-no-notes", vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_UNSPECIFIED},
		"explicit REFUSE":                                     {"type-org-short-notes", vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			id := retypeSecret(t, s, f, "type-web-password", map[string]string{"url": "https://a-long-url.example.test/path", "username": "u"})
			before := s.records[id]
			_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: tc.newType, UnmappedFields: tc.policy,
			})
			wantCode(t, err, codes.FailedPrecondition)
			if !strings.Contains(err.Error(), "url") || strings.Contains(err.Error(), "example.test") {
				t.Fatalf("error must name the key only: %v", err)
			}
			if s.findSecret(id).GetTypeId() != "type-web-password" || !reflect.DeepEqual(s.records[id], before) {
				t.Fatal("refused change must not touch the secret")
			}
		})
	}
}

// With real Postgres 17: a machine converting a generic password into
// an Active Directory account gets a heartbeat (it has a target) but no
// rotation until rotation is enabled; after that the connector's claim query
// picks it up once due, and the change is audited as the principal.
func TestChangeSecretType_IntoRotationTypeIsScheduled_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.SetHeartbeat(pool, nil)
	s.SetRotation(pool, nil)
	f := authorFolder(t, s)
	id := mutSecret(t, s, f)
	tgt, _ := reachableTarget(t, s)
	if _, err := s.SetSecretTargetForPrincipal(ctx, &vaultv1.SetSecretTargetForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id, TargetId: tgt,
	}); err != nil {
		t.Fatalf("attach target: %v", err)
	}
	if ok, _ := s.rot.Exists(ctx, id); ok {
		t.Fatal("a plain password must not be rotation-scheduled")
	}

	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-active-directory",
		Fields: map[string]string{"domain": "corp.example.test"},
	}); err != nil {
		t.Fatalf("into active-directory: %v", err)
	}
	if ok, _ := s.rot.Exists(ctx, id); ok {
		t.Fatal("rotation must stay off after the retype until it is enabled")
	}
	if _, err := s.SetSecretAutomationForPrincipal(ctx, &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id,
	}); err != nil {
		t.Fatalf("enable rotation: %v", err)
	}
	if ok, err := s.rot.Exists(ctx, id); err != nil || !ok {
		t.Fatalf("rotation_schedule row missing after enabling rotation: ok=%v err=%v", ok, err)
	}
	var days int
	if err := pool.Querier().QueryRow(ctx, `SELECT interval_days FROM rotation_schedule WHERE secret_id=$1`, id).Scan(&days); err != nil || days != 90 {
		t.Fatalf("interval_days = %d (err=%v), want the default policy's 90", days, err)
	}
	var hb int
	if err := pool.Querier().QueryRow(ctx, `SELECT count(*) FROM heartbeat_schedule WHERE secret_id=$1`, id).Scan(&hb); err != nil || hb != 1 {
		t.Fatalf("heartbeat_schedule rows = %d (err=%v), want 1", hb, err)
	}
	if _, err := pool.Querier().Exec(ctx, `UPDATE rotation_schedule SET next_rotation_at = now() - interval '1 minute' WHERE secret_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.rot.ClaimDue(ctx, 10, 60e9)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	found := false
	for _, c := range claimed {
		found = found || c == id
	}
	if !found {
		t.Fatalf("connector claim did not pick up the retyped secret: %v", claimed)
	}
	ev := ca.find("secret.type_change.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["to_type_id"] != "type-active-directory" || ev.Attributes["rotation_managed"] != "true" {
		t.Fatalf("audit = %+v", ev)
	}
}
