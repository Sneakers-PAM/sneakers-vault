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

// MoveSecretForPrincipal / ChangeSecretTypeForPrincipal. Same authz as the
// human edit/move path (RACI Author via canManage, never an admin flag for a
// machine), non-human principals only, audited as the principal, and the
// type change never silently drops or down-classifies a stored value.

const (
	mutUser = "svc-user"
	mutPass = "Sup3r$ecretValue-9"
	mutNote = "rack 4, shelf 2"
)

// mutFolder creates a top-level shared folder owned by carol and returns its id.
func mutFolder(t *testing.T, s *Server, name string) string {
	t.Helper()
	f, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: name,
	})
	if err != nil {
		t.Fatalf("CreateFolder(%s): %v", name, err)
	}
	return f.GetFolder().GetId()
}

// mutSecret creates a type-password secret (username/password/notes) as carol.
func mutSecret(t *testing.T, s *Server, folderID string) string {
	t.Helper()
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "svc", FolderId: folderID, TypeId: "type-password",
		Fields: map[string]string{"username": mutUser, "password": mutPass, "notes": mutNote},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return c.GetSecret().GetId()
}

// assertNoValueLeak fails if an error message carries any stored value.
func assertNoValueLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, v := range []string{mutUser, mutPass, mutNote} {
		if strings.Contains(err.Error(), v) {
			t.Fatalf("error leaks a stored value: %v", err)
		}
	}
}

func openFields(t *testing.T, s *Server, id string) map[string]string {
	t.Helper()
	m, err := s.crypt.OpenAll(s.records[id])
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	return m
}

// ---- MoveSecretForPrincipal --------------------------------------------------

func TestMoveSecretForPrincipal_AuthorOnSourceAndDestAllowed(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	src, dst := mutFolder(t, s, "Src"), mutFolder(t, s, "Dst")
	grantGroup(t, s, carol, src, "R")
	grantGroup(t, s, carol, dst, "R")
	id := mutSecret(t, s, src)
	recBefore := s.records[id]

	resp, err := s.MoveSecretForPrincipal(context.Background(), &vaultv1.MoveSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, DestFolderId: dst,
	})
	if err != nil {
		t.Fatalf("MoveSecretForPrincipal: %v", err)
	}
	if resp.GetSecret().GetId() != id || s.findSecret(id).GetFolderId() != dst {
		t.Fatalf("secret not moved in place: resp=%v folder=%q", resp.GetSecret(), s.findSecret(id).GetFolderId())
	}
	if !reflect.DeepEqual(s.records[id], recBefore) {
		t.Fatal("move must keep the sealed record (no destroy+recreate)")
	}
	ev := ca.find("secret.move.principal")
	if ev == nil {
		t.Fatal("expected a secret.move.principal audit event")
	}
	if ev.ActorUserID != "sa-1" || ev.Attributes["principal_id"] != "sa-1" ||
		ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" {
		t.Fatalf("audit not attributed to the service account: %+v", ev)
	}
	if ev.Attributes["from_folder_id"] != src || ev.Attributes["to_folder_id"] != dst {
		t.Fatalf("audit from/to = %q/%q, want %q/%q", ev.Attributes["from_folder_id"], ev.Attributes["to_folder_id"], src, dst)
	}
}

func TestMoveSecretForPrincipal_Denials(t *testing.T) {
	cases := []struct {
		name      string
		srcGrant  string // "" = no rule for g-agents
		dstGrant  string
		actor     *vaultv1.ActorContext
		secretDen bool // per-secret ruleset denies Author
	}{
		{name: "no rights on source", dstGrant: "R", actor: agentGroupActor("sa-1")},
		{name: "no rights on destination", srcGrant: "R", actor: agentGroupActor("sa-1")},
		{name: "read-only on both (cross-folder with only Read)", srcGrant: "C", dstGrant: "C", actor: agentGroupActor("sa-1")},
		{name: "author on source, read-only on destination", srcGrant: "R", dstGrant: "C", actor: agentGroupActor("sa-1")},
		{name: "read-only on source, author on destination", srcGrant: "C", dstGrant: "R", actor: agentGroupActor("sa-1")},
		{name: "per-secret deny overrides folder author", srcGrant: "R", dstGrant: "R", actor: agentGroupActor("sa-1"), secretDen: true},
		{name: "human caller (even site-admin) is rejected", srcGrant: "R", dstGrant: "R",
			actor: &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true, IsRoot: true}},
		{name: "service account with spoofed admin flags and no grants", actor: &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-evil",
			UserId: "user-carol", IsSiteAdmin: true, IsRoot: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			carol := &vaultv1.ActorContext{UserId: "user-carol"}
			src, dst := mutFolder(t, s, "Src"), mutFolder(t, s, "Dst")
			if tc.srcGrant != "" {
				grantGroup(t, s, carol, src, tc.srcGrant)
			}
			if tc.dstGrant != "" {
				grantGroup(t, s, carol, dst, tc.dstGrant)
			}
			id := mutSecret(t, s, src)
			if tc.secretDen {
				if _, err := s.SetSecretRuleset(context.Background(), &vaultv1.SetSecretRulesetRequest{
					Actor: carol, SecretId: id, Rules: []*vaultv1.RaciRule{{
						SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents",
						Grants: map[string]string{"R": "deny"},
					}},
				}); err != nil {
					t.Fatalf("SetSecretRuleset: %v", err)
				}
			}
			_, err := s.MoveSecretForPrincipal(context.Background(), &vaultv1.MoveSecretForPrincipalRequest{
				Actor: tc.actor, Id: id, DestFolderId: dst,
			})
			if code(err) != codes.PermissionDenied {
				t.Fatalf("want PermissionDenied, got %v", err)
			}
			if got := s.findSecret(id).GetFolderId(); got != src {
				t.Fatalf("denied move changed folder to %q", got)
			}
			if ca.find("secret.move.principal") != nil {
				t.Fatal("denied move must not emit secret.move.principal")
			}
		})
	}
}

// A move that demotes a shared secret into a personal folder needs a
// site-admin approval, for a machine as for a human. Once every RACI check has
// passed the vault moves nothing and signals approval_required (audited as the
// principal); the gateway files the approval request.
func TestMoveSecretForPrincipal_IntoPersonalNeedsApproval(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	seedPersonalFolder(s, "user-carol")
	src := mutFolder(t, s, "Src")
	grantGroup(t, s, carol, src, "R")
	grantGroup(t, s, carol, "folder-personal-carol", "R")
	id := mutSecret(t, s, src)
	resp, err := s.MoveSecretForPrincipal(context.Background(), &vaultv1.MoveSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, DestFolderId: "folder-personal-carol",
	})
	if err != nil {
		t.Fatalf("shared->personal by a machine: want approval_required, got %v", err)
	}
	if !resp.GetApprovalRequired() {
		t.Fatal("approval_required must be set")
	}
	if s.findSecret(id).GetFolderId() != src || resp.GetSecret().GetFolderId() != src {
		t.Fatal("an approval-required move must not move the secret")
	}
	if d := resp.GetDestination(); d.GetId() != "folder-personal-carol" || d.GetOwnerUserId() != "" || len(d.GetOwners()) != 0 {
		t.Fatalf("destination view = %+v", d)
	}
	ev := ca.find("secret.move.approval_required.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["to_folder_id"] != "folder-personal-carol" || ev.Attributes["from_folder_id"] != src {
		t.Fatalf("approval audit = %+v", ev)
	}
	if ca.find("secret.move.principal") != nil {
		t.Fatal("no move may be audited when approval is required")
	}
}

// The approval route is only offered after every RACI check: no Author on the
// personal destination (or only an everyone rule there) is a plain denial.
func TestMoveSecretForPrincipal_IntoPersonalWithoutGrantDenied(t *testing.T) {
	for name, grant := range map[string]func(s *Server){
		"no grant":              func(*Server) {},
		"only an everyone rule": func(s *Server) { injectEveryoneRule(s, "folder-personal-carol", map[string]string{"R": "allow"}) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			seedPersonalFolder(s, "user-carol")
			grant(s)
			src := mutFolder(t, s, "Src")
			grantGroup(t, s, orgCarol, src, "R")
			id := mutSecret(t, s, src)
			resp, err := s.MoveSecretForPrincipal(context.Background(), &vaultv1.MoveSecretForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, DestFolderId: "folder-personal-carol",
			})
			if code(err) != codes.PermissionDenied || resp.GetApprovalRequired() {
				t.Fatalf("want PermissionDenied without approval, got resp=%v err=%v", resp, err)
			}
			if ca.find("secret.move.approval_required.principal") != nil {
				t.Fatal("no approval may be signalled without Author on the destination")
			}
		})
	}
}

func TestMoveSecretForPrincipal_BadInput(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	src := mutFolder(t, s, "Src")
	grantGroup(t, s, carol, src, "R")
	id := mutSecret(t, s, src)
	ctx := context.Background()
	sa := agentGroupActor("sa-1")

	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: sa, Id: id}); code(err) != codes.InvalidArgument {
		t.Fatalf("missing dest: want InvalidArgument, got %v", err)
	}
	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: sa, Id: id, DestFolderId: src}); code(err) != codes.InvalidArgument {
		t.Fatalf("same folder: want InvalidArgument, got %v", err)
	}
	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: sa, Id: id, DestFolderId: "nope"}); code(err) != codes.NotFound {
		t.Fatalf("unknown dest: want NotFound, got %v", err)
	}
	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: sa, Id: "nope", DestFolderId: src}); code(err) != codes.NotFound {
		t.Fatalf("unknown secret: want NotFound, got %v", err)
	}
	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: id}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	dst := mutFolder(t, s, "Dst")
	grantGroup(t, s, carol, dst, "R")
	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: sa, Id: id, DestFolderId: dst}); code(err) != codes.FailedPrecondition {
		t.Fatalf("retired secret: want FailedPrecondition, got %v", err)
	}
}

// ---- ChangeSecretTypeForPrincipal --------------------------------------------

// Carry-over by identical key plus a supplied value for the new type's extra
// required field: values survive, the version ledger/record is re-sealed, and
// the change is audited as the principal with no values in the attributes.
func TestChangeSecretTypeForPrincipal_CarriesValues(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	id := mutSecret(t, s, f)

	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-web-password",
		Fields: map[string]string{"url": "https://example.test"},
	})
	if err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	if resp.GetSecret().GetTypeId() != "type-web-password" || s.findSecret(id).GetTypeId() != "type-web-password" {
		t.Fatalf("type not changed: %q", s.findSecret(id).GetTypeId())
	}
	got := openFields(t, s, id)
	want := map[string]string{"username": mutUser, "password": mutPass, "notes": mutNote, "url": "https://example.test"}
	if !stringMapsEqual(got, want) {
		t.Fatalf("stored fields after type change = %v keys, want %v", keysOf(got), keysOf(want))
	}
	if strings.Join(resp.GetFieldKeys(), ",") != "notes,password,url,username" {
		t.Fatalf("field_keys = %v", resp.GetFieldKeys())
	}
	ev := ca.find("secret.type_change.principal")
	if ev == nil {
		t.Fatal("expected a secret.type_change.principal audit event")
	}
	if !ev.Sensitive || ev.ActorUserID != "sa-1" || ev.Attributes["from_type_id"] != "type-password" || ev.Attributes["to_type_id"] != "type-web-password" {
		t.Fatalf("audit event wrong: %+v", ev)
	}
	for k, v := range ev.Attributes {
		for _, secret := range []string{mutUser, mutPass, mutNote, "https://example.test"} {
			if strings.Contains(v, secret) {
				t.Fatalf("audit attribute %s leaks a value", k)
			}
		}
	}
}

// Explicit field_mapping renames keys; every value still lands somewhere.
func TestChangeSecretTypeForPrincipal_FieldMapping(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	id := mutSecret(t, s, f)

	_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-secure-note",
		FieldMapping: map[string]string{"password": "note", "username": "description", "notes": "description2"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("mapping to a key the new type lacks: want InvalidArgument, got %v", err)
	}
	// Two sources into one destination would overwrite one value.
	_, err = s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-secure-note",
		FieldMapping: map[string]string{"password": "note", "username": "description", "notes": "description"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("mapping collision: want InvalidArgument, got %v", err)
	}
	assertNoValueLeak(t, err)
	if s.findSecret(id).GetTypeId() != "type-password" {
		t.Fatal("rejected change must leave the type unchanged")
	}
}

// The core safety property: a value with nowhere to go is never dropped. With
// unmapped_fields=REFUSE the call fails naming the KEY (not the value) and
// nothing changes (the NOTES default is covered in retype_notes_test.go).
func TestChangeSecretTypeForPrincipal_RejectsFieldLoss(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	id := mutSecret(t, s, f)
	before := openFields(t, s, id)

	_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-secure-note",
		FieldMapping:   map[string]string{"password": "note", "username": "description"}, // notes has nowhere to go
		UnmappedFields: vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE,
	})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("unmapped value: want FailedPrecondition, got %v", err)
	}
	if !strings.Contains(err.Error(), "notes") {
		t.Fatalf("error should name the unmapped key: %v", err)
	}
	assertNoValueLeak(t, err)
	if s.findSecret(id).GetTypeId() != "type-password" || !stringMapsEqual(openFields(t, s, id), before) {
		t.Fatal("rejected change must not touch the secret")
	}
}

// A sensitive value may never land in a non-sensitive field (that would make it
// readable through the un-audited GetSecretFields path), and a super-sensitive
// one may never lose its double-reveal protection.
func TestChangeSecretTypeForPrincipal_RejectsSensitivityDowngrade(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	id := mutSecret(t, s, f)

	_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-web-password",
		FieldMapping: map[string]string{"password": "description", "notes": "notes"},
		Fields:       map[string]string{"url": "https://x.test", "password": "other"},
	})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("sensitive->plain: want FailedPrecondition(sensitive), got %v", err)
	}
	assertNoValueLeak(t, err)

	// super-sensitive PIN -> ordinary password field.
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "pin", FolderId: f, TypeId: "type-pin", Fields: map[string]string{"pin": "123456"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(pin): %v", err)
	}
	_, err = s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: c.GetSecret().GetId(), NewTypeId: "type-password",
		FieldMapping: map[string]string{"pin": "password"}, Fields: map[string]string{"username": "u"},
	})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "super-sensitive") {
		t.Fatalf("super-sensitive->sensitive: want FailedPrecondition(super-sensitive), got %v", err)
	}
	if strings.Contains(err.Error(), "123456") {
		t.Fatal("error leaks the PIN")
	}
}

func TestChangeSecretTypeForPrincipal_ValidatesNewType(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	id := mutSecret(t, s, f)
	sa := agentGroupActor("sa-1")
	ctx := context.Background()

	// type-web-password requires url.
	_, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{Actor: sa, Id: id, NewTypeId: "type-web-password"})
	if code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "url") {
		t.Fatalf("missing required: want InvalidArgument(url), got %v", err)
	}
	// fields may not overwrite a carried-over value.
	_, err = s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: id, NewTypeId: "type-web-password", Fields: map[string]string{"url": "https://x.test", "password": "new"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("overwrite via fields: want InvalidArgument, got %v", err)
	}
	// fields for a key the new type lacks.
	_, err = s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: id, NewTypeId: "type-web-password", Fields: map[string]string{"url": "https://x.test", "bogus": "x"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("unknown field: want InvalidArgument, got %v", err)
	}
	// mapping a key the secret doesn't have.
	_, err = s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: id, NewTypeId: "type-web-password", FieldMapping: map[string]string{"nosuch": "url"},
	})
	if code(err) != codes.InvalidArgument {
		t.Fatalf("unknown mapping source: want InvalidArgument, got %v", err)
	}
	// pattern of the new type: a password is not a PIN.
	_, err = s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: id, NewTypeId: "type-bank-account",
		FieldMapping: map[string]string{"password": "accountNumber", "username": "onlineUsername", "notes": "notes"},
	})
	if code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "accountNumber") {
		t.Fatalf("pattern violation: want InvalidArgument(accountNumber), got %v", err)
	}
	assertNoValueLeak(t, err)
	// same type, unknown type.
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{Actor: sa, Id: id, NewTypeId: "type-password"}); code(err) != codes.InvalidArgument {
		t.Fatalf("same type: want InvalidArgument, got %v", err)
	}
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{Actor: sa, Id: id, NewTypeId: "type-nope"}); code(err) != codes.NotFound {
		t.Fatalf("unknown type: want NotFound, got %v", err)
	}
	if s.findSecret(id).GetTypeId() != "type-password" {
		t.Fatal("rejected changes must leave the type unchanged")
	}
}

// Changing INTO or OUT of a rotation/heartbeat-managed type is allowed
// for a machine (the automation side is covered in retype_automation_test.go),
// and so is the certificate type once its material validates. Dropping checkout
// from a type with no rotation/heartbeat stays human-only.
func TestChangeSecretTypeForPrincipal_ManagedTypes(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	admin := &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true}
	f := mutFolder(t, s, "F")
	grantGroup(t, s, carol, f, "R")
	ctx := context.Background()
	sa := agentGroupActor("sa-1")

	into := []struct {
		typeID string
		fields map[string]string
	}{
		{"type-active-directory", map[string]string{"domain": "corp.example.test"}},
		{"type-windows-domain", map[string]string{"domain": "corp.example.test"}},
		{"type-windows-local", map[string]string{"machine": "m1"}},
		{"type-database-account", map[string]string{"server": "db1"}},
		{"type-ssh-key", nil},
	}
	for _, tc := range into {
		t.Run("into "+tc.typeID, func(t *testing.T) {
			id := mutSecret(t, s, f)
			if fieldDef(s.findType(tc.typeID), "notes") == nil {
				// No notes field to receive the stored notes: store none.
				id = retypeSecret(t, s, f, "type-password", map[string]string{"username": mutUser, "password": mutPass})
			}
			req := &vaultv1.ChangeSecretTypeForPrincipalRequest{Actor: sa, Id: id, NewTypeId: tc.typeID, Fields: tc.fields}
			if tc.typeID == "type-ssh-key" {
				req.FieldMapping = map[string]string{"password": "passphrase"}
				req.Fields = map[string]string{"keyFormat": "Ed25519", "privateKey": "not-a-real-key"}
			}
			if _, err := s.ChangeSecretTypeForPrincipal(ctx, req); err != nil {
				t.Fatalf("into %s should be allowed: %v", tc.typeID, err)
			}
			if got := s.findSecret(id).GetTypeId(); got != tc.typeID {
				t.Fatalf("type = %q, want %q", got, tc.typeID)
			}
		})
	}

	plain := mutSecret(t, s, f)
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: plain, NewTypeId: "type-ssl-cert", Fields: map[string]string{"certificate": "x"},
		FieldMapping: map[string]string{"password": "privateKey"},
	}); code(err) != codes.InvalidArgument {
		t.Fatalf("into certificate with no certificate material: want InvalidArgument, got %v", err)
	}

	for _, out := range []struct {
		typeID string
		fields map[string]string
	}{
		{"type-active-directory", map[string]string{"domain": "corp.example.test", "username": "svc", "password": mutPass}},
		{"type-database-account", map[string]string{"server": "db1", "username": "svc", "password": mutPass}},
		{"type-ssh-key", map[string]string{"username": "svc", "keyFormat": "Ed25519", "privateKey": "k"}},
	} {
		t.Run("out of "+out.typeID, func(t *testing.T) {
			c, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
				Actor: carol, Name: "managed", FolderId: f, TypeId: out.typeID, Fields: out.fields,
			})
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			if _, err = s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: sa, Id: c.GetSecret().GetId(), NewTypeId: "type-secure-note",
			}); err != nil {
				t.Fatalf("out of %s should be allowed: %v", out.typeID, err)
			}
			if s.findSecret(c.GetSecret().GetId()).GetTypeId() != "type-secure-note" {
				t.Fatal("type must be changed")
			}
		})
	}

	// A custom checkout-only type (no rotation/heartbeat): dropping checkout
	// would lift a governance control humans rely on.
	ct, err := s.CreateSecretType(ctx, &vaultv1.CreateSecretTypeRequest{Actor: admin, Type: &vaultv1.SecretType{
		Name: "Checked-out password", Checkout: true, Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
			{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
			{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		},
	}})
	if err != nil {
		t.Fatalf("CreateSecretType: %v", err)
	}
	co, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "co", FolderId: f, TypeId: ct.GetType().GetId(),
		Fields: map[string]string{"username": "u", "password": mutPass},
	})
	if err != nil {
		t.Fatalf("CreateSecret(co): %v", err)
	}
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: co.GetSecret().GetId(), NewTypeId: "type-password",
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("dropping checkout: want FailedPrecondition, got %v", err)
	}
	// Adding checkout only tightens governance: allowed.
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: sa, Id: plain, NewTypeId: ct.GetType().GetId(),
	}); err != nil {
		t.Fatalf("plain -> checkout type should be allowed: %v", err)
	}
}

func TestChangeSecretTypeForPrincipal_Denials(t *testing.T) {
	cases := []struct {
		name  string
		grant string
		actor *vaultv1.ActorContext
	}{
		{name: "no rights", actor: agentGroupActor("sa-1")},
		{name: "read-only", grant: "C", actor: agentGroupActor("sa-1")},
		{name: "human caller (even site-admin)", grant: "R", actor: &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true}},
		{name: "spoofed admin service account", actor: &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-evil",
			UserId: "user-carol", IsSiteAdmin: true, IsRoot: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			carol := &vaultv1.ActorContext{UserId: "user-carol"}
			f := mutFolder(t, s, "F")
			if tc.grant != "" {
				grantGroup(t, s, carol, f, tc.grant)
			}
			id := mutSecret(t, s, f)
			_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: tc.actor, Id: id, NewTypeId: "type-web-password", Fields: map[string]string{"url": "https://x.test"},
			})
			if code(err) != codes.PermissionDenied {
				t.Fatalf("want PermissionDenied, got %v", err)
			}
			if s.findSecret(id).GetTypeId() != "type-password" || ca.find("secret.type_change.principal") != nil {
				t.Fatal("denied type change must not change or audit a change")
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
