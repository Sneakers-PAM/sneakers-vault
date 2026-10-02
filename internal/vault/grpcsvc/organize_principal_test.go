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
	"google.golang.org/grpc/status"
)

// Organize verbs: RenameSecretForPrincipal and
// UpdateSecretFieldsForPrincipal. Same edit gate as move/change-type (RACI
// Author on the folder chain AND the secret's own ruleset, never an admin flag
// for a machine), non-human principals only, audited as the principal, values
// never echoed. Folder verbs live in organize_folders_principal_test.go.

var orgCarol = &vaultv1.ActorContext{UserId: "user-carol"}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("code = %v (%v), want %v", status.Code(err), err, want)
	}
}

// denySecretAuthor adds a per-secret override that denies g-agents Author.
func denySecretAuthor(t *testing.T, s *Server, secretID string) {
	t.Helper()
	if _, err := s.SetSecretRuleset(context.Background(), &vaultv1.SetSecretRulesetRequest{
		Actor: orgCarol, SecretId: secretID,
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents",
			Grants: map[string]string{"R": "deny"},
		}},
	}); err != nil {
		t.Fatalf("SetSecretRuleset: %v", err)
	}
}

// injectEveryoneRule appends an everyone-subject rule straight into the store,
// standing in for an admin-set everyone rule (a non-admin cannot set one).
func injectEveryoneRule(s *Server, folderID string, grants map[string]string) {
	s.raciRules = append(s.raciRules, &vaultv1.RaciRule{
		Id: s.nextID("raci"), FolderId: folderID, Order: 99,
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: grants,
	})
}

var spoofedAdminSA = &vaultv1.ActorContext{
	PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-evil",
	UserId: "user-carol", IsSiteAdmin: true, IsRoot: true,
}

var humanAdmin = &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true, IsRoot: true}

// secretDenialCase is shared by the rename and update denial tables.
type secretDenialCase struct {
	name  string
	setup func(t *testing.T, s *Server) (secretID string)
	actor *vaultv1.ActorContext
	code  codes.Code
}

func secretDenialCases() []secretDenialCase {
	shared := func(grant string, secretDeny bool) func(t *testing.T, s *Server) string {
		return func(t *testing.T, s *Server) string {
			f := mutFolder(t, s, "Src")
			if grant != "" {
				grantGroup(t, s, orgCarol, f, grant)
			}
			id := mutSecret(t, s, f)
			if secretDeny {
				denySecretAuthor(t, s, id)
			}
			return id
		}
	}
	return []secretDenialCase{
		{name: "no rights", setup: shared("", false), actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "read-only", setup: shared("C", false), actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "per-secret deny overrides folder author", setup: shared("R", true), actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "per-secret allow cannot bypass a folder with no grant", setup: func(t *testing.T, s *Server) string {
			f := mutFolder(t, s, "Src")
			id := mutSecret(t, s, f)
			if _, err := s.SetSecretRuleset(context.Background(), &vaultv1.SetSecretRulesetRequest{
				Actor: orgCarol, SecretId: id,
				Rules: []*vaultv1.RaciRule{{
					SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents",
					Grants: map[string]string{"C": "allow", "R": "allow"},
				}},
			}); err != nil {
				t.Fatalf("SetSecretRuleset: %v", err)
			}
			return id
		}, actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "personal folder reached only via a master-root grant", setup: func(t *testing.T, s *Server) string {
			s.ensureMasterPersonalFolder()
			seedPersonalFolder(s, "user-carol")
			grantGroup(t, s, humanAdmin, "folder-personal-root", "R")
			return mutSecret(t, s, "folder-personal-carol")
		}, actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "human caller (even site-admin)", setup: shared("R", false), actor: humanAdmin, code: codes.PermissionDenied},
		{name: "spoofed admin flags, no grants", setup: shared("", false), actor: spoofedAdminSA, code: codes.PermissionDenied},
		{name: "personal folder not granted", setup: func(t *testing.T, s *Server) string {
			seedPersonalFolder(s, "user-carol")
			return mutSecret(t, s, "folder-personal-carol")
		}, actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "personal folder with only an everyone rule", setup: func(t *testing.T, s *Server) string {
			seedPersonalFolder(s, "user-carol")
			injectEveryoneRule(s, "folder-personal-carol", map[string]string{"C": "allow", "R": "allow"})
			return mutSecret(t, s, "folder-personal-carol")
		}, actor: agentGroupActor("sa-1"), code: codes.PermissionDenied},
		{name: "retired secret", setup: func(t *testing.T, s *Server) string {
			id := shared("R", false)(t, s)
			if _, err := s.RetireSecret(context.Background(), &vaultv1.RetireSecretRequest{Actor: orgCarol, Id: id}); err != nil {
				t.Fatalf("RetireSecret: %v", err)
			}
			return id
		}, actor: agentGroupActor("sa-1"), code: codes.FailedPrecondition},
	}
}

// ---- RenameSecretForPrincipal ------------------------------------------------

func TestRenameSecretForPrincipal_AuthorAllowedAndAudited(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	id := mutSecret(t, s, f)
	recBefore := s.records[id]

	resp, err := s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Name: "  prod db  ",
	})
	if err != nil {
		t.Fatalf("RenameSecretForPrincipal: %v", err)
	}
	if resp.GetSecret().GetName() != "prod db" || s.findSecret(id).GetName() != "prod db" {
		t.Fatalf("name = %q, want trimmed %q", s.findSecret(id).GetName(), "prod db")
	}
	if !reflect.DeepEqual(s.records[id], recBefore) {
		t.Fatal("rename must not touch the sealed record")
	}
	ev := ca.find("secret.rename.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["principal_id"] != "sa-1" ||
		ev.Attributes["principal_kind"] != "PRINCIPAL_KIND_SERVICE_ACCOUNT" || ev.Subject != id {
		t.Fatalf("audit not attributed to the service account: %+v", ev)
	}
	if ev.Attributes["from_name"] != "svc" || ev.Attributes["to_name"] != "prod db" {
		t.Fatalf("audit names = %q -> %q", ev.Attributes["from_name"], ev.Attributes["to_name"])
	}
}

func TestRenameSecretForPrincipal_Denials(t *testing.T) {
	for _, tc := range secretDenialCases() {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			id := tc.setup(t, s)
			before := s.findSecret(id).GetName()
			_, err := s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{
				Actor: tc.actor, Id: id, Name: "renamed",
			})
			wantCode(t, err, tc.code)
			if s.findSecret(id).GetName() != before {
				t.Fatal("denied rename must not change the name")
			}
			if ca.find("secret.rename.principal") != nil {
				t.Fatal("denied rename must not audit a rename")
			}
		})
	}
}

func TestRenameSecretForPrincipal_InvalidInput(t *testing.T) {
	s := newServer(t)
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	id := mutSecret(t, s, f)
	for name, req := range map[string]*vaultv1.RenameSecretForPrincipalRequest{
		"empty name":    {Id: id, Name: "   "},
		"no id":         {Name: "x"},
		"control chars": {Id: id, Name: "bad\nname"},
		"too long":      {Id: id, Name: strings.Repeat("n", maxOrganizeNameRunes+1)},
		"same name":     {Id: id, Name: "svc"},
	} {
		t.Run(name, func(t *testing.T) {
			req.Actor = agentGroupActor("sa-1")
			_, err := s.RenameSecretForPrincipal(context.Background(), req)
			wantCode(t, err, codes.InvalidArgument)
		})
	}
	_, err := s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: "secret-missing", Name: "x",
	})
	wantCode(t, err, codes.NotFound)
}

// ---- UpdateSecretFieldsForPrincipal -----------------------------------------

func TestUpdateSecretFieldsForPrincipal_PartialUpdateReseals(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	id := mutSecret(t, s, f)
	recBefore := s.records[id]
	const newPass = "N3w-Pa55word!value"

	resp, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Fields: map[string]string{"password": newPass, "notes": ""},
	})
	if err != nil {
		t.Fatalf("UpdateSecretFieldsForPrincipal: %v", err)
	}
	if got := strings.Join(resp.GetChangedFieldKeys(), ","); got != "notes,password" {
		t.Fatalf("changed keys = %q, want notes,password", got)
	}
	if reflect.DeepEqual(s.records[id], recBefore) {
		t.Fatal("a changed value must be re-sealed")
	}
	got := openFields(t, s, id)
	if got["password"] != newPass || got["username"] != mutUser {
		t.Fatalf("merged fields wrong (untouched username must stay): keys=%v", sortedKeys(got))
	}
	if _, ok := got["notes"]; ok {
		t.Fatal("an empty value must clear the optional field")
	}
	ev := ca.find("secret.update.principal")
	if ev == nil || ev.ActorUserID != "sa-1" || ev.Attributes["principal_id"] != "sa-1" || !ev.Sensitive {
		t.Fatalf("audit not attributed to the service account / not sensitive: %+v", ev)
	}
	if ev.Attributes["changed_field_keys"] != "notes,password" {
		t.Fatalf("audit keys = %q", ev.Attributes["changed_field_keys"])
	}
	for k, v := range ev.Attributes {
		for _, secret := range []string{newPass, mutPass, mutNote, mutUser} {
			if strings.Contains(v, secret) {
				t.Fatalf("audit attribute %s leaks a value", k)
			}
		}
	}
}

func TestUpdateSecretFieldsForPrincipal_NoChangeMintsNoVersion(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	id := mutSecret(t, s, f)
	recBefore := s.records[id]
	resp, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Fields: map[string]string{"notes": mutNote},
	})
	if err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	if len(resp.GetChangedFieldKeys()) != 0 || !reflect.DeepEqual(s.records[id], recBefore) {
		t.Fatalf("no-op must not re-seal: changed=%v", resp.GetChangedFieldKeys())
	}
	if ca.find("secret.update.principal") != nil {
		t.Fatal("no-op must not audit an update")
	}
}

func TestUpdateSecretFieldsForPrincipal_Denials(t *testing.T) {
	for _, tc := range secretDenialCases() {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			id := tc.setup(t, s)
			recBefore := s.records[id]
			_, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
				Actor: tc.actor, Id: id, Fields: map[string]string{"notes": "changed"},
			})
			wantCode(t, err, tc.code)
			if !reflect.DeepEqual(s.records[id], recBefore) {
				t.Fatal("denied update must not re-seal")
			}
			if ca.find("secret.update.principal") != nil {
				t.Fatal("denied update must not audit an update")
			}
		})
	}
}

// addType installs a custom type for a test.
func addType(s *Server, st *vaultv1.SecretType) { s.types = append(s.types, st) }

func TestUpdateSecretFieldsForPrincipal_ValidationNeverLeaksValues(t *testing.T) {
	s := newServer(t)
	addType(s, &vaultv1.SecretType{Id: "type-org-custom", Name: "Custom", Fields: []*vaultv1.SecretFieldDef{
		{Key: "code", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true, Pattern: `^[A-Z]{3}$`},
		{Key: "short", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, MaxLength: 4},
		{Key: "secret", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true},
	}})
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "c", FolderId: f, TypeId: "type-org-custom",
		Fields: map[string]string{"code": "ABC", "secret": "keep-me"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := c.GetSecret().GetId()
	const leaky = "LEAKY-VALUE-xyz"
	cases := map[string]struct {
		fields map[string]string
		code   codes.Code
	}{
		"unknown key":            {map[string]string{"nope": leaky}, codes.InvalidArgument},
		"pattern mismatch":       {map[string]string{"code": leaky}, codes.InvalidArgument},
		"max length":             {map[string]string{"short": leaky}, codes.InvalidArgument},
		"clear a required field": {map[string]string{"code": ""}, codes.InvalidArgument},
		"no fields":              {map[string]string{}, codes.InvalidArgument},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			recBefore := s.records[id]
			_, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, Fields: tc.fields,
			})
			wantCode(t, err, tc.code)
			if strings.Contains(err.Error(), leaky) || strings.Contains(err.Error(), "keep-me") {
				t.Fatalf("error leaks a value: %v", err)
			}
			if !reflect.DeepEqual(s.records[id], recBefore) {
				t.Fatal("rejected update must not re-seal")
			}
		})
	}
	// A valid update on the same custom type succeeds.
	if _, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Fields: map[string]string{"code": "XYZ", "short": "abcd"},
	}); err != nil {
		t.Fatalf("valid update: %v", err)
	}
}

// Managed types: rotation, heartbeat, checkout and certificate. A machine may
// only change the descriptive notes/description fields there.
func TestUpdateSecretFieldsForPrincipal_ManagedTypesOnlyDescriptive(t *testing.T) {
	addCheckoutOnly := func(s *Server) {
		addType(s, &vaultv1.SecretType{Id: "type-org-checkout", Name: "Checkout", Checkout: true, Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
			{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
			{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		}})
	}
	cases := []struct {
		name    string
		typeID  string
		initial map[string]string
		patch   map[string]string
		allowed bool
	}{
		{"rotation: password (would desync the target)", "type-windows-local",
			map[string]string{"machine": "m1", "username": "u", "password": "P@ss-1"}, map[string]string{"password": "P@ss-2"}, false},
		{"rotation: account identity", "type-windows-local",
			map[string]string{"machine": "m1", "username": "u", "password": "P@ss-1"}, map[string]string{"username": "other"}, false},
		{"rotation: notes allowed", "type-windows-local",
			map[string]string{"machine": "m1", "username": "u", "password": "P@ss-1"}, map[string]string{"notes": "n", "description": "d"}, true},
		{"database rotation: server", "type-database-account",
			map[string]string{"server": "db1", "username": "u", "password": "P@ss-1"}, map[string]string{"server": "db2"}, false},
		{"heartbeat: ssh private key", "type-ssh-key",
			map[string]string{"username": "u", "keyFormat": "Ed25519", "privateKey": "k"}, map[string]string{"privateKey": "k2"}, false},
		{"heartbeat: notes allowed", "type-ssh-key",
			map[string]string{"username": "u", "keyFormat": "Ed25519", "privateKey": "k"}, map[string]string{"notes": "n"}, true},
		{"checkout: password", "type-org-checkout",
			map[string]string{"username": "u", "password": "p"}, map[string]string{"password": "p2"}, false},
		{"checkout: notes allowed", "type-org-checkout",
			map[string]string{"username": "u", "password": "p"}, map[string]string{"notes": "n"}, true},
		{"certificate: chain", certSecretTypeID,
			map[string]string{"certificate": "c"}, map[string]string{"chain": "x"}, false},
		{"certificate: notes allowed", certSecretTypeID,
			map[string]string{"certificate": "c"}, map[string]string{"notes": "n"}, true},
		{"unmanaged: password allowed", "type-password",
			map[string]string{"username": "u", "password": "p"}, map[string]string{"password": "p2"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			addCheckoutOnly(s)
			f := mutFolder(t, s, "Src")
			grantGroup(t, s, orgCarol, f, "R")
			c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
				Actor: orgCarol, Name: "m", FolderId: f, TypeId: tc.typeID, Fields: tc.initial,
			})
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			id := c.GetSecret().GetId()
			recBefore := s.records[id]
			_, err = s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, Fields: tc.patch,
			})
			if tc.allowed {
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				return
			}
			wantCode(t, err, codes.FailedPrecondition)
			for _, v := range tc.patch {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("error leaks a value: %v", err)
				}
			}
			if !reflect.DeepEqual(s.records[id], recBefore) {
				t.Fatal("refused update must not re-seal")
			}
		})
	}
}

// Version history: with the Postgres version store wired, an update appends a
// new active version and the previous values stay revealable from history.
func TestUpdateSecretFieldsForPrincipal_KeepsHistoryInPostgres(t *testing.T) {
	s := newServerWithVersions(t)
	f := mutFolder(t, s, "Src")
	grantGroup(t, s, orgCarol, f, "R")
	id := mutSecret(t, s, f)
	if _, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, Fields: map[string]string{"password": "Second-Pa55!"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	vs, err := s.vers.List(context.Background(), id, s.crypt)
	if err != nil {
		t.Fatalf("List versions: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("versions = %d, want 2 (create + update)", len(vs))
	}
	var active, prior int
	for _, v := range vs {
		if v.Active {
			active++
			if v.CreatedBy != "sa-1" {
				t.Fatalf("new version created_by = %q, want sa-1", v.CreatedBy)
			}
			continue
		}
		prior++
		rec, ok, err := s.vers.LoadVersion(context.Background(), id, v.VersionNo)
		if err != nil || !ok {
			t.Fatalf("LoadVersion(%d): ok=%v err=%v", v.VersionNo, ok, err)
		}
		old, err := s.crypt.OpenAll(rec)
		if err != nil || old["password"] != mutPass {
			t.Fatalf("prior version must keep the old password (err=%v)", err)
		}
	}
	if active != 1 || prior != 1 {
		t.Fatalf("active=%d prior=%d, want 1/1", active, prior)
	}
}

// Every mutating organize verb must be persisted by PersistUnary (a missing
// entry would lose the change on restart); the read-only list must not be.
func TestOrganizeVerbs_RegisteredAsMutating(t *testing.T) {
	for _, m := range []string{"RenameSecretForPrincipal", "UpdateSecretFieldsForPrincipal",
		"CreateFolderForPrincipal", "RenameFolderForPrincipal", "MoveFolderForPrincipal",
		"MoveSecretForPrincipal", "ChangeSecretTypeForPrincipal"} {
		if !mutatingMethods[m] {
			t.Errorf("%s is not registered in mutatingMethods", m)
		}
	}
	if mutatingMethods["ListFoldersForPrincipal"] {
		t.Error("ListFoldersForPrincipal is read-only and must not trigger a persist")
	}
}
