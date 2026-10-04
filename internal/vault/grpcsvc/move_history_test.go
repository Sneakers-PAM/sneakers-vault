// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// moveWithEditorResave creates a password secret that never stored "notes" or
// "url", then moves it the way the staff editor saves: the new folder plus
// every non-sensitive field, with "" for the ones the record doesn't have.
func moveWithEditorResave(t *testing.T) (s *Server, ca *capAudit, secID, from, to string, before crypto.Record) {
	t.Helper()
	s = newServer(t)
	ca = &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	from = newSharedFolder(t, s)
	dest, err := s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: carol, Name: "Ops Team"})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	to = dest.GetFolder().GetId()
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc login", FolderId: from, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secID = created.GetSecret().GetId()
	before = s.records[secID]

	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, Name: "svc login", DestFolderId: to,
		Fields: map[string]string{"username": "svc", "notes": "", "url": ""},
	}); err != nil {
		t.Fatalf("move: %v", err)
	}
	return s, ca, secID, from, to, before
}

func TestUpdateSecret_MoveWithEditorResaveMintsNoVersion(t *testing.T) {
	s, _, secID, _, to, before := moveWithEditorResave(t)
	if got := s.findSecret(secID).GetFolderId(); got != to {
		t.Fatalf("folder = %q, want %q", got, to)
	}
	if !reflect.DeepEqual(before, s.records[secID]) {
		t.Error("move re-sealed the record: an empty value for a field the record never had is not a change")
	}
}

func TestUpdateSecret_MoveAuditsFromAndToFolders(t *testing.T) {
	_, ca, _, from, to, _ := moveWithEditorResave(t)
	ev := ca.find("secret.move")
	if ev == nil {
		t.Fatal("no secret.move audit event emitted")
	}
	if got := ev.Attributes["from_folder_id"]; got != from {
		t.Errorf("from_folder_id = %q, want %q", got, from)
	}
	if got := ev.Attributes["to_folder_id"]; got != to {
		t.Errorf("to_folder_id = %q, want %q", got, to)
	}
}

func TestUpdateSecret_MoveRecordsNoFieldChange(t *testing.T) {
	_, ca, _, _, _, _ := moveWithEditorResave(t)
	ev := ca.find("secret.update")
	if ev == nil {
		t.Fatal("no secret.update audit event emitted")
	}
	want := secretUpdateAttributes(nil, nil)
	if !reflect.DeepEqual(ev.Attributes, want) {
		t.Errorf("secret.update attributes = %v, want %v (no field changed)", ev.Attributes, want)
	}
}

func TestUpdateSecret_ClearingAStoredValueIsStillAChange(t *testing.T) {
	s := newServer(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret1", "notes": "keep me"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secID := created.GetSecret().GetId()
	before := s.records[secID]

	if _, err := s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: secID, Name: "svc", Fields: map[string]string{"username": "svc", "notes": ""},
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if reflect.DeepEqual(before, s.records[secID]) {
		t.Fatal("clearing a stored value did not re-seal the record")
	}
	got, err := s.crypt.OpenAll(s.records[secID])
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	if v, ok := got["notes"]; !ok || v != "" {
		t.Errorf("notes = %q (present %v), want cleared to empty", v, ok)
	}
}

func TestChangedFieldKeys_AbsentAndEmptyAreEqual(t *testing.T) {
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	env := crypto.New(kek)
	fp := func(fields map[string]string) map[string]string {
		rec, err := env.Seal(fields)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		out, err := fieldFingerprints(env, rec)
		if err != nil {
			t.Fatalf("fingerprints: %v", err)
		}
		return out
	}

	v1 := fp(map[string]string{"subject": "CN=a"})
	v2 := fp(map[string]string{"subject": "CN=a", "sans": ""})
	if got := changedFieldKeys(v2, v1); len(got) != 0 {
		t.Errorf("absent -> empty changed = %v, want none", got)
	}
	if got := changedFieldKeys(v1, v2); len(got) != 0 {
		t.Errorf("empty -> absent changed = %v, want none", got)
	}
	v3 := fp(map[string]string{"subject": "CN=a", "sans": "a.example.org"})
	if got := changedFieldKeys(v3, v2); !reflect.DeepEqual(got, []string{"sans"}) {
		t.Errorf("empty -> value changed = %v, want [sans]", got)
	}
	if got := changedFieldKeys(v1, nil); !reflect.DeepEqual(got, []string{"subject"}) {
		t.Errorf("oldest version changed = %v, want [subject]", got)
	}
}
