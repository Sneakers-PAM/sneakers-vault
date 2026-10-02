// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// newDiffServer builds a mem-backed Server wired to a capAudit, plus a
// type-password secret (username=non-sensitive, password=sensitive) owned by
// user-carol in a fresh shared folder, for exercising secret.update's
// field-level audit diff.
func newDiffServer(t *testing.T) (*Server, *capAudit, *vaultv1.ActorContext, string) {
	t.Helper()
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	ctx := context.Background()
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db creds", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "alice", "password": "old-Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return s, ca, carol, created.GetSecret().GetId()
}

// updateAttrs runs UpdateSecret and returns the resulting secret.update audit
// event's attributes.
func updateAttrs(t *testing.T, s *Server, ca *capAudit, req *vaultv1.UpdateSecretRequest) map[string]string {
	t.Helper()
	if _, err := s.UpdateSecret(context.Background(), req); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	ev := ca.find("secret.update")
	if ev == nil {
		t.Fatal("no secret.update audit event recorded")
	}
	return ev.Attributes
}

// TestUpdateSecretAuditsNonSensitiveFieldDiff proves a non-sensitive field
// change (username) records its old and new values in the secret.update
// audit event, so the UI history can render "username: alice -> bob".
func TestUpdateSecretAuditsNonSensitiveFieldDiff(t *testing.T) {
	s, ca, carol, sid := newDiffServer(t)
	attrs := updateAttrs(t, s, ca, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: sid, Fields: map[string]string{"username": "bob", "password": "old-Sup3r$ecret"},
	})

	raw, ok := attrs["changes"]
	if !ok {
		t.Fatalf("attributes missing \"changes\": %#v", attrs)
	}
	var changes []fieldChange
	if err := json.Unmarshal([]byte(raw), &changes); err != nil {
		t.Fatalf("unmarshal changes: %v", err)
	}
	found := false
	for _, c := range changes {
		if c.Field == "username" {
			found = true
			if c.Old != "alice" || c.New != "bob" {
				t.Fatalf("username change = %+v, want old=alice new=bob", c)
			}
		}
	}
	if !found {
		t.Fatalf("username change not present: %+v", changes)
	}
	if _, ok := attrs["sensitiveChanged"]; ok {
		t.Fatalf("unexpected sensitiveChanged (password unchanged): %#v", attrs)
	}
}

// TestUpdateSecretAuditsSensitiveFieldChangedOnly proves a sensitive field
// change (password) records ONLY that it changed — never the old or new
// value — anywhere in the emitted audit attributes. This is the hard security
// rule: a secret value must never enter the audit log.
func TestUpdateSecretAuditsSensitiveFieldChangedOnly(t *testing.T) {
	s, ca, carol, sid := newDiffServer(t)
	const oldVal, newVal = "old-Sup3r$ecret", "new-Sup3r$ecret"
	attrs := updateAttrs(t, s, ca, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: sid, Fields: map[string]string{"username": "alice", "password": newVal},
	})

	raw, ok := attrs["sensitiveChanged"]
	if !ok {
		t.Fatalf("attributes missing \"sensitiveChanged\": %#v", attrs)
	}
	var sensitiveChanged []string
	if err := json.Unmarshal([]byte(raw), &sensitiveChanged); err != nil {
		t.Fatalf("unmarshal sensitiveChanged: %v", err)
	}
	if len(sensitiveChanged) != 1 || sensitiveChanged[0] != "password" {
		t.Fatalf("sensitiveChanged = %v, want [password]", sensitiveChanged)
	}

	// Hard rule: neither the old nor new password value may appear ANYWHERE in
	// the serialized attributes, under any key (including inside "changes").
	blob, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("marshal attrs: %v", err)
	}
	if strings.Contains(string(blob), oldVal) {
		t.Fatalf("audit attributes leaked the OLD sensitive value: %s", blob)
	}
	if strings.Contains(string(blob), newVal) {
		t.Fatalf("audit attributes leaked the NEW sensitive value: %s", blob)
	}

	// "changes" (non-sensitive diffs) must not carry the password field at all.
	if raw, ok := attrs["changes"]; ok {
		var changes []fieldChange
		if err := json.Unmarshal([]byte(raw), &changes); err != nil {
			t.Fatalf("unmarshal changes: %v", err)
		}
		for _, c := range changes {
			if c.Field == "password" {
				t.Fatalf("password must not appear in non-sensitive changes: %+v", c)
			}
		}
	}
}

// TestUpdateSecretAuditsRenameAsNonSensitiveChange proves a secret rename is
// captured as a non-sensitive "name" field change.
func TestUpdateSecretAuditsRenameAsNonSensitiveChange(t *testing.T) {
	s, ca, carol, sid := newDiffServer(t)
	attrs := updateAttrs(t, s, ca, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: sid, Name: "renamed creds",
	})

	raw, ok := attrs["changes"]
	if !ok {
		t.Fatalf("attributes missing \"changes\": %#v", attrs)
	}
	var changes []fieldChange
	if err := json.Unmarshal([]byte(raw), &changes); err != nil {
		t.Fatalf("unmarshal changes: %v", err)
	}
	if len(changes) != 1 || changes[0].Field != "name" || changes[0].Old != "db creds" || changes[0].New != "renamed creds" {
		t.Fatalf("changes = %+v, want single name rename", changes)
	}
}

// TestUpdateSecretNoOpEmitsNoAttributes proves a save that changes nothing
// (no rename, unchanged field values) emits no attributes, same as before the
// diff feature existed — it doesn't manufacture spurious changes.
func TestUpdateSecretNoOpEmitsNoAttributes(t *testing.T) {
	s, ca, carol, sid := newDiffServer(t)
	attrs := updateAttrs(t, s, ca, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: sid, Fields: map[string]string{"username": "alice", "password": "old-Sup3r$ecret"},
	})
	if attrs != nil {
		t.Fatalf("expected nil attributes for a no-op update, got %#v", attrs)
	}
}
