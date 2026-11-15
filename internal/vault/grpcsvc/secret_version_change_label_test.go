// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// #165: a type change's version records the change itself (old type -> new
// type, fields added/renamed/carried over), instead of reading in history as
// only "Changed: host". Everywhere the version shows (ListSecretVersions,
// ChangeSecretTypeForPrincipal's own response, the secret.type_change.
// principal audit record) carries the same label.

func latestVersion(t *testing.T, s *Server, id string) *vaultv1.SecretVersion {
	t.Helper()
	resp, err := s.ListSecretVersions(context.Background(), &vaultv1.ListSecretVersionsRequest{
		Actor: orgCarol, SecretId: id,
	})
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	vs := resp.GetVersions()
	if len(vs) == 0 {
		t.Fatal("no versions")
	}
	return vs[0] // newest first
}

func TestChangeSecretType_VersionRecordsAnAddedField(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	f := authorFolder(t, s)
	id := retypeSecret(t, s, f, "type-password", map[string]string{"username": "svc", "password": "Init1alP@ss-2026"})

	ca := &capAudit{}
	s.audit = ca
	resp, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-unix-ssh", Fields: map[string]string{"host": "box.example.org"},
	})
	if err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	want := "Type changed: Password → Password Account (SSH)"
	if !strings.HasPrefix(resp.GetChangeLabel(), want) {
		t.Fatalf("response change_label = %q, want prefix %q", resp.GetChangeLabel(), want)
	}
	if !strings.Contains(resp.GetChangeLabel(), "added host") {
		t.Fatalf("response change_label = %q, want it to name the added field", resp.GetChangeLabel())
	}
	if !strings.Contains(resp.GetChangeLabel(), "fields carried over") ||
		!strings.Contains(resp.GetChangeLabel(), "username") || !strings.Contains(resp.GetChangeLabel(), "password") {
		t.Fatalf("response change_label = %q, want username and password named as carried over", resp.GetChangeLabel())
	}

	v := latestVersion(t, s, id)
	if v.GetChangeLabel() != resp.GetChangeLabel() {
		t.Fatalf("version change_label = %q, want it to match the response's %q", v.GetChangeLabel(), resp.GetChangeLabel())
	}
	if len(v.GetChangedFieldKeys()) == 0 {
		t.Fatal("the version must still report its changed field keys alongside the label")
	}

	ev := ca.find("secret.type_change.principal")
	if ev == nil || ev.Attributes["change_label"] != resp.GetChangeLabel() {
		t.Fatalf("audit change_label = %+v, want it to match the response", ev)
	}
}

func TestChangeSecretType_VersionRecordsARenamedField(t *testing.T) {
	s := newServerWithVersions(t)
	f := authorFolder(t, s)
	addType(s, &vaultv1.SecretType{Id: "type-org-login", Name: "Org Login", Fields: []*vaultv1.SecretFieldDef{
		{Key: "login", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
		{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
	}})
	id := retypeSecret(t, s, f, "type-password", map[string]string{"username": "svc", "password": "Init1alP@ss-2026"})

	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-org-login",
		FieldMapping: map[string]string{"username": "login"},
	})
	if err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	if !strings.Contains(resp.GetChangeLabel(), "renamed username to login") {
		t.Fatalf("change_label = %q, want the rename named", resp.GetChangeLabel())
	}
	if strings.Contains(resp.GetChangeLabel(), "added") {
		t.Fatalf("change_label = %q, a renamed field must not also read as added", resp.GetChangeLabel())
	}
}

// A target attached right after a type change gets its own audit entry and
// never touches the type change's already-written version label — there is
// no shared mutable state between them to fold into or lose from.
func TestChangeSecretType_TargetAttachAfterwardsDoesNotAlterTheLabel(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	f := authorFolder(t, s)
	id := retypeSecret(t, s, f, "type-password", map[string]string{"username": "svc", "password": "Init1alP@ss-2026"})
	ca := &capAudit{}
	s.audit = ca
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-unix-ssh", Fields: map[string]string{"host": "box.example.org"},
	}); err != nil {
		t.Fatalf("ChangeSecretTypeForPrincipal: %v", err)
	}
	before := latestVersion(t, s, id)

	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "ssh", Protocol: "ssh", Port: 22},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	tgt, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{Name: "box", Hostname: "box.example.org", ConnectionId: conn.GetConnection().GetId()},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	if _, err := s.SetSecretTargetForPrincipal(ctx, &vaultv1.SetSecretTargetForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id, TargetId: tgt.GetTarget().GetId(),
	}); err != nil {
		t.Fatalf("SetSecretTargetForPrincipal: %v", err)
	}

	after := latestVersion(t, s, id)
	if after.GetVersionNo() != before.GetVersionNo() || after.GetChangeLabel() != before.GetChangeLabel() {
		t.Fatalf("attaching a target must not touch the type change's version: before %+v after %+v", before, after)
	}
	if ca.find("secret.target.principal") == nil {
		t.Fatal("the target attach must still be audited on its own")
	}
}

// An ordinary create or update — no type change — carries no change_label,
// so the web keeps rendering it from changed_field_keys as before.
func TestVersionChangeLabel_EmptyForAnOrdinaryUpdate(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "db", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Init1alP@ss-2026"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	id := created.GetSecret().GetId()
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Fields: map[string]string{"username": "svc", "password": "N3wP@ss-2026"},
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if v := latestVersion(t, s, id); v.GetChangeLabel() != "" {
		t.Fatalf("change_label = %q, want empty for an ordinary update", v.GetChangeLabel())
	}
}
