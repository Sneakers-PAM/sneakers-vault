// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// signalsFixture is a shared folder the g-agents principal can read and author,
// holding one password secret created by carol.
func signalsFixture(t *testing.T) (s *Server, ca *capAudit, folderID, secretID string) {
	t.Helper()
	s = newServer(t)
	ca = &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	folderID = newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: folderID, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents",
			Grants: map[string]string{"C": "allow", "R": "allow"}}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc", FolderId: folderID, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return s, ca, folderID, created.GetSecret().GetId()
}

func valueVersion(s *Server, id string) (int32, string) {
	sec := s.findSecret(id)
	return sec.GetValueVersion(), sec.GetValueChangedAt()
}

func TestValueVersion_CountsValueChangesOnly(t *testing.T) {
	s, _, _, id := signalsFixture(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	v, at := valueVersion(s, id)
	if v != 1 || at == "" {
		t.Fatalf("after create: value_version=%d changed_at=%q, want 1 and a time", v, at)
	}
	if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Fatalf("changed_at %q is not RFC3339", at)
	}

	// A rename and a save that changes nothing don't touch the counter.
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: id, Name: "svc renamed", Fields: map[string]string{"username": "svc"}}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	other, err := s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "Elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: id, Name: "svc renamed", DestFolderId: other.GetFolder().GetId()}); err != nil {
		t.Fatalf("move: %v", err)
	}
	if v2, _ := valueVersion(s, id); v2 != 1 {
		t.Fatalf("after rename and move: value_version=%d, want 1", v2)
	}

	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: id, Name: "svc renamed", Fields: map[string]string{"password": "N3w$ecret22"}}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if v3, _ := valueVersion(s, id); v3 != 2 {
		t.Fatalf("after a value edit: value_version=%d, want 2", v3)
	}
}

func TestValueVersion_PrincipalEditsCount(t *testing.T) {
	s, _, _, id := signalsFixture(t)
	resp, err := s.UpdateSecretFieldsForPrincipal(context.Background(), &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: agentGroupActor("sa-agent"), Id: id, Fields: map[string]string{"notes": "rotated by hand"},
	})
	if err != nil {
		t.Fatalf("UpdateSecretFieldsForPrincipal: %v", err)
	}
	if got := resp.GetSecret().GetValueVersion(); got != 2 {
		t.Fatalf("response value_version=%d, want 2", got)
	}
	if v, _ := valueVersion(s, id); v != 2 {
		t.Fatalf("stored value_version=%d, want 2", v)
	}
}

func TestListSecretsForPrincipal_ChangedSince(t *testing.T) {
	s, ca, folderID, id := signalsFixture(t)
	ctx := context.Background()
	agent := agentGroupActor("sa-agent")
	list := func(since string) ([]*vaultv1.Secret, error) {
		resp, err := s.ListSecretsForPrincipal(ctx, &vaultv1.ListSecretsForPrincipalRequest{Actor: agent, FolderId: folderID, ChangedSince: since})
		return resp.GetSecrets(), err
	}

	_, at := valueVersion(s, id)
	changed, _ := time.Parse(time.RFC3339, at)
	got, err := list(changed.Format(time.RFC3339))
	if err != nil || len(got) != 1 || got[0].GetValueVersion() != 1 {
		t.Fatalf("since the change: %v err=%v, want the secret", got, err)
	}
	if ev := ca.find("secret.list.principal"); ev == nil || ev.Attributes["changed_since"] == "" {
		t.Fatalf("the list audit doesn't record changed_since: %+v", ev)
	}
	if got, err := list(changed.Add(time.Hour).Format(time.RFC3339)); err != nil || len(got) != 0 {
		t.Fatalf("after the change: %v err=%v, want nothing", got, err)
	}
	if got, err := list(""); err != nil || len(got) != 1 {
		t.Fatalf("no filter: %v err=%v", got, err)
	}
	if _, err := list("yesterday"); code(err) != codes.InvalidArgument {
		t.Fatalf("bad changed_since: %v, want InvalidArgument", err)
	}
}

func TestPrincipalResponsesCarryTheAutomationState(t *testing.T) {
	s, _, folderID, _ := signalsFixture(t)
	resp, err := s.ListSecretsForPrincipal(context.Background(), &vaultv1.ListSecretsForPrincipalRequest{Actor: agentGroupActor("sa-agent"), FolderId: folderID})
	if err != nil || len(resp.GetSecrets()) != 1 {
		t.Fatalf("list: %v err=%v", resp, err)
	}
	sec := resp.GetSecrets()[0]
	if sec.GetRotationEnabled() || sec.GetRotatesOnCheckin() {
		t.Fatalf("a plain password with no target reports rotation: %+v", sec)
	}
	// The flags are computed per response, never stored.
	if stored := s.findSecret(sec.GetId()); stored.GetRotationEnabled() || stored.GetHeartbeatEnabled() {
		t.Fatal("automation flags were written to the stored secret")
	}
}

func TestGetSecretForPrincipal(t *testing.T) {
	s, ca, _, id := signalsFixture(t)
	ctx := context.Background()

	resp, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: agentGroupActor("sa-agent"), Id: id})
	if err != nil || resp.GetSecret().GetId() != id || resp.GetSecret().GetValueVersion() != 1 {
		t.Fatalf("get: %v err=%v", resp, err)
	}
	if ev := ca.find("secret.get.principal"); ev == nil || ev.Attributes["value_version"] != "1" {
		t.Fatalf("get not audited with the value version: %+v", ev)
	}

	stranger := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-other", GroupNames: []string{"g-other"}}
	if _, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: stranger, Id: id}); code(err) != codes.PermissionDenied {
		t.Fatalf("no read grant: %v, want PermissionDenied", err)
	}
	if _, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Id: id}); code(err) != codes.PermissionDenied {
		t.Fatalf("a human caller: %v, want PermissionDenied", err)
	}
	if _, err := s.GetSecretForPrincipal(ctx, &vaultv1.GetSecretForPrincipalRequest{Actor: agentGroupActor("sa-agent"), Id: "nope"}); code(err) != codes.NotFound {
		t.Fatalf("unknown id: %v, want NotFound", err)
	}
}

func TestValueVersion_CommittedRotationCounts(t *testing.T) {
	s, _, secID := newRotationServer(t)
	before, _ := valueVersion(s, secID)
	_, v := revealNewVer(t, s, secID)
	if _, err := s.ReportRotation(context.Background(), &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: v,
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	after, _ := valueVersion(s, secID)
	if after <= before || after != v {
		t.Fatalf("value_version %d -> %d, want the committed version %d", before, after, v)
	}
	// An idempotent retry doesn't count the same commit twice.
	if _, err := s.ReportRotation(context.Background(), &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: v,
	}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if again, _ := valueVersion(s, secID); again != after {
		t.Fatalf("retry moved value_version %d -> %d", after, again)
	}
}
