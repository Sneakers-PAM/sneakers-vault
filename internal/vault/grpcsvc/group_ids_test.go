// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// GROUP rules saved with a subject_id match ActorContext.group_ids for every
// principal kind: a person, a personal token and a service account.

func groupIDFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	sid := secretIn(t, s, carol, fid, "db")
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "Ops", SubjectId: "g-ops-1",
			Grants: map[string]string{"C": "allow"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return s, sid
}

func principalKinds(groupNames, groupIDs []string) map[string]*vaultv1.ActorContext {
	return map[string]*vaultv1.ActorContext{
		"human":      {UserId: "user-dave", GroupNames: groupNames, GroupIds: groupIDs},
		"user token": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-dave", TokenId: "utok-9", GroupNames: groupNames, GroupIds: groupIDs},
		"service account": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-reports",
			GroupNames: groupNames, GroupIds: groupIDs},
	}
}

func canReveal(s *Server, a *vaultv1.ActorContext, sid string) error {
	ctx := context.Background()
	if a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		_, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: a, Id: sid, FieldKey: "password"})
		return err
	}
	_, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: a, Id: sid, FieldKey: "password"})
	return err
}

func TestGroupIDRulesMatchEveryPrincipalKind(t *testing.T) {
	s, sid := groupIDFixture(t)
	for kind, a := range principalKinds([]string{"Operations"}, []string{"g-ops-1"}) {
		if err := canReveal(s, a, sid); err != nil {
			t.Fatalf("%s in the group (renamed): %v", kind, err)
		}
	}
	for kind, a := range principalKinds([]string{"Ops"}, []string{"g-other"}) {
		if err := canReveal(s, a, sid); code(err) != codes.PermissionDenied {
			t.Fatalf("%s with only the old name: %v, want PermissionDenied", kind, err)
		}
	}
}

func TestSavedRulesKeepTheGroupID(t *testing.T) {
	s, sid := groupIDFixture(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	sec := s.findSecret(sid)
	got, err := s.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: carol, FolderId: sec.GetFolderId()})
	if err != nil || len(got.GetRules()) != 1 || got.GetRules()[0].GetSubjectId() != "g-ops-1" || got.GetRules()[0].GetSubjectName() != "Ops" {
		t.Fatalf("folder ruleset = %v, %v", got.GetRules(), err)
	}
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: carol, SecretId: sid, Rules: []*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "Ops", SubjectId: "g-ops-1", Grants: map[string]string{"C": "deny"},
	}}}); err != nil {
		t.Fatal(err)
	}
	if r := s.findSecret(sid).GetRuleset(); len(r) != 1 || r[0].GetSubjectId() != "g-ops-1" {
		t.Fatalf("secret ruleset = %v", r)
	}
	// A user rule never keeps a subject id.
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: carol, SecretId: sid, Rules: []*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-dave", SubjectId: "g-ops-1", Grants: map[string]string{"C": "allow"},
	}}}); err != nil {
		t.Fatal(err)
	}
	if r := s.findSecret(sid).GetRuleset(); r[0].GetSubjectId() != "" {
		t.Fatalf("user rule kept subject_id %q", r[0].GetSubjectId())
	}
}

func TestLegacyNameOnlyGroupRuleStillWorks(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	sid := secretIn(t, s, carol, fid, "db")
	if _, err := s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{Actor: carol, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "Ops", Grants: map[string]string{"C": "allow"}}}}); err != nil {
		t.Fatal(err)
	}
	for kind, a := range principalKinds([]string{"ops"}, []string{"g-anything"}) {
		if err := canReveal(s, a, sid); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}

func TestSimulationMatchesGroupIDs(t *testing.T) {
	s, sid := groupIDFixture(t)
	resp, err := s.SimulateSecret(context.Background(), &vaultv1.SimulateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, SecretId: sid, SimUserId: "user-dave", SimGroupIds: []string{"g-ops-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetDecision().GetRead() {
		t.Fatalf("simulated member of g-ops-1 can't read: %v", resp)
	}
}
