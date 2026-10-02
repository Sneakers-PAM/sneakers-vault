// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// An everyone rule is for people. A service account, workload or personal
// token never gains access from one; it matches only rules naming its own id
// or user, or one of its groups. An everyone deny still applies to it.

// everyoneReadFolder is a shared folder carrying an admin-set everyone:C rule
// and one human-authored password secret.
func everyoneReadFolder(t *testing.T, s *Server) (folderID, secretID string) {
	t.Helper()
	folderID = mutFolder(t, s, "Shared Ops")
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: humanAdmin, FolderId: folderID, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: map[string]string{"C": "allow"}}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(everyone:C): %v", err)
	}
	return folderID, mutSecret(t, s, folderID)
}

func principalCanListAndReveal(t *testing.T, s *Server, a *vaultv1.ActorContext, folderID, secretID string) (listed bool, revealErr error) {
	t.Helper()
	resp, err := s.ListSecretsForPrincipal(context.Background(), &vaultv1.ListSecretsForPrincipalRequest{Actor: a, FolderId: folderID})
	if err != nil {
		t.Fatalf("ListSecretsForPrincipal: %v", err)
	}
	_, revealErr = s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{
		Actor: a, Id: secretID, FieldKey: "password",
	})
	return idsOf(resp.GetSecrets())[secretID], revealErr
}

func TestEveryoneRule_DoesNotReachMachinePrincipals(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"service account with no grants": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-nobody"},
		"workload with no grants":        {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "spiffe://example.org/ns/ci/sa/runner"},
		"personal token, no group grant": tokenActor("user-ada", false, "g-staff"),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			folderID, secretID := everyoneReadFolder(t, s)
			listed, err := principalCanListAndReveal(t, s, a, folderID, secretID)
			if listed {
				t.Fatal("an everyone rule must not make the secret listable to a machine caller")
			}
			wantCode(t, err, codes.PermissionDenied)
		})
	}
}

func TestEveryoneRule_StillReachesPeople(t *testing.T) {
	s := newServer(t)
	_, secretID := everyoneReadFolder(t, s)
	resp, err := s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-ada"}, Id: secretID, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("a person must still read through an everyone rule: %v", err)
	}
	if resp.GetValue() != mutPass {
		t.Fatal("unexpected reveal value")
	}
}

func TestEveryoneRule_ExplicitGrantStillWorksForMachines(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"service account in g-agents": agentGroupActor("sa-1"),
		"personal token in g-agents":  tokenActor("user-ada", false, "g-agents"),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			folderID, secretID := everyoneReadFolder(t, s)
			if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
				Actor: humanAdmin, FolderId: folderID, Owners: []string{"user-carol"},
				Rules: []*vaultv1.RaciRule{
					{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: map[string]string{"C": "allow"}},
					{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: map[string]string{"C": "allow"}},
				},
			}); err != nil {
				t.Fatalf("SetFolderRuleset: %v", err)
			}
			listed, err := principalCanListAndReveal(t, s, a, folderID, secretID)
			if !listed || err != nil {
				t.Fatalf("an explicit group grant must still work: listed=%v err=%v", listed, err)
			}
		})
	}
}

func TestEveryoneDeny_StillAppliesToMachines(t *testing.T) {
	s := newServer(t)
	parent := mutFolder(t, s, "Parent")
	grantGroup(t, s, orgCarol, parent, "C")
	child := subFolder(t, s, parent, "Locked")
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: humanAdmin, FolderId: child, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: map[string]string{"C": "deny"}}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset(everyone:deny): %v", err)
	}
	secretID := mutSecret(t, s, child)
	listed, err := principalCanListAndReveal(t, s, agentGroupActor("sa-1"), child, secretID)
	if listed {
		t.Fatal("an everyone deny below a group grant must still hide the secret from a machine")
	}
	wantCode(t, err, codes.PermissionDenied)
}

func TestEveryoneRule_TargetDoesNotReachMachines(t *testing.T) {
	s := newServer(t)
	tgt, _ := everyoneTarget(t, s)
	if s.canConnectTarget(agentGroupActor("sa-1"), tgt) {
		t.Fatal("an everyone target rule must not let a machine connect")
	}
	if !s.canConnectTarget(&vaultv1.ActorContext{UserId: "user-ada"}, tgt) {
		t.Fatal("a person must still connect through an everyone target rule")
	}
}

func everyoneTarget(t *testing.T, s *Server) (*vaultv1.Target, string) {
	t.Helper()
	conn := adminConnection(t, s)
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: humanAdmin, Target: &vaultv1.Target{Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	if _, err := s.SetTargetRuleset(context.Background(), &vaultv1.SetTargetRulesetRequest{
		Actor: humanAdmin, TargetId: resp.GetTarget().GetId(),
		Ruleset: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, Grants: map[string]string{"C": "allow"}}},
	}); err != nil {
		t.Fatalf("SetTargetRuleset: %v", err)
	}
	return findByID(s.targets, resp.GetTarget().GetId()), conn
}

// A machine principal id is its RACI subject key, the same shape a human user
// id has. A machine whose id is a human user id must never match that user's
// rules or ownership.
func TestMachinePrincipalWithAUserIDNeverMatchesThatUser(t *testing.T) {
	for name, kind := range map[string]vaultv1.PrincipalKind{
		"service account": vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		"workload":        vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			impostor := &vaultv1.ActorContext{PrincipalKind: kind, PrincipalId: "user-ada"}

			userRuled := mutFolder(t, s, "Ada's grant")
			if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
				Actor: orgCarol, FolderId: userRuled, Owners: []string{"user-carol"},
				Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-ada", Grants: map[string]string{"C": "allow", "R": "allow"}}},
			}); err != nil {
				t.Fatalf("SetFolderRuleset: %v", err)
			}
			ruledSecret := mutSecret(t, s, userRuled)
			listed, err := principalCanListAndReveal(t, s, impostor, userRuled, ruledSecret)
			if listed {
				t.Fatal("a machine with a user's id must not match that user's rule")
			}
			wantCode(t, err, codes.PermissionDenied)

			seedPersonalFolder(s, "user-ada")
			owned := secretIn(t, s, &vaultv1.ActorContext{UserId: "user-ada"}, "folder-personal-ada", "ada-login")
			listed, err = principalCanListAndReveal(t, s, impostor, "folder-personal-ada", owned)
			if listed {
				t.Fatal("a machine with a user's id must not own that user's personal folder")
			}
			wantCode(t, err, codes.PermissionDenied)
		})
	}
}
