// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A principal create or generate may attach only a target it could attach
// later with SetSecretTargetForPrincipal: one that exists and is shared or
// owned by the token's user.

type principalCreate func(s *Server, a *vaultv1.ActorContext, folderID, targetID string) (*vaultv1.Secret, error)

func principalCreators() map[string]principalCreate {
	return map[string]principalCreate{
		"create": func(s *Server, a *vaultv1.ActorContext, folderID, targetID string) (*vaultv1.Secret, error) {
			r, err := s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
				Actor: a, Name: "svc", FolderId: folderID, TypeId: "type-password", TargetId: targetID,
				Fields: map[string]string{"username": "svc", "password": "Init1alP@ss"},
			})
			return r.GetSecret(), err
		},
		"generate": func(s *Server, a *vaultv1.ActorContext, folderID, targetID string) (*vaultv1.Secret, error) {
			r, err := s.GenerateSecretForPrincipal(context.Background(), &vaultv1.GenerateSecretForPrincipalRequest{
				Actor: a, Name: "svc", FolderId: folderID, TypeId: "type-password", TargetId: targetID,
				Fields: map[string]string{"username": "svc"},
			})
			return r.GetSecret(), err
		},
	}
}

func targetOwnedBy(t *testing.T, s *Server, owner *vaultv1.ActorContext) string {
	t.Helper()
	conn := adminConnection(t, s)
	r, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: owner, Target: &vaultv1.Target{Name: "t", Hostname: "t.example.org", ConnectionId: conn},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	return r.GetTarget().GetId()
}

func TestPrincipalCreate_TargetVisibility(t *testing.T) {
	cases := []struct {
		name   string
		actor  *vaultv1.ActorContext
		target func(t *testing.T, s *Server) string
		want   codes.Code
	}{
		{"unknown target", tokenActor("user-ada", false, "g-agents"), func(*testing.T, *Server) string { return "target-missing" }, codes.NotFound},
		{"another user's target", tokenActor("user-ada", false, "g-agents"), func(t *testing.T, s *Server) string { return targetOwnedBy(t, s, orgCarol) }, codes.PermissionDenied},
		{"a user's target for a service account", agentGroupActor("sa-1"), func(t *testing.T, s *Server) string { return targetOwnedBy(t, s, orgCarol) }, codes.PermissionDenied},
		{"own target", tokenActor("user-ada", false, "g-agents"), func(t *testing.T, s *Server) string {
			return targetOwnedBy(t, s, &vaultv1.ActorContext{UserId: "user-ada"})
		}, codes.OK},
		{"shared target", agentGroupActor("sa-1"), func(t *testing.T, s *Server) string { return targetOwnedBy(t, s, siteAdmin) }, codes.OK},
		{"no target", agentGroupActor("sa-1"), func(*testing.T, *Server) string { return "" }, codes.OK},
	}
	for cname, create := range principalCreators() {
		for _, tc := range cases {
			t.Run(cname+"/"+tc.name, func(t *testing.T) {
				s := newServer(t)
				f := mutFolder(t, s, "Ops")
				grantGroup(t, s, orgCarol, f, "R")
				tgt := tc.target(t, s)
				n := len(s.secrets)
				sec, err := create(s, tc.actor, f, tgt)
				wantCode(t, err, tc.want)
				if tc.want != codes.OK {
					if len(s.secrets) != n {
						t.Fatal("a refused create must not store a secret")
					}
					return
				}
				if sec.GetTargetId() != tgt {
					t.Fatalf("target_id = %q, want %q", sec.GetTargetId(), tgt)
				}
			})
		}
	}
}
