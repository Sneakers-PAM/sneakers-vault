// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// Ownership is a human standing. A non-human actor is never an owner on the
// human paths, even when its ActorContext carries a user id.

func spoofedUserActors() map[string]*vaultv1.ActorContext {
	return map[string]*vaultv1.ActorContext{
		"service account": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x", UserId: "user-carol"},
		"workload":        {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-x", UserId: "user-carol"},
		"personal token":  tokenActor("user-carol", false),
	}
}

func TestNonHumanWithUserIDIsNeverFolderOwner(t *testing.T) {
	for name, a := range spoofedUserActors() {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			shared := mutFolder(t, s, "Carol's")
			seedPersonalFolder(s, "user-carol")
			for _, id := range []string{shared, "folder-personal-carol"} {
				if s.isFolderOwner(a, s.findFolder(id)) {
					t.Fatalf("%s must not own %s", name, id)
				}
			}
			_, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
				Actor: a, FolderId: shared, Owners: []string{"user-carol", "sa-x"},
			})
			wantCode(t, err, codes.PermissionDenied)
			n := len(s.folders)
			_, err = s.CreateFolder(context.Background(), &vaultv1.CreateFolderRequest{Actor: a, ParentId: shared, Name: "planted"})
			wantCode(t, err, codes.PermissionDenied)
			if len(s.folders) != n {
				t.Fatal("a denied create must not add a folder")
			}
		})
	}
}

func TestNonHumanWithUserIDIsNeverTargetOwner(t *testing.T) {
	for name, a := range spoofedUserActors() {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			conn := adminConnection(t, s)
			resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
				Actor: orgCarol, Target: &vaultv1.Target{Name: "mine", Hostname: "h.example.org", ConnectionId: conn},
			})
			if err != nil {
				t.Fatalf("SaveTarget: %v", err)
			}
			tgt := findByID(s.targets, resp.GetTarget().GetId())
			if s.isTargetOwner(a, tgt) {
				t.Fatalf("%s must not own carol's target", name)
			}
			_, err = s.SetTargetRuleset(context.Background(), &vaultv1.SetTargetRulesetRequest{Actor: a, TargetId: tgt.GetId()})
			wantCode(t, err, codes.PermissionDenied)
		})
	}
}

// Targets are created and edited by a user or that user's token; a service
// account or workload carrying a user id is neither.
func TestMachineWithUserIDCannotEditOrDeleteUsersTarget(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"service account": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x", UserId: "user-carol"},
		"workload":        {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-x", UserId: "user-carol"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			conn := adminConnection(t, s)
			resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
				Actor: orgCarol, Target: &vaultv1.Target{Name: "mine", Hostname: "h.example.org", ConnectionId: conn},
			})
			if err != nil {
				t.Fatalf("SaveTarget: %v", err)
			}
			id := resp.GetTarget().GetId()
			_, err = s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
				Actor: a, Target: &vaultv1.Target{Id: id, Name: "hijacked", Hostname: "evil.example.org", ConnectionId: conn},
			})
			wantCode(t, err, codes.PermissionDenied)
			_, err = s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
				Actor: a, Target: &vaultv1.Target{Name: "new", Hostname: "n.example.org", ConnectionId: conn},
			})
			wantCode(t, err, codes.PermissionDenied)
			del, err := s.DeleteTarget(context.Background(), &vaultv1.DeleteTargetRequest{Actor: a, Id: id})
			if code(err) != codes.PermissionDenied || del.GetRemoved() {
				t.Fatalf("delete: want PermissionDenied, got %v %v", del, err)
			}
			if findByID(s.targets, id).GetName() != "mine" {
				t.Fatal("a denied call must not change the target")
			}
		})
	}
}
