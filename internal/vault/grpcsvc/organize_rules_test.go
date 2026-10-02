// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
)

// Organize rules for machine callers: names never carry a path separator, a
// personal token organizes inside its own Personal tree and never another
// user's, and every rename/create is audited with the names and the token.

func TestOrganizeNames_RejectPathSeparators(t *testing.T) {
	for _, bad := range []string{"ssh/keys", `ssh\keys`, "/", `\`} {
		t.Run(bad, func(t *testing.T) {
			s := newServer(t)
			f := mutFolder(t, s, "Ops")
			grantGroup(t, s, orgCarol, f, "R")
			id := mutSecret(t, s, f)
			child := subFolder(t, s, f, "Child")
			sa := agentGroupActor("sa-1")

			_, err := s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{Actor: sa, Id: id, Name: bad})
			wantCode(t, err, codes.InvalidArgument)
			_, err = s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{Actor: sa, ParentId: f, Name: bad})
			wantCode(t, err, codes.InvalidArgument)
			_, err = s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{Actor: sa, Id: child, Name: bad})
			wantCode(t, err, codes.InvalidArgument)
			if s.findSecret(id).GetName() != "svc" || s.findFolder(child).GetName() != "Child" {
				t.Fatal("a rejected name must change nothing")
			}
		})
	}
}

func TestUserTokenCreatesFolderInOwnPersonalTree(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	seedPersonalFolder(s, "user-carol")
	tok := tokenActor("user-carol", false)

	resp, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: tok, ParentId: "folder-personal-carol", Name: "SSH Keys",
	})
	if err != nil {
		t.Fatalf("create in own personal tree: %v", err)
	}
	f := s.findFolder(resp.GetFolder().GetId())
	if f.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL || f.GetOwnerUserId() != "user-carol" {
		t.Fatalf("new folder must stay in the owner's personal tree: %+v", f)
	}
	if personal, owner := s.destPersonal(f); !personal || owner != "user-carol" {
		t.Fatalf("destPersonal = %v/%q, want personal/user-carol", personal, owner)
	}
	if resp.GetFolder().GetOwnerUserId() != "" {
		t.Fatalf("response must be metadata only: %+v", resp.GetFolder())
	}
	ev := ca.find("folder.create.principal")
	if ev == nil || ev.ActorUserID != "user-carol" || ev.Attributes["token_id"] != "utok-1" ||
		ev.Attributes["name"] != "SSH Keys" || ev.Attributes["parent_id"] != "folder-personal-carol" {
		t.Fatalf("create audit = %+v", ev)
	}

	sub, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: tok, ParentId: f.GetId(), Name: "Lab",
	})
	if err != nil {
		t.Fatalf("create deeper in own personal tree: %v", err)
	}
	if s.findFolder(sub.GetFolder().GetId()).GetOwnerUserId() != "user-carol" {
		t.Fatal("a nested personal folder must keep the owner")
	}

	_, err = s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: tok, ParentId: "folder-personal-carol", Name: "ssh keys",
	})
	wantCode(t, err, codes.AlreadyExists)
}

func TestUserTokenNeverOrganizesAnotherUsersPersonalTree(t *testing.T) {
	for name, tok := range map[string]*vaultv1.ActorContext{
		"user token":        tokenActor("user-carol", false),
		"admin's token":     tokenActor("user-admin", true),
		"token in bob's gr": tokenActor("user-carol", false, "g-bob"),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			seedPersonalFolder(s, "user-bob")
			bob := &vaultv1.ActorContext{UserId: "user-bob"}
			if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
				Actor: bob, FolderId: "folder-personal-bob", Owners: []string{"user-bob"},
				Rules: []*vaultv1.RaciRule{{
					SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-bob", Grants: map[string]string{"R": "allow"},
				}},
			}); err != nil {
				t.Fatalf("SetFolderRuleset: %v", err)
			}
			child := &vaultv1.Folder{Id: "folder-bob-child", Name: "Child", ParentId: "folder-personal-bob",
				Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "user-bob"}
			s.folders = append(s.folders, child)
			id := secretIn(t, s, bob, "folder-personal-bob", "bob-login")

			_, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
				Actor: tok, ParentId: "folder-personal-bob", Name: "Planted",
			})
			wantCode(t, err, codes.PermissionDenied)
			_, err = s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{
				Actor: tok, Id: child.GetId(), Name: "Renamed",
			})
			wantCode(t, err, codes.PermissionDenied)
			_, err = s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{
				Actor: tok, Id: id, Name: "Renamed",
			})
			wantCode(t, err, codes.PermissionDenied)
			if child.GetName() != "Child" || s.findSecret(id).GetName() != "bob-login" {
				t.Fatal("a denied call must change nothing")
			}
			for _, a := range []string{"folder.create.principal", "folder.rename.principal", "secret.rename.principal"} {
				if ca.find(a) != nil {
					t.Fatalf("a denied call must not audit %s", a)
				}
			}
		})
	}
}

func TestUserTokenRenamesInOwnPersonalTreeAuditedWithToken(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	seedPersonalFolder(s, "user-carol")
	tok := tokenActor("user-carol", false)
	child := &vaultv1.Folder{Id: "folder-carol-child", Name: "Old", ParentId: "folder-personal-carol",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "user-carol"}
	sibling := &vaultv1.Folder{Id: "folder-carol-sib", Name: "Taken", ParentId: "folder-personal-carol",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "user-carol"}
	s.folders = append(s.folders, child, sibling)
	secID := secretIn(t, s, orgCarol, "folder-personal-carol", "old-login")

	if _, err := s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{
		Actor: tok, Id: child.GetId(), Name: "New",
	}); err != nil {
		t.Fatalf("rename own personal folder: %v", err)
	}
	ev := ca.find("folder.rename.principal")
	if ev == nil || ev.ActorUserID != "user-carol" || ev.Attributes["from_name"] != "Old" ||
		ev.Attributes["to_name"] != "New" || ev.Attributes["token_id"] != "utok-1" {
		t.Fatalf("folder rename audit = %+v", ev)
	}
	_, err := s.RenameFolderForPrincipal(context.Background(), &vaultv1.RenameFolderForPrincipalRequest{
		Actor: tok, Id: child.GetId(), Name: "taken",
	})
	wantCode(t, err, codes.AlreadyExists)

	resp, err := s.RenameSecretForPrincipal(context.Background(), &vaultv1.RenameSecretForPrincipalRequest{
		Actor: tok, Id: secID, Name: "new-login",
	})
	if err != nil {
		t.Fatalf("rename own personal secret: %v", err)
	}
	ev = ca.find("secret.rename.principal")
	if ev == nil || ev.ActorUserID != "user-carol" || ev.Attributes["from_name"] != "old-login" ||
		ev.Attributes["to_name"] != "new-login" || ev.Attributes["token_id"] != "utok-1" {
		t.Fatalf("secret rename audit = %+v", ev)
	}
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"p"`) || strings.Contains(string(raw), "fields") {
		t.Fatalf("a rename must never return field values: %s", raw)
	}
}

func TestUserTokenNeverCreatesUnderTheMasterPersonalRoot(t *testing.T) {
	s := newServer(t)
	s.ensureMasterPersonalFolder()
	injectEveryoneRule(s, "folder-personal-root", map[string]string{"R": "allow"})
	grantGroup(t, s, humanAdmin, "folder-personal-root", "R")
	n := len(s.folders)
	_, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: tokenActor("user-admin", true, "g-agents"), ParentId: "folder-personal-root", Name: "Planted",
	})
	wantCode(t, err, codes.PermissionDenied)
	if len(s.folders) != n {
		t.Fatal("a denied create must not add a folder")
	}
}

func TestServiceAccountNeverCreatesInOwnersGrantedPersonalFolder(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-carol")
	grantGroup(t, s, orgCarol, "folder-personal-carol", "R")
	_, err := s.CreateFolderForPrincipal(context.Background(), &vaultv1.CreateFolderForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), ParentId: "folder-personal-carol", Name: "x",
	})
	wantCode(t, err, codes.PermissionDenied)
}
