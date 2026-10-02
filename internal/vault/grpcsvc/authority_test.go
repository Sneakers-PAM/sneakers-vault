// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The vault checks authority itself rather than trusting the gateway to have
// done it: admin methods need a human site admin or root with a real user id,
// and folder-rule edits need the folder's owner (or such an admin).

func refusalReason(t *testing.T, err error) string {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err %v, want PermissionDenied", err)
	}
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			if info.GetDomain() != "sneakers.vault" {
				t.Fatalf("domain %q", info.GetDomain())
			}
			return info.GetReason()
		}
	}
	t.Fatalf("no ErrorInfo on %v", err)
	return ""
}

func authzServer(t *testing.T) (*Server, *recordingAuditor) {
	t.Helper()
	s := newServer(t)
	ra := &recordingAuditor{}
	s.audit = ra
	return s, ra
}

// notAdmins are actors that must never pass an admin check.
func notAdmins() map[string]*vaultv1.ActorContext {
	return map[string]*vaultv1.ActorContext{
		"plain user":            {UserId: "user-bob"},
		"admin without user id": {IsSiteAdmin: true, IsRoot: true},
		"admin as system":       {UserId: "system", IsSiteAdmin: true, IsRoot: true},
		"service account":       {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x", IsSiteAdmin: true},
		"user token":            {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-admin", IsSiteAdmin: true},
	}
}

type adminCall func(s *Server, a *vaultv1.ActorContext) error

func adminCalls(t *testing.T) map[string]adminCall {
	t.Helper()
	ctx := context.Background()
	f := false
	return map[string]adminCall{
		"UpdateSecuritySettings": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{Actor: a, AllowApiForSensitive: &f})
			return err
		},
		"SavePasswordPolicy": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.SavePasswordPolicy(ctx, &vaultv1.SavePasswordPolicyRequest{Actor: a, Policy: &vaultv1.PasswordPolicy{Name: "p"}})
			return err
		},
		"DeletePasswordPolicy": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.DeletePasswordPolicy(ctx, &vaultv1.DeletePasswordPolicyRequest{Actor: a, Id: "no-such-policy"})
			return err
		},
		"CreateSecretType": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.CreateSecretType(ctx, &vaultv1.CreateSecretTypeRequest{Actor: a, Type: &vaultv1.SecretType{Name: "Custom"}})
			return err
		},
		"UpdateSecretType": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.UpdateSecretType(ctx, &vaultv1.UpdateSecretTypeRequest{Actor: a, Id: "no-such-type", Type: &vaultv1.SecretType{Name: "X"}})
			return err
		},
		"DeleteSecretType": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.DeleteSecretType(ctx, &vaultv1.DeleteSecretTypeRequest{Actor: a, Id: "no-such-type"})
			return err
		},
		"CloneSecretType": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.CloneSecretType(ctx, &vaultv1.CloneSecretTypeRequest{Actor: a, Id: "type-password"})
			return err
		},
		"ImportExtension": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.ImportExtension(ctx, &vaultv1.ImportExtensionRequest{Actor: a, Id: "no-such-extension"})
			return err
		},
		"ImportExtensionFromJson": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.ImportExtensionFromJson(ctx, &vaultv1.ImportExtensionFromJsonRequest{Actor: a, Json: "{}"})
			return err
		},
		"SeedBuiltins": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.SeedBuiltins(ctx, &vaultv1.SeedBuiltinsRequest{Actor: a})
			return err
		},
		"SaveConnection": func(s *Server, a *vaultv1.ActorContext) error {
			_, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{Actor: a, Connection: &vaultv1.Connection{Name: "c"}})
			return err
		},
	}
}

func TestAdminMethodsRefuseNonAdmins(t *testing.T) {
	for method, call := range adminCalls(t) {
		for who, actor := range notAdmins() {
			t.Run(method+"/"+who, func(t *testing.T) {
				s, ra := authzServer(t)
				if got := refusalReason(t, call(s, actor)); got != ReasonNotSiteAdmin {
					t.Fatalf("reason %q, want %s", got, ReasonNotSiteAdmin)
				}
				ev := ra.find("authz.denied")
				if ev == nil || ev.Attributes["method"] != method || ev.Attributes["reason"] != ReasonNotSiteAdmin {
					t.Fatalf("audit = %+v", ev)
				}
			})
		}
	}
}

func TestAdminMethodsAllowASiteAdmin(t *testing.T) {
	for method, call := range adminCalls(t) {
		t.Run(method, func(t *testing.T) {
			s, ra := authzServer(t)
			if err := call(s, siteAdmin); status.Code(err) == codes.PermissionDenied {
				t.Fatalf("site admin refused: %v", err)
			}
			if ev := ra.find("authz.denied"); ev != nil {
				t.Fatalf("site admin audited as denied: %+v", ev)
			}
		})
	}
}

func TestRootWithAUserIDIsAnAdmin(t *testing.T) {
	s, _ := authzServer(t)
	root := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true}
	if _, err := s.CreateSecretType(context.Background(), &vaultv1.CreateSecretTypeRequest{Actor: root, Type: &vaultv1.SecretType{Name: "C"}}); err != nil {
		t.Fatal(err)
	}
}

type folderCall func(s *Server, a *vaultv1.ActorContext, folderID string) error

func folderCalls() map[string]folderCall {
	ctx := context.Background()
	return map[string]folderCall{
		"AddFolderRule": func(s *Server, a *vaultv1.ActorContext, fid string) error {
			_, err := s.AddFolderRule(ctx, &vaultv1.AddFolderRuleRequest{Actor: a, Rule: &vaultv1.FolderAccessRule{
				FolderId: fid, SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectId: "user-bob"}})
			return err
		},
		"RemoveFolderRule": func(s *Server, a *vaultv1.ActorContext, fid string) error {
			s.rules = append(s.rules, &vaultv1.FolderAccessRule{Id: "rule-t", FolderId: fid, SubjectId: "user-dave"})
			_, err := s.RemoveFolderRule(ctx, &vaultv1.RemoveFolderRuleRequest{Actor: a, Id: "rule-t"})
			return err
		},
		"RenameFolder": func(s *Server, a *vaultv1.ActorContext, fid string) error {
			_, err := s.RenameFolder(ctx, &vaultv1.RenameFolderRequest{Actor: a, Id: fid, Name: "Renamed"})
			return err
		},
		"ReorderFolders": func(s *Server, a *vaultv1.ActorContext, fid string) error {
			_, err := s.ReorderFolders(ctx, &vaultv1.ReorderFoldersRequest{Actor: a, ParentId: fid})
			return err
		},
	}
}

func TestFolderEditsNeedTheFolderOwner(t *testing.T) {
	for method, call := range folderCalls() {
		t.Run(method, func(t *testing.T) {
			s, ra := authzServer(t)
			fid := newSharedFolder(t, s) // owned by user-carol
			bob := &vaultv1.ActorContext{UserId: "user-bob"}
			if got := refusalReason(t, call(s, bob, fid)); got != ReasonNotFolderOwner {
				t.Fatalf("reason %q, want %s", got, ReasonNotFolderOwner)
			}
			if ev := ra.find("authz.denied"); ev == nil || ev.ActorUserID != "user-bob" || ev.Attributes["method"] != method || ev.Subject != fid {
				t.Fatalf("audit = %+v", ev)
			}
			for _, ok := range []*vaultv1.ActorContext{{UserId: "user-carol"}, siteAdmin} {
				if err := call(s, ok, fid); err != nil {
					t.Fatalf("%s: %v", ok.GetUserId(), err)
				}
			}
		})
	}
}

func TestRemovingARuleChangesNothingWhenRefused(t *testing.T) {
	s, _ := authzServer(t)
	fid := newSharedFolder(t, s)
	before := len(s.rules)
	_ = folderCalls()["RemoveFolderRule"](s, &vaultv1.ActorContext{UserId: "user-bob"}, fid)
	if len(s.rules) != before+1 {
		t.Fatalf("rules %d, want %d (the refused removal deleted a rule)", len(s.rules), before+1)
	}
}

func TestReorderingTopLevelFoldersNeedsASiteAdmin(t *testing.T) {
	s, _ := authzServer(t)
	_, err := s.ReorderFolders(context.Background(), &vaultv1.ReorderFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}})
	if got := refusalReason(t, err); got != ReasonNotSiteAdmin {
		t.Fatalf("reason %q", got)
	}
	if _, err := s.ReorderFolders(context.Background(), &vaultv1.ReorderFoldersRequest{Actor: siteAdmin}); err != nil {
		t.Fatal(err)
	}
}
