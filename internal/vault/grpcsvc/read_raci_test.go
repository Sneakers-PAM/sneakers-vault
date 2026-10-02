// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// GetSecretFields returns field values, so it needs read on the secret, like
// a reveal. It's checked in the vault, not only by the gateway.

func TestGetSecretFieldsNeedsRead(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	sid := secretIn(t, s, carol, newSharedFolder(t, s), "db")

	got, err := s.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: carol, Id: sid})
	if err != nil || got.GetFields()["username"] != "u" {
		t.Fatalf("reader: %v %v", got, err)
	}
	for name, a := range map[string]*vaultv1.ActorContext{
		"person without read": {UserId: "user-nobody"},
		"no actor":            nil,
		"user token":          {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-nobody", TokenId: "utok-1"},
		"service account":     {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x"},
	} {
		ca.mu.Lock()
		ca.events = nil
		ca.mu.Unlock()
		if _, err := s.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: a, Id: sid}); code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v, want PermissionDenied", name, err)
		}
		if ev := ca.find("secret.read.denied"); ev == nil || ev.Subject != sid || ev.Attributes["reason"] != "NO_ACCESS" {
			t.Fatalf("%s: audit = %+v", name, ev)
		}
	}
	root := &vaultv1.ActorContext{UserId: "system:workflow", IsRoot: true}
	if _, err := s.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: root, Id: sid}); err != nil {
		t.Fatalf("root: %v", err)
	}
}

// ListSecretsInFolder and GetSecret show a secret's metadata to anyone who can
// see its folder, so people can find and request what they can't read yet,
// with can_read telling the UI which ones are locked. A secret an explicit
// deny covers is hidden, and so is anything in someone else's personal tree.

type listFixture struct {
	s                *Server
	ca               *capAudit
	folder           string
	open, denied     string // open: no rule for bob; denied: an explicit deny for bob
	personal, carols string
}

func newListFixture(t *testing.T) *listFixture {
	t.Helper()
	fx := &listFixture{s: newServer(t), ca: &capAudit{}}
	fx.s.audit = fx.ca
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fx.folder = newSharedFolder(t, fx.s)
	fx.open = secretIn(t, fx.s, carol, fx.folder, "open")
	fx.denied = secretIn(t, fx.s, carol, fx.folder, "denied")
	if _, err := fx.s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: carol, SecretId: fx.denied, Rules: []*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-bob", Grants: map[string]string{"C": "deny"},
	}}}); err != nil {
		t.Fatal(err)
	}
	seedPersonalFolder(fx.s, "user-carol")
	fx.personal = "folder-personal-carol"
	fx.carols = secretIn(t, fx.s, carol, fx.personal, "mine")
	return fx
}

func listed(t *testing.T, s *Server, a *vaultv1.ActorContext, folderID string) map[string]bool {
	t.Helper()
	resp, err := s.ListSecretsInFolder(context.Background(), &vaultv1.ListSecretsInFolderRequest{Actor: a, FolderId: folderID})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, sec := range resp.GetSecrets() {
		out[sec.GetId()] = sec.GetCanRead()
	}
	return out
}

func TestListSecretsInFolderShowsLockedSecretsAndHidesDenied(t *testing.T) {
	fx := newListFixture(t)
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	got := listed(t, fx.s, bob, fx.folder)
	if canRead, ok := got[fx.open]; !ok || canRead {
		t.Fatalf("bob: open secret listed=%v can_read=%v, want listed and locked", ok, canRead)
	}
	if _, ok := got[fx.denied]; ok {
		t.Fatal("bob: a secret denied to him was listed")
	}
	carolSees := listed(t, fx.s, &vaultv1.ActorContext{UserId: "user-carol"}, fx.folder)
	if !carolSees[fx.open] || !carolSees[fx.denied] {
		t.Fatalf("owner: %v, want both readable", carolSees)
	}
	if fx.s.findSecret(fx.open).GetCanRead() {
		t.Fatal("can_read leaked into the stored secret")
	}
}

func TestOtherPeoplesPersonalSecretsAreHidden(t *testing.T) {
	fx := newListFixture(t)
	for name, a := range map[string]*vaultv1.ActorContext{
		"another person":       {UserId: "user-dave"},
		"another person token": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-dave", TokenId: "utok-2"},
	} {
		if got := listed(t, fx.s, a, fx.personal); len(got) != 0 {
			t.Fatalf("%s: listed %v from carol's personal folder", name, got)
		}
		if _, err := fx.s.GetSecret(context.Background(), &vaultv1.GetSecretRequest{Actor: a, Id: fx.carols}); code(err) != codes.NotFound {
			t.Fatalf("%s: GetSecret = %v, want NotFound", name, err)
		}
	}
	if got := listed(t, fx.s, &vaultv1.ActorContext{UserId: "user-carol"}, fx.personal); !got[fx.carols] {
		t.Fatalf("owner: %v", got)
	}
}

func TestGetSecretFollowsTheSameVisibility(t *testing.T) {
	fx := newListFixture(t)
	ctx := context.Background()
	bob := &vaultv1.ActorContext{UserId: "user-bob"}
	got, err := fx.s.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: bob, Id: fx.open})
	if err != nil || got.GetSecret().GetCanRead() {
		t.Fatalf("open secret for bob: %v %v, want metadata, locked", got, err)
	}
	if _, err := fx.s.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: bob, Id: fx.denied}); code(err) != codes.NotFound {
		t.Fatalf("denied secret for bob: %v, want NotFound", err)
	}
	if ev := fx.ca.find("secret.read.denied"); ev == nil || ev.ActorUserID != "user-bob" || ev.Subject != fx.denied {
		t.Fatalf("audit = %+v", ev)
	}
	// The workflow reads as its own root actor (the vault fills it in for a
	// self caller).
	wf := &vaultv1.ActorContext{UserId: "system:workflow", IsRoot: true}
	if got, err := fx.s.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: wf, Id: fx.denied}); err != nil || !got.GetSecret().GetCanRead() {
		t.Fatalf("workflow: %v %v", got, err)
	}
}
