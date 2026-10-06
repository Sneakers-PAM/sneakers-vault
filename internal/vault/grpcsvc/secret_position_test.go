// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A secret has a manual, 1-based, dense position among its folder's active
// secrets. New, moved-in and restored secrets go last; retire, delete and
// move-out close the gap; ReorderSecrets sets the whole order.

var posCarol = &vaultv1.ActorContext{UserId: "user-carol"}

func posSecret(t *testing.T, s *Server, folderID, name string) string {
	t.Helper()
	c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: posCarol, Name: name, FolderId: folderID, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "Str0ng!Passw0rd-1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret(%s): %v", name, err)
	}
	return c.GetSecret().GetId()
}

// listOrder returns the folder's active secret names in listing order and
// fails unless their positions are exactly 1..n in that order.
func listOrder(t *testing.T, s *Server, folderID string) []string {
	t.Helper()
	resp, err := s.ListSecretsInFolder(context.Background(), &vaultv1.ListSecretsInFolderRequest{Actor: posCarol, FolderId: folderID})
	if err != nil {
		t.Fatalf("ListSecretsInFolder: %v", err)
	}
	var names []string
	for i, sec := range resp.GetSecrets() {
		if sec.GetPosition() != int32(i+1) {
			t.Fatalf("%s at index %d has position %d, want %d", sec.GetName(), i, sec.GetPosition(), i+1)
		}
		names = append(names, sec.GetName())
	}
	return names
}

func wantOrder(t *testing.T, s *Server, folderID string, want ...string) {
	t.Helper()
	if got := listOrder(t, s, folderID); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestCreateSecretAppendsLast(t *testing.T) {
	s := newServer(t)
	f := mutFolder(t, s, "Ops")
	posSecret(t, s, f, "charlie")
	posSecret(t, s, f, "alpha")
	posSecret(t, s, f, "bravo")
	wantOrder(t, s, f, "charlie", "alpha", "bravo")
}

func TestReorderSecretsSetsOrder(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := mutFolder(t, s, "Ops")
	a, b, c := posSecret(t, s, f, "a"), posSecret(t, s, f, "b"), posSecret(t, s, f, "c")
	resp, err := s.ReorderSecrets(context.Background(), &vaultv1.ReorderSecretsRequest{Actor: posCarol, FolderId: f, OrderedIds: []string{c, a, b}})
	if err != nil {
		t.Fatalf("ReorderSecrets: %v", err)
	}
	if len(resp.GetSecrets()) != 3 || resp.GetSecrets()[0].GetId() != c || resp.GetSecrets()[0].GetPosition() != 1 {
		t.Fatalf("response = %v, want the folder in the new order", resp.GetSecrets())
	}
	wantOrder(t, s, f, "c", "a", "b")
	ev := ca.find("secret.reorder")
	if ev == nil || ev.Subject != f || ev.ActorUserID != "user-carol" {
		t.Fatalf("expected a secret.reorder audit on the folder, got %+v", ev)
	}
}

func TestReorderSecretsRejectsAMismatchedSet(t *testing.T) {
	s := newServer(t)
	f, other := mutFolder(t, s, "Ops"), mutFolder(t, s, "Other")
	a, b, c := posSecret(t, s, f, "a"), posSecret(t, s, f, "b"), posSecret(t, s, f, "c")
	x := posSecret(t, s, other, "x")
	r := posSecret(t, s, f, "retired")
	if _, err := s.RetireSecret(context.Background(), &vaultv1.RetireSecretRequest{Actor: posCarol, Id: r}); err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string][]string{
		"missing one":      {a, b},
		"duplicate":        {a, b, b, c},
		"other folder":     {a, b, c, x},
		"retired secret":   {a, b, c, r},
		"unknown id":       {a, b, c, "secret-nope"},
		"empty":            nil,
		"duplicate swap":   {a, a, c},
		"other folder sub": {a, b, x},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.ReorderSecrets(context.Background(), &vaultv1.ReorderSecretsRequest{Actor: posCarol, FolderId: f, OrderedIds: ids})
			if code(err) != codes.InvalidArgument {
				t.Fatalf("err %v, want InvalidArgument", err)
			}
			wantOrder(t, s, f, "a", "b", "c")
		})
	}
}

func TestReorderSecretsNeedsAuthor(t *testing.T) {
	s := newServer(t)
	f := mutFolder(t, s, "Ops")
	a, b := posSecret(t, s, f, "a"), posSecret(t, s, f, "b")
	_, err := s.ReorderSecrets(context.Background(), &vaultv1.ReorderSecretsRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-bob"}, FolderId: f, OrderedIds: []string{b, a},
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("err %v, want PermissionDenied", err)
	}
	wantOrder(t, s, f, "a", "b")
	if _, err := s.ReorderSecrets(context.Background(), &vaultv1.ReorderSecretsRequest{Actor: posCarol, FolderId: "folder-nope", OrderedIds: []string{a}}); code(err) != codes.NotFound {
		t.Fatalf("unknown folder: err %v, want NotFound", err)
	}
}

func TestRetireRestoreDeleteKeepPositionsDense(t *testing.T) {
	s := newServer(t)
	f := mutFolder(t, s, "Ops")
	a := posSecret(t, s, f, "a")
	b := posSecret(t, s, f, "b")
	posSecret(t, s, f, "c")
	ctx := context.Background()
	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: posCarol, Id: a}); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, s, f, "b", "c")
	if got := s.findSecret(a).GetPosition(); got != 0 {
		t.Fatalf("retired secret position = %d, want 0", got)
	}
	if _, err := s.RestoreSecret(ctx, &vaultv1.RestoreSecretRequest{Actor: posCarol, Id: a}); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, s, f, "b", "c", "a")
	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: posCarol, Id: b}); err != nil {
		t.Fatal(err)
	}
	wantOrder(t, s, f, "c", "a")
}

func TestListWithRetiredPutsRetiredLast(t *testing.T) {
	s := newServer(t)
	f := mutFolder(t, s, "Ops")
	a := posSecret(t, s, f, "a")
	posSecret(t, s, f, "b")
	if _, err := s.RetireSecret(context.Background(), &vaultv1.RetireSecretRequest{Actor: posCarol, Id: a}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSecretsInFolder(context.Background(), &vaultv1.ListSecretsInFolderRequest{Actor: posCarol, FolderId: f, IncludeRetired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetSecrets()) != 2 || resp.GetSecrets()[0].GetName() != "b" || resp.GetSecrets()[1].GetName() != "a" {
		t.Fatalf("list = %v, want b then the retired a", resp.GetSecrets())
	}
}

func TestMovesKeepPositionsDense(t *testing.T) {
	s := newServer(t)
	src, dst := mutFolder(t, s, "Src"), mutFolder(t, s, "Dst")
	grantGroup(t, s, posCarol, src, "R")
	grantGroup(t, s, posCarol, dst, "R")
	a := posSecret(t, s, src, "a")
	b := posSecret(t, s, src, "b")
	posSecret(t, s, src, "c")
	posSecret(t, s, dst, "x")
	ctx := context.Background()

	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: posCarol, Id: a, DestFolderId: dst}); err != nil {
		t.Fatalf("UpdateSecret move: %v", err)
	}
	wantOrder(t, s, src, "b", "c")
	wantOrder(t, s, dst, "x", "a")

	if _, err := s.MoveSecretForPrincipal(ctx, &vaultv1.MoveSecretForPrincipalRequest{Actor: agentGroupActor("sa-1"), Id: b, DestFolderId: dst}); err != nil {
		t.Fatalf("MoveSecretForPrincipal: %v", err)
	}
	wantOrder(t, s, src, "c")
	wantOrder(t, s, dst, "x", "a", "b")

	// An edit that doesn't move keeps the place.
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: posCarol, Id: a, Name: "a2"}); err != nil {
		t.Fatalf("UpdateSecret rename: %v", err)
	}
	wantOrder(t, s, dst, "x", "a2", "b")
}

func TestDeleteFolderReassignAppendsMovedSecrets(t *testing.T) {
	s := newServer(t)
	gone, keep := mutFolder(t, s, "Gone"), mutFolder(t, s, "Keep")
	posSecret(t, s, keep, "k1")
	posSecret(t, s, gone, "g1")
	posSecret(t, s, gone, "g2")
	if _, err := s.DeleteFolder(context.Background(), &vaultv1.DeleteFolderRequest{Actor: posCarol, Id: gone, ReassignToId: keep}); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	wantOrder(t, s, keep, "k1", "g1", "g2")
}

func TestReorderSecretsPersists(t *testing.T) {
	if !mutatingMethods["ReorderSecrets"] {
		t.Fatal("ReorderSecrets must persist its change")
	}
}
