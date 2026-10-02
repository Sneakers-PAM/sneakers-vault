// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// TestListAndRevealSecretVersions exercises the value-history surface end to
// end: creating then updating a secret leaves two ledger versions (newest
// first, active flag on the current one, field keys but no values), and a prior
// version's field can be revealed to recover the old value — gated by the same
// read access as RevealSecretField. Skips without TEST_DATABASE_DSN.
func TestListAndRevealSecretVersions(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // OWNER of the shared folder
	fid := newSharedFolder(t, s)

	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db creds", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "old-pw"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
		Actor: carol, Id: sid, Fields: map[string]string{"password": "new-pw"},
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}

	list, err := s.ListSecretVersions(ctx, &vaultv1.ListSecretVersionsRequest{Actor: carol, SecretId: sid})
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	vers := list.GetVersions()
	if len(vers) != 2 {
		t.Fatalf("got %d versions, want 2", len(vers))
	}
	// Newest first, active on the current version.
	if vers[0].GetVersionNo() != 2 || !vers[0].GetActive() {
		t.Fatalf("v[0] = no %d active %v, want 2/active", vers[0].GetVersionNo(), vers[0].GetActive())
	}
	if vers[1].GetVersionNo() != 1 || vers[1].GetActive() {
		t.Fatalf("v[1] = no %d active %v, want 1/inactive", vers[1].GetVersionNo(), vers[1].GetActive())
	}
	// Field keys enumerated, no values leaked in the listing.
	if got := len(vers[1].GetFieldKeys()); got != 2 {
		t.Fatalf("v1 field keys = %d, want 2 (username, password)", got)
	}

	// Reveal the OLD password from version 1.
	rev, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: carol, SecretId: sid, VersionNo: 1, FieldKey: "password",
	})
	if err != nil {
		t.Fatalf("RevealSecretVersionField(v1): %v", err)
	}
	if rev.GetValue() != "old-pw" {
		t.Fatalf("v1 password = %q, want old-pw", rev.GetValue())
	}

	// Current version reveals the new value.
	rev2, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: carol, SecretId: sid, VersionNo: 2, FieldKey: "password",
	})
	if err != nil || rev2.GetValue() != "new-pw" {
		t.Fatalf("v2 password = %q err=%v, want new-pw", rev2.GetValue(), err)
	}

	// A user with no grant may neither list nor reveal history.
	nobody := &vaultv1.ActorContext{UserId: "user-nobody"}
	if _, err := s.ListSecretVersions(ctx, &vaultv1.ListSecretVersionsRequest{Actor: nobody, SecretId: sid}); code(err) != codes.PermissionDenied {
		t.Fatalf("list by non-member: want PermissionDenied, got %v", err)
	}
	if _, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: nobody, SecretId: sid, VersionNo: 1, FieldKey: "password",
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("reveal by non-member: want PermissionDenied, got %v", err)
	}

	// A missing version is NotFound.
	if _, err := s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{
		Actor: carol, SecretId: sid, VersionNo: 99, FieldKey: "password",
	}); code(err) != codes.NotFound {
		t.Fatalf("reveal missing version: want NotFound, got %v", err)
	}
}
