// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// newServerWithVersions builds a mem-backed Server (random KEK) but attaches a
// pool-backed version store, so create/update version-write wiring can be
// exercised against the real secret_versions table.
func newServerWithVersions(t *testing.T) *Server {
	t.Helper()
	s := newServer(t)
	s.vers = newVersionStore(verTestPool(t))
	return s
}

func TestCreateSecretAppendsActiveVersion(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "db creds", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	sid := created.GetSecret().GetId()

	rec, ok, err := s.vers.ActiveRecord(ctx, sid)
	if err != nil || !ok {
		t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
	}
	pw, err := s.crypt.Open(rec, "password")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pw != "Sup3r$ecret" {
		t.Fatalf("active version password = %q", pw)
	}
}

func TestUpdateSecretAppendsNewVersionRetainingOld(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
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

	// Active version now decrypts to the new value.
	rec, ok, err := s.vers.ActiveRecord(ctx, sid)
	if err != nil || !ok {
		t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
	}
	pw, err := s.crypt.Open(rec, "password")
	if err != nil || pw != "new-pw" {
		t.Fatalf("active password = %q err=%v", pw, err)
	}

	// Two versions exist; v1 retained inactive.
	var total, active int
	if err := s.vers.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE active) FROM secret_versions WHERE secret_id=$1`, sid).Scan(&total, &active); err != nil {
		t.Fatal(err)
	}
	if total != 2 || active != 1 {
		t.Fatalf("versions total=%d active=%d, want 2/1", total, active)
	}
}

// TestCreateSecretNoVersionStoreOK guards the nil-store path: mem-only servers
// (no pool) must still create secrets, so existing tests stay green.
func TestCreateSecretNoVersionStoreOK(t *testing.T) {
	s := newServer(t) // s.vers is nil
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	if _, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Name: "x", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	}); err != nil {
		t.Fatalf("CreateSecret without version store: %v", err)
	}
}

func TestDeleteSecretRemovesItsVersionHistory(t *testing.T) {
	s := newServerWithVersions(t)
	ctx := context.Background()
	fid := newSharedFolder(t, s)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	keep, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "keep", FolderId: fid, TypeId: "type-password", Fields: map[string]string{"password": "k"},
	})
	if err != nil {
		t.Fatalf("CreateSecret keep: %v", err)
	}
	gone, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "gone", FolderId: fid, TypeId: "type-password", Fields: map[string]string{"password": "old"},
	})
	if err != nil {
		t.Fatalf("CreateSecret gone: %v", err)
	}
	sid := gone.GetSecret().GetId()
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: sid, Fields: map[string]string{"password": "new"}}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}

	if _, err := s.DeleteSecret(ctx, &vaultv1.DeleteSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	if vs, err := s.vers.List(ctx, sid, s.crypt); err != nil || len(vs) != 0 {
		t.Fatalf("deleted secret still has %d versions (err=%v)", len(vs), err)
	}
	if vs, err := s.vers.List(ctx, keep.GetSecret().GetId(), s.crypt); err != nil || len(vs) != 1 {
		t.Fatalf("other secret's history touched: %d versions (err=%v)", len(vs), err)
	}
}
