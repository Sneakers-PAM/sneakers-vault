// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
)

func TestSeedIncludesSSHKeyType(t *testing.T) {
	s := newServer(t)
	resp, err := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	var ssh *vaultv1.SecretType
	for _, ty := range resp.GetTypes() {
		if ty.GetId() == "type-ssh-key" {
			ssh = ty
		}
	}
	if ssh == nil {
		t.Fatal("type-ssh-key not seeded")
	}
	if ssh.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
		t.Errorf("origin = %v, want SYSTEM", ssh.GetOrigin())
	}
	if !ssh.GetHeartbeat() || !ssh.GetCheckout() {
		t.Errorf("heartbeat=%v checkout=%v, want both true", ssh.GetHeartbeat(), ssh.GetCheckout())
	}
	want := map[string]struct {
		kind      vaultv1.FieldKind
		sensitive bool
		required  bool
	}{
		"username":   {vaultv1.FieldKind_FIELD_KIND_TEXT, false, true},
		"keyFormat":  {vaultv1.FieldKind_FIELD_KIND_SELECT, false, true},
		"publicKey":  {vaultv1.FieldKind_FIELD_KIND_MULTILINE, false, false},
		"privateKey": {vaultv1.FieldKind_FIELD_KIND_SENSITIVE, true, true},
		"passphrase": {vaultv1.FieldKind_FIELD_KIND_SENSITIVE, true, false},
		"notes":      {vaultv1.FieldKind_FIELD_KIND_MULTILINE, false, false},
	}
	got := map[string]*vaultv1.SecretFieldDef{}
	for _, f := range ssh.GetFields() {
		got[f.GetKey()] = f
	}
	for k, w := range want {
		f := got[k]
		if f == nil {
			t.Errorf("missing field %q", k)
			continue
		}
		if f.GetKind() != w.kind {
			t.Errorf("%s.kind = %v, want %v", k, f.GetKind(), w.kind)
		}
		if f.GetSensitive() != w.sensitive {
			t.Errorf("%s.sensitive = %v, want %v", k, f.GetSensitive(), w.sensitive)
		}
		if f.GetRequired() != w.required {
			t.Errorf("%s.required = %v, want %v", k, f.GetRequired(), w.required)
		}
	}
	kf := got["keyFormat"]
	if kf != nil && kf.GetDefaultValue() != "Ed25519" {
		t.Errorf("keyFormat default = %q, want Ed25519", kf.GetDefaultValue())
	}
}

// createScheduledSSHSecret mirrors createLifecycleSecret (vault_test.go): a
// shared folder owned by user-carol plus one secret in it. It differs in two
// ways needed for a heartbeat reveal of an ssh-key secret: the secret is
// type-ssh-key with synthetic key-material fields, and the server is wired to
// a real heartbeat store (backed by TEST_DATABASE_DSN, same as
// heartbeat_store_test.go/rotation_test.go's DB-backed tests), and given a
// reachable target (heartbeats are only scheduled with one), *before*
// CreateSecret runs, so CreateSecret's existing auto-enroll of
// heartbeat-capable types (secrets.go) inserts the schedule row itself —
// exactly the path a real type-ssh-key secret goes through in production.
// That makes s.heartbeatScheduled(ctx, secretID) true without needing a
// separate, ssh-specific scheduling call.
func createScheduledSSHSecret(t *testing.T, s *Server) (actor *vaultv1.ActorContext, secretID string) {
	t.Helper()
	s.hb = newHeartbeatStore(hbTestPool(t).Querier())
	actor = &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: actor, Name: "deploy key", FolderId: fid, TypeId: "type-ssh-key", TargetId: tgt,
		Fields: map[string]string{
			"username":   "svc-deploy",
			"privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC\n-----END OPENSSH PRIVATE KEY-----", // gitleaks:allow -- a synthetic placeholder, not a key
			"passphrase": "",
		},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return actor, created.GetSecret().GetId()
}

func TestRevealForHeartbeatReturnsSSHKeyMaterial(t *testing.T) {
	s := newServer(t)
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}
	ctx := context.Background()

	_, sid := createScheduledSSHSecret(t, s) // typeId type-ssh-key, scheduled for heartbeat

	resp, err := s.RevealForHeartbeat(ctx, &vaultv1.RevealForHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "any"}, SecretId: sid,
	})
	if err != nil {
		t.Fatalf("RevealForHeartbeat: %v", err)
	}
	if resp.GetUsername() == "" {
		t.Error("username empty, want the ssh account name")
	}
	if resp.GetPrivateKey() == "" {
		t.Error("private_key empty, want the ssh private key")
	}
	if resp.GetPassword() != "" {
		t.Errorf("password = %q, want empty for an ssh key secret", resp.GetPassword())
	}
}
