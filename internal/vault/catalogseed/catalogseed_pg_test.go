// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package catalogseed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"reflect"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

const adTypeID = "type-active-directory"

// freshDB creates an isolated, migrated database on the TEST_DATABASE_DSN server.
func freshDB(t *testing.T) *postgres.DB {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_DSN")
	if base == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	ctx := context.Background()
	admin, err := postgres.New(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "catalog_" + hex.EncodeToString(b)
	if _, err := admin.Querier().Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	if err := postgres.Migrate(u.String(), "../../../migrations/vault"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Querier().Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	return pool
}

func persisted[Req, Resp any](t *testing.T, s *grpcsvc.Server, method string, req Req, h func(context.Context, Req) (Resp, error)) Resp {
	t.Helper()
	out, err := s.PersistUnary(context.Background(), req, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/" + method},
		func(ctx context.Context, r any) (any, error) { return h(ctx, r.(Req)) })
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return out.(Resp)
}

// preNetbiosAD is the Active Directory type as it shipped before the NetBIOS
// field: the current built-in minus that field.
func preNetbiosAD(t *testing.T) *vaultv1.SecretType {
	t.Helper()
	for _, bt := range grpcsvc.BuiltinTypes() {
		if bt.GetId() != adTypeID {
			continue
		}
		var fields []*vaultv1.SecretFieldDef
		for _, f := range bt.GetFields() {
			if f.GetKey() != "netbios" {
				fields = append(fields, f)
			}
		}
		bt.Fields = fields
		return bt
	}
	t.Fatalf("%s not in BuiltinTypes()", adTypeID)
	return nil
}

func adFieldKeys(t *testing.T, s *grpcsvc.Server) []string {
	t.Helper()
	resp, err := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	for _, ty := range resp.GetTypes() {
		if ty.GetId() == adTypeID {
			var keys []string
			for _, f := range ty.GetFields() {
				keys = append(keys, f.GetKey())
			}
			return keys
		}
	}
	t.Fatalf("%s not listed", adTypeID)
	return nil
}

type rowSnapshot struct{ secret, record string }

func secretRows(t *testing.T, pool *postgres.DB, id string) rowSnapshot {
	t.Helper()
	var r rowSnapshot
	if err := pool.Querier().QueryRow(context.Background(), `SELECT data::text FROM secrets WHERE id=$1`, id).Scan(&r.secret); err != nil {
		t.Fatalf("read secrets row: %v", err)
	}
	if err := pool.Querier().QueryRow(context.Background(), `SELECT record::text FROM secret_records WHERE secret_id=$1`, id).Scan(&r.record); err != nil {
		t.Fatalf("read secret_records row: %v", err)
	}
	return r
}

// TestRunUpgradesADWithNetbiosAndKeepsExistingSecrets upgrades a store whose
// Active Directory type predates the NetBIOS field: the upgrade adds the field
// next to the domain and leaves existing AD secrets exactly as they were.
func TestRunUpgradesADWithNetbiosAndKeepsExistingSecrets(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	store := grpcsvc.NewPGStore(pool)
	if _, err := grpcsvc.NewWithStore(ctx, store, env, nil, "dev"); err != nil {
		t.Fatalf("boot: %v", err)
	}
	old, err := protojson.Marshal(preNetbiosAD(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Querier().Exec(ctx, `UPDATE secret_types SET data=$2::jsonb WHERE id=$1`, adTypeID, old); err != nil {
		t.Fatalf("install the pre-upgrade AD type: %v", err)
	}

	s, err := grpcsvc.NewWithStore(ctx, store, env, nil, "dev")
	if err != nil {
		t.Fatalf("boot on the old catalog: %v", err)
	}
	for _, k := range adFieldKeys(t, s) {
		if k == "netbios" {
			t.Fatal("precondition: the old catalog must not have netbios")
		}
	}
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	folder := persisted(t, s, "CreateFolder", &vaultv1.CreateFolderRequest{Actor: carol, Name: "Directory"}, s.CreateFolder)
	values := map[string]string{
		"description": "named admin", "domain": "ad.example.org", "username": "admin_ea",
		"password": "Str0ng!Passw0rd-1", "serviceAccount": "false", "gmsa": "false", "notes": "tier 0",
	}
	created := persisted(t, s, "CreateSecret", &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "admin_ea", FolderId: folder.GetFolder().GetId(), TypeId: adTypeID, Fields: values,
	}, s.CreateSecret)
	id := created.GetSecret().GetId()
	before := secretRows(t, pool, id)

	if err := Run(ctx, pool); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := Run(ctx, pool); err != nil {
		t.Fatalf("Run again: %v", err)
	}

	up, err := grpcsvc.NewWithStore(ctx, store, env, nil, "dev")
	if err != nil {
		t.Fatalf("boot after upgrade: %v", err)
	}
	keys := adFieldKeys(t, up)
	want := []string{"description", "domain", "netbios", "username", "password", "serviceAccount", "gmsa", "notes"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("AD fields after upgrade = %v, want %v", keys, want)
	}

	if after := secretRows(t, pool, id); after != before {
		t.Fatalf("upgrade changed the stored secret:\nbefore %+v\nafter  %+v", before, after)
	}
	got, err := up.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: carol, Id: id})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.GetSecret().GetTypeId() != adTypeID || got.GetSecret().GetName() != "admin_ea" {
		t.Fatalf("secret metadata changed: %+v", got.GetSecret())
	}
	fields, err := up.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: carol, Id: id})
	if err != nil {
		t.Fatalf("GetSecretFields: %v", err)
	}
	for k, v := range values {
		if k == "password" {
			continue
		}
		if fields.GetFields()[k] != v {
			t.Fatalf("field %s = %q after upgrade, want %q", k, fields.GetFields()[k], v)
		}
	}
	if _, ok := fields.GetFields()["netbios"]; ok {
		t.Fatal("an existing secret must not gain a netbios value")
	}
	pw, err := up.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: carol, Id: id, FieldKey: "password"})
	if err != nil {
		t.Fatalf("RevealSecretField: %v", err)
	}
	if pw.GetValue() != values["password"] {
		t.Fatal("password changed across the upgrade")
	}
}
