// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
)

// organizeFreshDB creates an isolated database on the TEST_DATABASE_DSN server,
// applies the repo migrations, and returns a pool on it (dropped on cleanup).
func organizeFreshDB(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_DSN")
	if base == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "organize_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	dsn := u.String()
	if err := postgres.Migrate(dsn, "../../../migrations/vault"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	return dsn, pool
}

// callPersisted runs one handler through PersistUnary, exactly as the gRPC
// server does, so a verb missing from mutatingMethods would not survive the
// reload below.
func callPersisted[Req, Resp any](t *testing.T, s *Server, method string, req Req, h func(context.Context, Req) (Resp, error)) Resp {
	t.Helper()
	out, err := s.PersistUnary(context.Background(), req, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/" + method},
		func(ctx context.Context, r any) (any, error) { return h(ctx, r.(Req)) })
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return out.(Resp)
}

// Real Postgres 17: every organize verb persists through the snapshot store
// and a restarted vault sees the same tree, names and sealed values, with the
// prior field values kept in secret_versions.
func TestOrganizeVerbs_PersistAcrossRestart_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	s, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	s.SetRotation(pool, nil)

	sa := agentGroupActor("sa-pg")
	top := callPersisted(t, s, "CreateFolder", &vaultv1.CreateFolderRequest{Actor: orgCarol, Name: "Platform"}, s.CreateFolder).GetFolder().GetId()
	dst := callPersisted(t, s, "CreateFolder", &vaultv1.CreateFolderRequest{Actor: orgCarol, Name: "Archive"}, s.CreateFolder).GetFolder().GetId()
	for _, f := range []string{top, dst} {
		callPersisted(t, s, "SetFolderRuleset", &vaultv1.SetFolderRulesetRequest{
			Actor: orgCarol, FolderId: f, Owners: []string{"user-carol"},
			Rules: []*vaultv1.RaciRule{{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: map[string]string{"R": "allow"}}},
		}, s.SetFolderRuleset)
	}
	sec := callPersisted(t, s, "CreateSecret", &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "svc", FolderId: top, TypeId: "type-password",
		Fields: map[string]string{"username": mutUser, "password": mutPass},
	}, s.CreateSecret).GetSecret().GetId()

	sub := callPersisted(t, s, "CreateFolderForPrincipal", &vaultv1.CreateFolderForPrincipalRequest{Actor: sa, ParentId: top, Name: "Databases"}, s.CreateFolderForPrincipal).GetFolder().GetId()
	callPersisted(t, s, "RenameFolderForPrincipal", &vaultv1.RenameFolderForPrincipalRequest{Actor: sa, Id: sub, Name: "DBs"}, s.RenameFolderForPrincipal)
	callPersisted(t, s, "MoveFolderForPrincipal", &vaultv1.MoveFolderForPrincipalRequest{Actor: sa, Id: sub, NewParentId: dst}, s.MoveFolderForPrincipal)
	callPersisted(t, s, "RenameSecretForPrincipal", &vaultv1.RenameSecretForPrincipalRequest{Actor: sa, Id: sec, Name: "svc-renamed"}, s.RenameSecretForPrincipal)
	callPersisted(t, s, "UpdateSecretFieldsForPrincipal", &vaultv1.UpdateSecretFieldsForPrincipalRequest{
		Actor: sa, Id: sec, Fields: map[string]string{"password": "Rotated-By-Agent-1!", "notes": "moved by agent"},
	}, s.UpdateSecretFieldsForPrincipal)

	// "Restart": a brand-new server hydrated from the same database.
	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "qa")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	s2.SetRotation(pool, nil)
	f := s2.findFolder(sub)
	if f == nil || f.GetName() != "DBs" || f.GetParentId() != dst {
		t.Fatalf("folder after restart = %+v", f)
	}
	if got := s2.findSecret(sec).GetName(); got != "svc-renamed" {
		t.Fatalf("secret name after restart = %q", got)
	}
	vals, err := s2.crypt.OpenAll(s2.records[sec])
	if err != nil || vals["password"] != "Rotated-By-Agent-1!" || vals["notes"] != "moved by agent" || vals["username"] != mutUser {
		t.Fatalf("values after restart wrong (err=%v keys=%v)", err, sortedKeys(vals))
	}
	vs, err := s2.vers.List(ctx, sec, s2.crypt)
	if err != nil || len(vs) != 2 {
		t.Fatalf("versions = %d (err=%v), want 2", len(vs), err)
	}
	listed, err := s2.ListFoldersForPrincipal(ctx, &vaultv1.ListFoldersForPrincipalRequest{Actor: sa})
	if err != nil {
		t.Fatal(err)
	}
	if got := orgFolderIDs(listed.GetFolders()); got[sub] == nil || got[top] == nil || got[dst] == nil {
		t.Fatalf("principal listing after restart = %v", got)
	}
}
