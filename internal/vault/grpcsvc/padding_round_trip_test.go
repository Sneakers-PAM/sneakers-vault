// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strconv"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// paddedValues are values whose trailing "=" (base64 padding) must come back
// byte for byte, including one with an embedded newline between the "=".
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

var (
	padHuman = &vaultv1.ActorContext{UserId: "user-carol"}
	padSA    = &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-pad"}
)

func padFolder(t *testing.T, s *Server) string {
	t.Helper()
	fid := newSharedFolder(t, s)
	if _, err := s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: padHuman, FolderId: fid, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-pad",
			Grants: map[string]string{"C": "allow", "R": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	return fid
}

// assertRevealsExactly checks both reveal paths return want byte for byte.
func assertRevealsExactly(t *testing.T, s *Server, id, field, want string) {
	t.Helper()
	ctx := context.Background()
	h, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: padHuman, Id: id, FieldKey: field})
	if err != nil {
		t.Fatalf("RevealSecretField: %v", err)
	}
	if h.GetValue() != want {
		t.Fatalf("RevealSecretField = %s, want %s", strconv.Quote(h.GetValue()), strconv.Quote(want))
	}
	p, err := s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: padSA, Id: id, FieldKey: field})
	if err != nil {
		t.Fatalf("RevealSecretFieldForPrincipal: %v", err)
	}
	if p.GetValue() != want {
		t.Fatalf("RevealSecretFieldForPrincipal = %s, want %s", strconv.Quote(p.GetValue()), strconv.Quote(want))
	}
}

func TestPaddingSurvivesHumanCreate(t *testing.T) {
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			s := newServer(t)
			c, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
				Actor: padHuman, Name: "api", FolderId: padFolder(t, s), TypeId: "type-api-token",
				Fields: map[string]string{"token": v},
			})
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			assertRevealsExactly(t, s, c.GetSecret().GetId(), "token", v)
		})
	}
}

func TestPaddingSurvivesPrincipalCreate(t *testing.T) {
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			s := newServer(t)
			c, err := s.CreateSecretForPrincipal(context.Background(), &vaultv1.CreateSecretForPrincipalRequest{
				Actor: padSA, Name: "api", FolderId: padFolder(t, s), TypeId: "type-api-token",
				Fields: map[string]string{"token": v},
			})
			if err != nil {
				t.Fatalf("CreateSecretForPrincipal: %v", err)
			}
			assertRevealsExactly(t, s, c.GetSecret().GetId(), "token", v)
		})
	}
}

func TestPaddingSurvivesPrincipalGenerate(t *testing.T) {
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			s := newServer(t)
			addType(s, &vaultv1.SecretType{Id: "type-pad-generate", Name: "Password plus API key", Fields: []*vaultv1.SecretFieldDef{
				{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
				{Key: "apiKey", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true},
			}})
			g, err := s.GenerateSecretForPrincipal(context.Background(), &vaultv1.GenerateSecretForPrincipalRequest{
				Actor: padSA, Name: "gen", FolderId: padFolder(t, s), TypeId: "type-pad-generate",
				Fields: map[string]string{"apiKey": v},
			})
			if err != nil {
				t.Fatalf("GenerateSecretForPrincipal: %v", err)
			}
			assertRevealsExactly(t, s, g.GetSecret().GetId(), "apiKey", v)
		})
	}
}

func TestPaddingSurvivesUpdates(t *testing.T) {
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			s := newServer(t)
			ctx := context.Background()
			fid := padFolder(t, s)
			c, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
				Actor: padHuman, Name: "api", FolderId: fid, TypeId: "type-api-token",
				Fields: map[string]string{"token": "seed"},
			})
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			id := c.GetSecret().GetId()
			if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
				Actor: padHuman, Id: id, Fields: map[string]string{"token": v},
			}); err != nil {
				t.Fatalf("UpdateSecret: %v", err)
			}
			assertRevealsExactly(t, s, id, "token", v)

			if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{
				Actor: padHuman, Id: id, Fields: map[string]string{"token": "seed"},
			}); err != nil {
				t.Fatalf("UpdateSecret reset: %v", err)
			}
			if _, err := s.UpdateSecretFieldsForPrincipal(ctx, &vaultv1.UpdateSecretFieldsForPrincipalRequest{
				Actor: padSA, Id: id, Fields: map[string]string{"token": v},
			}); err != nil {
				t.Fatalf("UpdateSecretFieldsForPrincipal: %v", err)
			}
			assertRevealsExactly(t, s, id, "token", v)
		})
	}
}

func TestPaddingSurvivesPostgresReload(t *testing.T) {
	ctx := context.Background()
	p := lostWritePool(t)
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			for _, tbl := range stateTables {
				if _, err := p.Querier().Exec(ctx, "TRUNCATE "+tbl); err != nil {
					t.Fatalf("truncate %s: %v", tbl, err)
				}
			}
			a, err := NewWithStore(ctx, NewPGStore(p), crypto.New(kek), nil, "dev")
			if err != nil {
				t.Fatalf("NewWithStore: %v", err)
			}
			fid := viaInterceptor(ctx, t, a, "CreateFolder", func() (any, error) {
				return a.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: padHuman, Name: "pad"})
			}).(*vaultv1.CreateFolderResponse).GetFolder().GetId()
			viaInterceptor(ctx, t, a, "SetFolderRuleset", func() (any, error) {
				return a.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
					Actor: padHuman, FolderId: fid, Owners: []string{"user-carol"},
					Rules: []*vaultv1.RaciRule{{
						SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-pad",
						Grants: map[string]string{"C": "allow", "R": "allow"},
					}},
				})
			})
			human := viaInterceptor(ctx, t, a, "CreateSecret", func() (any, error) {
				return a.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
					Actor: padHuman, Name: "human", FolderId: fid, TypeId: "type-api-token",
					Fields: map[string]string{"token": v},
				})
			}).(*vaultv1.CreateSecretResponse).GetSecret().GetId()
			machine := viaInterceptor(ctx, t, a, "CreateSecretForPrincipal", func() (any, error) {
				return a.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
					Actor: padSA, Name: "machine", FolderId: fid, TypeId: "type-api-token",
					Fields: map[string]string{"token": v},
				})
			}).(*vaultv1.CreateSecretForPrincipalResponse).GetSecret().GetId()

			b, err := NewWithStore(ctx, NewPGStore(lostWritePool(t)), crypto.New(kek), nil, "dev")
			if err != nil {
				t.Fatalf("fresh NewWithStore: %v", err)
			}
			assertRevealsExactly(t, b, human, "token", v)
			assertRevealsExactly(t, b, machine, "token", v)
		})
	}
}

func TestPaddingSurvivesTheVersionLedger(t *testing.T) {
	for _, v := range paddedValues {
		t.Run(strconv.Quote(v), func(t *testing.T) {
			s := newServerWithVersions(t)
			ctx := context.Background()
			fid := padFolder(t, s)
			activeToken := func(id string) string {
				t.Helper()
				rec, ok, err := s.vers.ActiveRecord(ctx, id)
				if err != nil || !ok {
					t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
				}
				got, err := s.crypt.Open(rec, "token")
				if err != nil {
					t.Fatalf("open version: %v", err)
				}
				return got
			}

			c, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
				Actor: padHuman, Name: "api", FolderId: fid, TypeId: "type-api-token",
				Fields: map[string]string{"token": v},
			})
			if err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
			if got := activeToken(c.GetSecret().GetId()); got != v {
				t.Fatalf("ledger after CreateSecret = %s, want %s", strconv.Quote(got), strconv.Quote(v))
			}

			pc, err := s.CreateSecretForPrincipal(ctx, &vaultv1.CreateSecretForPrincipalRequest{
				Actor: padSA, Name: "machine", FolderId: fid, TypeId: "type-api-token",
				Fields: map[string]string{"token": "seed"},
			})
			if err != nil {
				t.Fatalf("CreateSecretForPrincipal: %v", err)
			}
			id := pc.GetSecret().GetId()
			if _, err := s.UpdateSecretFieldsForPrincipal(ctx, &vaultv1.UpdateSecretFieldsForPrincipalRequest{
				Actor: padSA, Id: id, Fields: map[string]string{"token": v},
			}); err != nil {
				t.Fatalf("UpdateSecretFieldsForPrincipal: %v", err)
			}
			if got := activeToken(id); got != v {
				t.Fatalf("ledger after principal update = %s, want %s", strconv.Quote(got), strconv.Quote(v))
			}
		})
	}
}
