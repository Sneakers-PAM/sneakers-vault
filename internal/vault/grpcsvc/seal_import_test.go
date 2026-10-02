// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SealForImport is for the sneakers-migrate Job only: the workload-auth grant
// must name the migrate caller, whatever actor a request carries.

func grantCtx(caller string, access workloadauth.Access) context.Context {
	return workloadauth.ContextWithGrant(context.Background(), workloadauth.Grant{
		Caller: workloadauth.Caller{Name: caller, ServiceAccount: "sneakers/sneakers-" + caller}, Access: access,
	})
}

// sealAs runs SealForImport behind SelfActorUnary, as the server does.
func sealAs(s *Server, ctx context.Context, req *vaultv1.SealForImportRequest) (*vaultv1.SealForImportResponse, error) {
	info := &grpc.UnaryServerInfo{FullMethod: vaultv1.VaultService_SealForImport_FullMethodName}
	resp, err := s.SelfActorUnary(ctx, req, info, func(ctx context.Context, r any) (any, error) {
		return s.SealForImport(ctx, r.(*vaultv1.SealForImportRequest))
	})
	if err != nil {
		return nil, err
	}
	return resp.(*vaultv1.SealForImportResponse), nil
}

func TestSealForImport_SealsUnderActiveKeyAndStoresNothing(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	items := []map[string]string{
		{"username": "svc-backup", "password": "Imported-1"},
		{"password": "Imported-2", "note": ""},
	}
	req := &vaultv1.SealForImportRequest{}
	for _, f := range items {
		req.Items = append(req.Items, &vaultv1.SealForImportItem{Fields: f})
	}
	resp, err := sealAs(fx.s, grantCtx(CallerMigrate, workloadauth.Self), req)
	if err != nil {
		t.Fatalf("SealForImport: %v", err)
	}
	if len(resp.GetRecords()) != len(items) {
		t.Fatalf("records = %d, want %d", len(resp.GetRecords()), len(items))
	}
	for i, raw := range resp.GetRecords() {
		var rec crypto.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatalf("record %d: decode: %v", i, err)
		}
		if rec.KeyRef != "kek-v1" {
			t.Fatalf("record %d KeyRef = %q, want the active kek-v1", i, rec.KeyRef)
		}
		got, err := fx.s.crypt.OpenAll(rec)
		if err != nil {
			t.Fatalf("record %d: open: %v", i, err)
		}
		if len(got) != len(items[i]) {
			t.Fatalf("record %d fields = %v, want %v", i, got, items[i])
		}
		for k, v := range items[i] {
			if got[k] != v {
				t.Fatalf("record %d field %s does not round-trip", i, k)
			}
		}
		if strings.Contains(string(raw), "Imported-") {
			t.Fatalf("record %d carries a plaintext value", i)
		}
	}
	if len(fx.s.records) != 0 || len(fx.s.secrets) != 0 {
		t.Fatalf("SealForImport stored state: %d records, %d secrets", len(fx.s.records), len(fx.s.secrets))
	}
	ev := auditor.find("vault.import.seal")
	if ev == nil {
		t.Fatal("no vault.import.seal audit event")
	}
	if ev.ActorUserID != "system:migrate" || ev.Attributes["items"] != "2" {
		t.Fatalf("audit event = %+v, want actor system:migrate and items=2", ev)
	}
	for _, v := range ev.Attributes {
		if strings.Contains(v, "Imported-") {
			t.Fatal("audit attributes carry a value")
		}
	}
}

func TestSealForImport_OnlyTheMigrateCaller(t *testing.T) {
	one := []*vaultv1.SealForImportItem{{Fields: map[string]string{"password": "x"}}}
	fx := newRotateTestServer(t, nil)
	root := &vaultv1.ActorContext{UserId: "system:migrate", IsRoot: true, IsSiteAdmin: true}
	workload := &vaultv1.ActorContext{UserId: "system:migrate", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD}
	for name, c := range map[string]struct {
		ctx   context.Context
		actor *vaultv1.ActorContext
	}{
		"no grant (auth disabled), root actor":     {context.Background(), root},
		"no grant (auth disabled), workload actor": {context.Background(), workload},
		"gateway on behalf of a root admin":        {grantCtx(CallerGateway, workloadauth.OnBehalf), root},
		"workflow as itself":                       {grantCtx(CallerWorkflow, workloadauth.Self), nil},
		"connector as itself":                      {grantCtx(CallerConnector, workloadauth.Self), nil},
	} {
		_, err := sealAs(fx.s, c.ctx, &vaultv1.SealForImportRequest{Actor: c.actor, Items: one})
		wantDenied(t, err, name)
	}

	migrate := grantCtx(CallerMigrate, workloadauth.Self)
	resp, err := sealAs(fx.s, migrate, &vaultv1.SealForImportRequest{})
	if err != nil || len(resp.GetRecords()) != 0 {
		t.Fatalf("empty batch: got %v, %v; want no records", resp, err)
	}
	big := make([]*vaultv1.SealForImportItem, maxSealForImportItems+1)
	for i := range big {
		big[i] = &vaultv1.SealForImportItem{}
	}
	if _, err := sealAs(fx.s, migrate, &vaultv1.SealForImportRequest{Items: big}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized batch: err = %v, want InvalidArgument", err)
	}
}

// The migrate Job verifies an import by reading back as itself: the vault
// gives it a root actor named for the tool, so it never names a user.
func TestMigrateCallerActsAsSystemMigrate(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	req := &vaultv1.GetSecretRequest{Id: "x"}
	info := &grpc.UnaryServerInfo{FullMethod: vaultv1.VaultService_GetSecret_FullMethodName}
	_, _ = fx.s.SelfActorUnary(grantCtx(CallerMigrate, workloadauth.Self), req, info, func(context.Context, any) (any, error) { return nil, nil })
	if a := req.GetActor(); a.GetUserId() != "system:migrate" || !a.GetIsRoot() {
		t.Fatalf("actor = %+v, want system:migrate root", a)
	}
}
