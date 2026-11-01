// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	workloadauth "github.com/Bugs5382/go-workload-identity"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func adminToken(clientKind string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-ada", TokenId: "utok-1",
		TokenOwnerIsSiteAdmin: true, TokenClientKind: clientKind,
	}
}

func newExtensionServer(t *testing.T) (*Server, *capAudit) {
	t.Helper()
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	return s, ca
}

func hasSecretType(t *testing.T, s *Server, id string) bool {
	t.Helper()
	types, err := s.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	return containsTypeID(types.GetTypes(), id)
}

func TestImportExtensionForPrincipal_SiteAdminTokenActivatesACataloguedPack(t *testing.T) {
	s, _ := newExtensionServer(t)
	resp, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{
		Actor: adminToken("mcp"), Id: docusignExtID,
	})
	if err != nil {
		t.Fatalf("ImportExtensionForPrincipal: %v", err)
	}
	if resp.GetType().GetId() != docusignExtID || resp.GetType().GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION {
		t.Fatalf("type = %+v", resp.GetType())
	}
	if !hasSecretType(t, s, docusignExtID) {
		t.Fatal("the pack was not installed")
	}
	avail, err := s.ListAvailableExtensions(context.Background(), &vaultv1.ListAvailableExtensionsRequest{})
	if err != nil {
		t.Fatalf("ListAvailableExtensions: %v", err)
	}
	if containsTypeID(avail.GetExtensions(), docusignExtID) {
		t.Fatal("an installed pack is still offered")
	}
}

// The record names the person, the pack and the MCP, in the tamper-evident tier.
func TestImportExtensionForPrincipal_AuditsThePersonThePackAndTheSource(t *testing.T) {
	s, ca := newExtensionServer(t)
	if _, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{
		Actor: adminToken("mcp"), Id: docusignExtID,
	}); err != nil {
		t.Fatalf("ImportExtensionForPrincipal: %v", err)
	}
	ev := ca.find("extension.import.principal")
	if ev == nil {
		t.Fatal("no extension.import.principal event")
	}
	if ev.Tier != audit.TierAudit || ev.ActorUserID != "user-ada" || ev.Subject != docusignExtID || ev.Sensitive {
		t.Fatalf("event = %+v", ev)
	}
	for k, want := range map[string]string{
		"source": "mcp", "token_id": "utok-1", "principal_kind": "PRINCIPAL_KIND_USER_TOKEN",
	} {
		if got := ev.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}
	if ca.find("extension.import") != nil {
		t.Fatal("a token's import must not also read as a person's")
	}
}

// Only an MCP agent token reads as the MCP; a script's token doesn't.
func TestImportExtensionForPrincipal_AnotherClientReadsAsTheMachineAPI(t *testing.T) {
	for _, kind := range []string{"", "cli"} {
		s, ca := newExtensionServer(t)
		if _, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{
			Actor: adminToken(kind), Id: docusignExtID,
		}); err != nil {
			t.Fatalf("kind %q: %v", kind, err)
		}
		if got := ca.find("extension.import.principal").Attributes["source"]; got != "machine_api" {
			t.Errorf("kind %q: source = %q", kind, got)
		}
	}
}

// With no record there's no activation, so the audit log can't miss one.
func TestImportExtensionForPrincipal_AuditFailureInstallsNothing(t *testing.T) {
	s := newServer(t)
	s.audit = failAudit{}
	_, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{
		Actor: adminToken("mcp"), Id: docusignExtID,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v, want Internal", err)
	}
	if hasSecretType(t, s, docusignExtID) {
		t.Fatal("the pack was installed with no audit record")
	}
}

func TestImportExtensionForPrincipal_RefusesEveryoneElse(t *testing.T) {
	plainToken := adminToken("mcp")
	plainToken.TokenOwnerIsSiteAdmin = false
	noUser := adminToken("mcp")
	noUser.UserId = ""
	for name, actor := range map[string]*vaultv1.ActorContext{
		"token of a plain user": plainToken,
		"token with no user":    noUser,
		"service account carrying the flag": {
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-1", TokenOwnerIsSiteAdmin: true,
		},
		"workload carrying admin flags": {
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-1", TokenOwnerIsSiteAdmin: true, IsSiteAdmin: true, IsRoot: true,
		},
		"token claiming admin flags, owner not": {
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, UserId: "user-bob", TokenId: "utok-2", IsSiteAdmin: true, IsRoot: true,
		},
		"no actor": nil,
	} {
		t.Run(name, func(t *testing.T) {
			s, ca := newExtensionServer(t)
			_, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{Actor: actor, Id: docusignExtID})
			if name == "no actor" {
				// A nil actor reads as a person, and *ForPrincipal refuses people.
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("err = %v", err)
				}
				return
			}
			st := status.Convert(err)
			if st.Code() != codes.PermissionDenied {
				t.Fatalf("err = %v", err)
			}
			var reason string
			for _, d := range st.Details() {
				if info, ok := d.(*errdetails.ErrorInfo); ok {
					reason = info.GetReason()
				}
			}
			if reason != ReasonNotSiteAdmin {
				t.Fatalf("reason = %q", reason)
			}
			ev := ca.find("authz.denied")
			if ev == nil {
				t.Fatal("the refusal was not audited")
			}
			if ev.Subject != docusignExtID || ev.Attributes["method"] != "ImportExtensionForPrincipal" || ev.Attributes["reason"] != ReasonNotSiteAdmin {
				t.Fatalf("event = %+v", ev)
			}
			if hasSecretType(t, s, docusignExtID) {
				t.Fatal("a refused call installed the pack")
			}
		})
	}
}

func TestImportExtensionForPrincipal_RefusesAPerson(t *testing.T) {
	s, _ := newExtensionServer(t)
	_, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true, IsRoot: true}, Id: docusignExtID,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v", err)
	}
}

// A refused caller can't write whatever it likes into the audit subject.
func TestImportExtensionForPrincipal_RefusalOfAnUnknownPackKeepsTheCallersTextOutOfTheAudit(t *testing.T) {
	s, ca := newExtensionServer(t)
	plain := adminToken("mcp")
	plain.TokenOwnerIsSiteAdmin = false
	if _, err := s.ImportExtensionForPrincipal(context.Background(), &vaultv1.ImportExtensionForPrincipalRequest{Actor: plain, Id: "made up"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v", err)
	}
	if ev := ca.find("authz.denied"); ev == nil || ev.Subject != "vault" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestImportExtensionForPrincipal_UnknownAndInstalledPacks(t *testing.T) {
	s, ca := newExtensionServer(t)
	ctx := context.Background()
	if _, err := s.ImportExtensionForPrincipal(ctx, &vaultv1.ImportExtensionForPrincipalRequest{Actor: adminToken("mcp"), Id: "no-such-extension"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown: %v", err)
	}
	if ca.find("extension.import.principal") != nil {
		t.Fatal("audited an activation that didn't happen")
	}
	if _, err := s.ImportExtensionForPrincipal(ctx, &vaultv1.ImportExtensionForPrincipalRequest{Actor: adminToken("mcp"), Id: docusignExtID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportExtensionForPrincipal(ctx, &vaultv1.ImportExtensionForPrincipalRequest{Actor: adminToken("mcp"), Id: docusignExtID}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("installed: %v", err)
	}
}

func TestImportExtensionForPrincipal_IsPersistedAndOpenToTheGatewayAlone(t *testing.T) {
	if !mutatingMethods["ImportExtensionForPrincipal"] {
		t.Error("ImportExtensionForPrincipal is not in mutatingMethods, so a restart loses it")
	}
	got := CallerPolicy()[vaultv1.VaultService_ImportExtensionForPrincipal_FullMethodName]
	if len(got) != 1 || got[CallerGateway] != workloadauth.OnBehalf {
		t.Errorf("callers = %+v, want the gateway on behalf of a user", got)
	}
}
