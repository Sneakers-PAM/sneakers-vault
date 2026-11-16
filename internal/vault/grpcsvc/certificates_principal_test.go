// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
	"google.golang.org/grpc/codes"
)

// ReplaceCertificateForPrincipal: the machine form of ReplaceCertificate.
// Authorized like the other *ForPrincipal edits (Author on the folder chain and
// on the secret), non-human actors only, audited with the principal's kind.

func userTokenActor(id string) *vaultv1.ActorContext {
	a := agentGroupActor(id)
	a.PrincipalKind = vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
	a.TokenId = "tok-1"
	return a
}

// principalCertFixture imports an "old" certificate as carol and grants g-agents
// the given RACI action on its folder.
func principalCertFixture(t *testing.T, grant string) (s *Server, ca *capAudit, secID string) {
	t.Helper()
	s, ca, fid := newCertTestServer(t)
	oldTC := makeCertTestChainNamed(t, "old.example.com", 1)
	secID = importedCertSecret(t, s, fid, oldTC, makeCertTestP12(t, oldTC, "changeit"), "changeit")
	if grant != "" {
		grantGroup(t, s, orgCarol, fid, grant)
	}
	return s, ca, secID
}

func storedFields(t *testing.T, s *Server, id string) map[string]string {
	t.Helper()
	rec, ok := s.records[id]
	if !ok {
		t.Fatalf("no record for %s", id)
	}
	got, err := s.crypt.OpenAll(rec)
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	return got
}

func TestReplaceCertificateForPrincipal_AuthorReplacesInPlace(t *testing.T) {
	for _, actor := range []*vaultv1.ActorContext{agentGroupActor("sa-1"), userTokenActor("pt-1")} {
		t.Run(actor.GetPrincipalKind().String(), func(t *testing.T) {
			s, ca, secID := principalCertFixture(t, "R")
			before := s.findSecret(secID)
			folder, name := before.GetFolderId(), before.GetName()

			newTC := makeCertTestChainNamed(t, "new.example.com", 2)
			newP12 := makeCertTestP12(t, newTC, "newpass")
			wantFields, wantMeta, _, err := certsvc.ImportFields(newP12, "newpass", "")
			if err != nil {
				t.Fatalf("fixture ImportFields: %v", err)
			}

			resp, err := s.ReplaceCertificateForPrincipal(context.Background(), &vaultv1.ReplaceCertificateForPrincipalRequest{
				Actor: actor, SecretId: secID, FileBytes: newP12, Passphrase: "newpass",
			})
			if err != nil {
				t.Fatalf("ReplaceCertificateForPrincipal: %v", err)
			}
			sec := resp.GetSecret()
			if sec.GetId() != secID || sec.GetFolderId() != folder || sec.GetName() != name {
				t.Errorf("secret identity changed: id=%q folder=%q name=%q", sec.GetId(), sec.GetFolderId(), sec.GetName())
			}
			if got := storedFields(t, s, secID); !stringMapsEqual(got, wantFields) {
				t.Errorf("stored fields = %v, want the new file's fields %v", got, wantFields)
			}
			if resp.GetMeta().GetSerialNumber() != wantMeta.SerialNumber || !resp.GetMeta().GetHasPrivateKey() {
				t.Errorf("meta = %v, want the new certificate's meta with a key", resp.GetMeta())
			}
			if sec.GetExpiresAt() == "" {
				t.Error("expires_at not recomputed from the new certificate")
			}
			ev := ca.find("certificate.replace")
			if ev == nil || !ev.Sensitive {
				t.Fatalf("certificate.replace event = %+v, want a sensitive event", ev)
			}
			if ev.Attributes["principal_kind"] != actor.GetPrincipalKind().String() || ev.Attributes["principal_id"] != actor.GetPrincipalId() {
				t.Errorf("event attrs = %v, want the principal kind and id", ev.Attributes)
			}
			if actor.GetTokenId() != "" && ev.Attributes["token_id"] != actor.GetTokenId() {
				t.Errorf("event attrs = %v, want the token id", ev.Attributes)
			}
			for k, v := range ev.Attributes {
				if strings.Contains(v, "newpass") || strings.Contains(v, "BEGIN") {
					t.Errorf("event attr %s carries file or passphrase material", k)
				}
			}
		})
	}
}

func TestReplaceCertificateForPrincipal_RefusalsChangeNothing(t *testing.T) {
	newTC := makeCertTestChainNamed(t, "new.example.com", 2)
	good := makeCertTestP12(t, newTC, "newpass")
	otherTC := makeCertTestChainNamed(t, "other.example.com", 3)
	mismatched := append(newTC.leafPEM(), otherTC.keyPEM(t)...)

	cases := []struct {
		name  string
		grant string
		actor *vaultv1.ActorContext
		file  []byte
		pass  string
		pre   func(t *testing.T, s *Server, secID string)
		code  codes.Code
	}{
		{name: "no grant", grant: "", actor: agentGroupActor("sa-1"), file: good, pass: "newpass", code: codes.PermissionDenied},
		{name: "read-only grant", grant: "C", actor: agentGroupActor("sa-1"), file: good, pass: "newpass", code: codes.PermissionDenied},
		{name: "per-secret deny", grant: "R", actor: agentGroupActor("sa-1"), file: good, pass: "newpass",
			pre: func(t *testing.T, s *Server, secID string) { denySecretAuthor(t, s, secID) }, code: codes.PermissionDenied},
		{name: "human caller", grant: "R", actor: humanAdmin, file: good, pass: "newpass", code: codes.PermissionDenied},
		{name: "spoofed admin flags", grant: "", actor: spoofedAdminSA, file: good, pass: "newpass", code: codes.PermissionDenied},
		{name: "retired secret", grant: "R", actor: agentGroupActor("sa-1"), file: good, pass: "newpass",
			pre: func(t *testing.T, s *Server, secID string) { s.findSecret(secID).Retired = true }, code: codes.FailedPrecondition},
		{name: "not a certificate", grant: "R", actor: agentGroupActor("sa-1"), file: good, pass: "newpass",
			pre: func(t *testing.T, s *Server, secID string) { s.findSecret(secID).TypeId = "type-password" }, code: codes.InvalidArgument},
		{name: "wrong passphrase", grant: "R", actor: agentGroupActor("sa-1"), file: good, pass: "wrong", code: codes.InvalidArgument},
		{name: "key does not match", grant: "R", actor: agentGroupActor("sa-1"), file: mismatched, pass: "", code: codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ca, secID := principalCertFixture(t, tc.grant)
			if tc.pre != nil {
				tc.pre(t, s, secID)
			}
			before := storedFields(t, s, secID)
			resp, err := s.ReplaceCertificateForPrincipal(context.Background(), &vaultv1.ReplaceCertificateForPrincipalRequest{
				Actor: tc.actor, SecretId: secID, FileBytes: tc.file, Passphrase: tc.pass,
			})
			wantCode(t, err, tc.code)
			if resp != nil {
				t.Errorf("response = %v, want none on a refusal", resp)
			}
			if after := storedFields(t, s, secID); !stringMapsEqual(before, after) {
				t.Error("stored fields changed on a refused replace")
			}
			if ev := ca.find("certificate.replace"); ev != nil {
				t.Error("a refused replace must not emit certificate.replace")
			}
		})
	}
}

func TestReplaceCertificateForPrincipal_MissingSecretNotFound(t *testing.T) {
	s, _, _ := principalCertFixture(t, "R")
	_, err := s.ReplaceCertificateForPrincipal(context.Background(), &vaultv1.ReplaceCertificateForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: "no-such", FileBytes: []byte("x"),
	})
	wantCode(t, err, codes.NotFound)
}

func TestReplaceCertificateForPrincipal_MultiEntryReturnsAliasesAndChangesNothing(t *testing.T) {
	s, ca, secID := principalCertFixture(t, "R")
	before := storedFields(t, s, secID)
	tc := makeCertTestChainNamed(t, "multi.example.com", 4)

	resp, err := s.ReplaceCertificateForPrincipal(context.Background(), &vaultv1.ReplaceCertificateForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: secID, FileBytes: makeCertTestJKS(t, tc, "storepass"), Passphrase: "storepass",
	})
	if err != nil {
		t.Fatalf("ReplaceCertificateForPrincipal: %v", err)
	}
	if len(resp.GetAliases()) < 2 || resp.GetSecret() != nil {
		t.Fatalf("resp = %v, want aliases and no secret", resp)
	}
	if after := storedFields(t, s, secID); !stringMapsEqual(before, after) {
		t.Error("stored fields changed while the alias was still unchosen")
	}
	if ev := ca.find("certificate.replace"); ev != nil {
		t.Error("an alias-pending call must not emit certificate.replace")
	}
}
