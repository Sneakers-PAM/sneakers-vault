// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// inWebSession is a copy of a, signed in to web session "web-1".
func inWebSession(a *vaultv1.ActorContext) *vaultv1.ActorContext {
	c := proto.Clone(a).(*vaultv1.ActorContext)
	c.SessionRef = "web-1"
	return c
}

// A person's reveal is made from their own signed-in web session: the
// gateway and the SSH broker send its reference, and a person-kind actor
// without one (including no actor at all, whose kind reads as a person's) is
// refused and audited. The vault's own actor for a Self caller is not a
// person and isn't asked for one.
func TestAPersonsRevealNeedsTheirWebSession(t *testing.T) {
	f := newAuthFixture(t)
	for _, caller := range []string{"gateway", "sshbroker"} {
		for name, actor := range map[string]*vaultv1.ActorContext{
			"no session ref": {UserId: "user-carol"},
			"no actor":       nil,
		} {
			f.ca.mu.Lock()
			f.ca.events = nil
			f.ca.mu.Unlock()
			_, err := f.reveal(f.as(t, caller), actor)
			wantCode(t, err, codes.PermissionDenied)
			if r := btgReason(err); r != ReasonPersonSessionRequired {
				t.Fatalf("%s %s: reason = %q", caller, name, r)
			}
			ev := f.ca.find("secret.reveal.denied")
			if ev == nil || ev.Tier != audit.TierAudit || ev.Attributes["reason"] != ReasonPersonSessionRequired ||
				ev.Attributes["method"] != vaultv1.VaultService_RevealSecretField_FullMethodName || ev.Attributes["caller"] != caller {
				t.Fatalf("%s %s: audit = %+v", caller, name, ev)
			}
		}
		rev, err := f.reveal(f.as(t, caller), &vaultv1.ActorContext{UserId: "user-carol", SessionRef: "web-1"})
		if err != nil || rev.GetValue() != "Sup3r$ecret" {
			t.Fatalf("%s with the web session: %v", caller, err)
		}
	}
}

// Every call that hands a value to a person needs the web session, not just
// the field reveal.
func TestEveryPersonRevealCallNeedsTheWebSession(t *testing.T) {
	f := newAuthFixture(t)
	ctx := f.as(t, "gateway")
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	for method, call := range map[string]func() error{
		"CopySecret": func() error {
			_, err := f.client.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: carol, Id: f.secret})
			return err
		},
		"RevealSecretVersionField": func() error {
			_, err := f.client.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{Actor: carol, SecretId: f.secret, VersionNo: 1, FieldKey: "password"})
			return err
		},
		"ExportCertificate": func() error {
			_, err := f.client.ExportCertificate(ctx, &vaultv1.ExportCertificateRequest{Actor: carol, SecretId: f.secret, Format: "pem"})
			return err
		},
		"BreakGlassSecret": func() error {
			_, err := f.client.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: carol, SecretId: f.secret, Reason: "outage"})
			return err
		},
	} {
		err := call()
		if code(err) != codes.PermissionDenied || btgReason(err) != ReasonPersonSessionRequired {
			t.Fatalf("%s: %v", method, err)
		}
	}
	if ev := f.ca.find("break_glass.denied"); ev == nil || !strings.HasSuffix(ev.Attributes["method"], "/BreakGlassSecret") {
		t.Fatalf("break-glass refusal audit = %+v", ev)
	}
}

// Break-glass is for people only. The vault refuses an agent's personal
// token, a service account and a workload on its own, without relying on
// the gateway, and a person with no web session too; each refusal is
// audited and says why.
func TestBreakGlassSecretIsRefusedToAgentsAndTokens(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	actors := map[string]*vaultv1.ActorContext{
		"personal token":  {UserId: "user-carol", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, TokenId: "tok-1", SessionRef: "web-1"},
		"service account": {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-1"},
		"workload":        {PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD, PrincipalId: "wl-1"},
		"no web session":  {UserId: "user-carol"},
	}
	for name, a := range actors {
		ca.mu.Lock()
		ca.events = nil
		ca.mu.Unlock()
		_, err := s.BreakGlassSecret(context.Background(), &vaultv1.BreakGlassSecretRequest{Actor: a, SecretId: "s-1", Reason: "outage"})
		if code(err) != codes.PermissionDenied || btgReason(err) != ReasonPersonSessionRequired {
			t.Fatalf("%s: %v", name, err)
		}
		if msg := status.Convert(err).Message(); msg != "break-glass needs a person's own signed-in session; agents and tokens can't use it" {
			t.Fatalf("%s: message = %q", name, msg)
		}
		ev := ca.find("break_glass.denied")
		if ev == nil || ev.Tier != audit.TierAudit || ev.Subject != "s-1" || ev.Attributes["principal_kind"] != a.GetPrincipalKind().String() {
			t.Fatalf("%s: audit = %+v", name, ev)
		}
	}
}
