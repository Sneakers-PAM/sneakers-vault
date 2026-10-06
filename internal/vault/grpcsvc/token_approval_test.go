// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (fx *useFixture) setApproval(actor *vaultv1.ActorContext, on bool) error {
	_, err := fx.s.SetSecretTokenApproval(context.Background(), &vaultv1.SetSecretTokenApprovalRequest{Actor: actor, SecretId: fx.secret, Required: on})
	return err
}

func (fx *useFixture) reveal() (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	return fx.s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: fx.token, Id: fx.secret, FieldKey: "password"})
}

func (fx *useFixture) prepareReveal(t *testing.T) *vaultv1.SecretUse {
	t.Helper()
	resp, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: fx.token, SecretId: fx.secret, FieldKey: "password", Reveal: true, ClientLabel: "Example CLI", ActiveUsers: fx.users,
	})
	if err != nil {
		t.Fatalf("prepare reveal: %v", err)
	}
	return resp.GetUse()
}

var carolManager = &vaultv1.ActorContext{UserId: "user-carol"}

func TestTokenApprovalDefaultsOffAndAnOffSecretRevealsDirectly(t *testing.T) {
	fx := newUseFixture(t)
	fresh := secretIn(t, fx.s, carolManager, fx.folder, "fresh")
	if sec := fx.s.findSecret(fresh); sec.GetRequireTokenApproval() || sec.GetAlwaysRequireApproval() {
		t.Fatal("a secret must default to no token approval")
	}
	if err := fx.setApproval(carolManager, false); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.reveal(); err != nil {
		t.Fatalf("OFF reveal: %v", err)
	}
}

func TestOnlyAPersonWithManageRightsSetsTokenApproval(t *testing.T) {
	fx := newUseFixture(t)
	for name, actor := range map[string]*vaultv1.ActorContext{
		"the owner's token": tokenActor("user-carol", false),
		"no manage rights":  fx.owner,
	} {
		if err := fx.setApproval(actor, true); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, err)
		}
	}
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatalf("manager: %v", err)
	}
	if !fx.s.findSecret(fx.secret).GetRequireTokenApproval() {
		t.Fatal("toggle not stored")
	}
	if ev := fx.ca.find("secret.token_approval.enable"); ev == nil || ev.ActorUserID != "user-carol" {
		t.Fatalf("toggle change not audited: %+v", ev)
	}
}

func TestOnSecretRefusesADirectTokenReveal(t *testing.T) {
	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	_, err := fx.reveal()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "approval_required") {
		t.Fatalf("ON direct reveal: want FailedPrecondition approval_required, got %v", err)
	}
}

func TestOnSecretRevealIsReleasedOnceAfterApproval(t *testing.T) {
	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	u := fx.prepareReveal(t)
	if u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING || !u.GetReveal() || len(u.GetArgv()) != 0 {
		t.Fatalf("reveal use = %+v, want a pending reveal", u)
	}
	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("released before approval")
	}
	if err := fx.decide(fx.approver, u.GetId(), true); err != nil {
		t.Fatal(err)
	}
	fx.ca.events = nil
	resp, err := fx.redeem(fx.token, u.GetId())
	if err != nil || resp.GetValue() == "" {
		t.Fatalf("redeem after approval: %v", err)
	}
	if ev := fx.ca.find("secret.reveal"); ev == nil || ev.ActorUserID != "user-ada" || ev.Attributes["via"] != "mcp" || ev.Attributes["use_id"] != u.GetId() {
		t.Fatalf("approved reveal audit = %+v", ev)
	}
	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("released twice")
	}
}

func TestAnAllowRevealGrantApprovesAnOnSecretReveal(t *testing.T) {
	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	fx.grant(t, &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{fx.secret}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()})
	if u := fx.prepareReveal(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("matching allow-reveal grant: state %s, want APPROVED", u.GetState())
	}
}

func TestGrantsWithoutAllowRevealOrOutOfScopeLeaveARevealPending(t *testing.T) {
	cases := map[string]func(fx *useFixture) *vaultv1.UseGrant{
		"no allow_reveal": func(fx *useFixture) *vaultv1.UseGrant {
			return &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{fx.secret}, Programs: []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "*"}}, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()}
		},
		"another token": func(fx *useFixture) *vaultv1.UseGrant {
			return &vaultv1.UseGrant{TokenId: "utok-9", SecretIds: []string{fx.secret}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()}
		},
		"another secret": func(fx *useFixture) *vaultv1.UseGrant {
			return &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{"other"}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()}
		},
	}
	for name, mk := range cases {
		fx := newUseFixture(t)
		if err := fx.setApproval(carolManager, true); err != nil {
			t.Fatal(err)
		}
		fx.grant(t, mk(fx))
		if u := fx.prepareReveal(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
			t.Errorf("%s: state %s, want PENDING", name, u.GetState())
		}
	}

	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	g := fx.grant(t, &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{fx.secret}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()})
	if _, err := fx.s.RevokeUseGrant(context.Background(), &vaultv1.RevokeUseGrantRequest{Actor: fx.owner, GrantId: g.GetId()}); err != nil {
		t.Fatal(err)
	}
	if u := fx.prepareReveal(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Errorf("revoked grant: state %s, want PENDING", u.GetState())
	}
	fx2 := newUseFixture(t)
	if err := fx2.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	fx2.grant(t, &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{fx2.secret}, AllowReveal: true, ExpiresAtUnix: fx2.now.Add(time.Hour).Unix()})
	fx2.now = fx2.now.Add(2 * time.Hour)
	if u := fx2.prepareReveal(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Errorf("expired grant: state %s, want PENDING", u.GetState())
	}
}

func TestAnAllowRevealGrantNeedsNoProgramsAndIsStillPersonOnly(t *testing.T) {
	fx := newUseFixture(t)
	fx.grant(t, &vaultv1.UseGrant{TokenId: "utok-1", SecretIds: []string{fx.secret}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix()})
	_, err := fx.s.CreateUseGrant(context.Background(), &vaultv1.CreateUseGrantRequest{Actor: fx.token, Grant: &vaultv1.UseGrant{
		TokenId: "utok-1", SecretIds: []string{fx.secret}, AllowReveal: true, ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
	}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a token creating an allow-reveal grant: want PermissionDenied, got %v", err)
	}
}

func TestARevealUseCarriesNoCommand(t *testing.T) {
	fx := newUseFixture(t)
	_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: fx.token, SecretId: fx.secret, FieldKey: "password", Reveal: true, Argv: []string{"ssh"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("reveal with argv: want InvalidArgument, got %v", err)
	}
}

// Token approval covers personal tokens only. A service account with read
// reveals directly; its reveals are governed by RACI and
// allow_api_for_sensitive, not by this switch.
func TestTokenApprovalDoesNotCoverServiceAccounts(t *testing.T) {
	fx := newUseFixture(t)
	if err := fx.setApproval(carolManager, true); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.reveal(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("personal token with approval on: %v, want approval_required", err)
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-ci", GroupNames: []string{"g-agents"}}
	r, err := fx.s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: sa, Id: fx.secret, FieldKey: "password"})
	if err != nil || r.GetValue() == "" {
		t.Fatalf("service account reveal: %v %v", r, err)
	}
}
