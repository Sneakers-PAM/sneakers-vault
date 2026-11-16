// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A break-glass session belongs to the web session that opened it. The same
// user's personal (MCP or agent) token can't use it, not with its id and not
// with a plain break-glass reveal, and each attempt is audited, while the web
// session that opened it still can.
func TestBreakGlassSessionIsNotUsableByTheSameUsersToken(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()
	sess := fx.open(t, admin)

	token := &vaultv1.ActorContext{
		UserId: admin.GetUserId(), PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, TokenId: "tok-1",
		MfaVerifiedAtUnix: fx.now.Unix(),
	}
	sameRef := &vaultv1.ActorContext{
		UserId: admin.GetUserId(), PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, TokenId: "tok-1",
		SessionRef: admin.GetSessionRef(), MfaVerifiedAtUnix: fx.now.Unix(),
	}
	before := fx.count("break_glass.denied")
	for name, req := range map[string]*vaultv1.BreakGlassSecretRequest{
		"token with the session id":         {Actor: token, SecretId: fx.personalSec, SessionId: sess.GetId()},
		"token with a copied session ref":   {Actor: sameRef, SecretId: fx.personalSec, SessionId: sess.GetId()},
		"token, plain break-glass reveal":   {Actor: token, SecretId: fx.sharedSecID, Reason: "outage"},
		"token, plain reveal with ref copy": {Actor: sameRef, SecretId: fx.sharedSecID, Reason: "outage"},
	} {
		_, err := fx.s.BreakGlassSecret(ctx, req)
		if code(err) != codes.PermissionDenied || btgReason(err) != ReasonPersonSessionRequired {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got := fx.count("break_glass.denied") - before; got != 4 {
		t.Fatalf("audited refusals = %d, want 4", got)
	}
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: token, SessionId: sess.GetId()}); err == nil {
		t.Fatal("the token listed the break-glass session")
	}

	resp, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, SessionId: sess.GetId()})
	if err != nil || resp.GetFields()["password"] != "Enigma#42" {
		t.Fatalf("the web session's own reveal: %v", err)
	}
}
