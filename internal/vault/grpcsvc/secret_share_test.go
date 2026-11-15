// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A one-time share of a secret field through a link (#148 in the gateway): the
// creator prepares a share use, which follows the normal approval rules, and
// whoever holds the link's token redeems it once.

func shareHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (fx *approvalFixture) tryShare(actor *vaultv1.ActorContext, token string, ttl int64) (*vaultv1.SecretUse, error) {
	resp, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: actor, SecretId: fx.secret, FieldKey: "password", ClientLabel: "share link", Reveal: true,
		ShareHash: shareHash(token), ShareTtlSeconds: ttl, ActiveUsers: everyone,
	})
	return resp.GetUse(), err
}

func (fx *approvalFixture) redeemShare(id, token string) (*vaultv1.RedeemSecretShareResponse, error) {
	return fx.s.RedeemSecretShare(context.Background(), &vaultv1.RedeemSecretShareRequest{UseId: id, ShareHash: shareHash(token)})
}

func shareReason(t *testing.T, err error, want codes.Code) string {
	t.Helper()
	return reasonOf(t, err, want)
}

func TestAnOwnerSharesOnceAndTheValueComesBackOnce(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	use, err := fx.tryShare(human("user-carol"), "tok-1", 3600)
	if err != nil || use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("an owner needs no approval: %v %v", use, err)
	}
	if got := use.GetExpiresAtUnix(); got != fx.now.Add(time.Hour).Unix() {
		t.Fatalf("expiry %d, want the link's lifetime", got)
	}
	resp, err := fx.redeemShare(use.GetId(), "tok-1")
	if err != nil || resp.GetValue() != "p" {
		t.Fatalf("redeem: %v %v", resp, err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); shareReason(t, err, codes.FailedPrecondition) != ReasonShareUsed {
		t.Fatal("a second view must be refused as used")
	}
	var reveal bool
	for _, ev := range fx.ca.events {
		if ev.Action == "secret.reveal" && ev.ActorUserID == "user-carol" && ev.Attributes["via"] == "share_link" && ev.Attributes["use_id"] == use.GetId() {
			reveal = true
		}
		if strings.Contains(strings.Join(mapValues(ev.Attributes), " "), "p\x00") {
			t.Fatal("the audit must not carry the value")
		}
	}
	if !reveal {
		t.Fatalf("no secret.reveal via share_link in %+v", fx.ca.events)
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestAWrongTokenIsRefusedAndBurnsNothing(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	use, _ := fx.tryShare(human("user-carol"), "tok-1", 3600)
	if _, err := fx.redeemShare(use.GetId(), "tok-2"); status.Code(err) != codes.NotFound {
		t.Fatalf("wrong token: %v, want NotFound", err)
	}
	if _, err := fx.s.RedeemSecretShare(context.Background(), &vaultv1.RedeemSecretShareRequest{UseId: "no-such-use", ShareHash: shareHash("tok-1")}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown use: %v, want NotFound", err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); err != nil {
		t.Fatalf("the right token must still work after a wrong one: %v", err)
	}
}

func TestAShareNeedsTheOwnersApprovalAndApprovalKeepsTheLifetime(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	ada := human("user-ada", "g-readers")
	use, err := fx.tryShare(ada, "tok-1", 86400)
	if err != nil || use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatalf("a reader's share must wait: %v %v", use, err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); shareReason(t, err, codes.FailedPrecondition) != ReasonShareNotApproved {
		t.Fatal("an unapproved share must say so")
	}
	if err := fx.decide(human("user-carol"), use.GetId(), true); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(2 * time.Hour) // far beyond the one-minute redeem window of an ordinary use
	if resp, err := fx.redeemShare(use.GetId(), "tok-1"); err != nil || resp.GetValue() != "p" {
		t.Fatalf("an approved share lives for the link's lifetime: %v %v", resp, err)
	}
}

func TestADeniedShareIsRefused(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	use, _ := fx.tryShare(human("user-ada", "g-readers"), "tok-1", 3600)
	if err := fx.decide(human("user-carol"), use.GetId(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); shareReason(t, err, codes.FailedPrecondition) != ReasonShareDenied {
		t.Fatal("a denied share must say so")
	}
}

func TestAShareExpires(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	use, _ := fx.tryShare(human("user-carol"), "tok-1", 600)
	fx.now = fx.now.Add(11 * time.Minute)
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); shareReason(t, err, codes.FailedPrecondition) != ReasonShareExpired {
		t.Fatal("an expired share must say so")
	}
}

func TestOnlyTheCreatorOrASiteAdminRevokes(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	use, _ := fx.tryShare(human("user-carol"), "tok-1", 3600)
	revoke := func(a *vaultv1.ActorContext) error {
		_, err := fx.s.RevokeSecretShare(context.Background(), &vaultv1.RevokeSecretShareRequest{Actor: a, UseId: use.GetId()})
		return err
	}
	if err := revoke(human("user-bob")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another person: %v", err)
	}
	if err := revoke(tokenActor("user-carol", false)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a token: %v", err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); err != nil {
		t.Fatalf("a refused revoke must leave it working: %v", err)
	}
	use2, _ := fx.tryShare(human("user-carol"), "tok-2", 3600)
	if _, err := fx.s.RevokeSecretShare(context.Background(), &vaultv1.RevokeSecretShareRequest{Actor: human("user-carol"), UseId: use2.GetId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.redeemShare(use2.GetId(), "tok-2"); shareReason(t, err, codes.FailedPrecondition) != ReasonShareExpired {
		t.Fatal("a revoked share must not redeem")
	}
	if fx.ca.find("secret.share.revoke") == nil {
		t.Fatal("a revoke must be audited")
	}
}

func TestAShareUseCannotBeRedeemedTheOrdinaryWay(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	use, _ := fx.tryShare(human("user-carol"), "tok-1", 3600)
	_, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: human("user-carol"), UseId: use.GetId()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ordinary redeem of a share: %v, want FailedPrecondition", err)
	}
	if _, err := fx.redeemShare(use.GetId(), "tok-1"); err != nil {
		t.Fatalf("the share must still redeem: %v", err)
	}
}

func TestShareRefusals(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	for name, c := range map[string]struct {
		actor  *vaultv1.ActorContext
		hash   string
		ttl    int64
		reveal bool
		want   codes.Code
	}{
		"a token":            {tokenActor("user-carol", false), shareHash("t"), 3600, true, codes.PermissionDenied},
		"a bad hash":         {human("user-carol"), "not-a-hash", 3600, true, codes.InvalidArgument},
		"an upper-case hash": {human("user-carol"), strings.ToUpper(shareHash("t")), 3600, true, codes.InvalidArgument},
		"too long a life":    {human("user-carol"), shareHash("t"), 8 * 24 * 3600, true, codes.InvalidArgument},
		"too short a life":   {human("user-carol"), shareHash("t"), 30, true, codes.InvalidArgument},
		"not a reveal":       {human("user-carol"), shareHash("t"), 3600, false, codes.InvalidArgument},
		"no read access":     {human("user-eve"), shareHash("t"), 3600, true, codes.PermissionDenied},
	} {
		_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
			Actor: c.actor, SecretId: fx.secret, FieldKey: "password", Reveal: c.reveal, ShareHash: c.hash, ShareTtlSeconds: c.ttl, ActiveUsers: everyone,
			Argv: map[bool][]string{true: nil, false: {"ssh"}}[c.reveal],
		})
		if status.Code(err) != c.want {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if u, err := fx.tryShare(human("user-carol"), "t", 0); err != nil || u.GetExpiresAtUnix() != fx.now.Add(24*time.Hour).Unix() {
		t.Fatalf("no lifetime means a day: %v %v", u, err)
	}
}

func TestAShareNeedsAFreshSecondFactorWhereTheSecretDoes(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	fx.s.settings.RequireMfaForReveal = true
	carol := &vaultv1.ActorContext{UserId: "user-carol", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	if _, err := fx.tryShare(carol, "t", 3600); reasonOf(t, err, codes.PermissionDenied) != ReasonStepUpRequired {
		t.Fatal("a share without a fresh factor must ask for one")
	}
	carol.MfaVerifiedAtUnix = fx.now.Unix()
	if _, err := fx.tryShare(carol, "t", 3600); err != nil {
		t.Fatalf("with a fresh factor: %v", err)
	}
}
