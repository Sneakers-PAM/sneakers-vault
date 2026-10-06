// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (fx *useFixture) programGrant(t *testing.T, program string) {
	t.Helper()
	fx.grant(t, &vaultv1.UseGrant{
		TokenId: "utok-1", SecretIds: []string{fx.secret},
		Programs:      []*vaultv1.UseGrantProgram{{Program: program, ArgPattern: "*"}},
		ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
	})
}

func TestUseGrantProgramMatchesArgv0Exactly(t *testing.T) {
	fx := newUseFixture(t)
	fx.programGrant(t, "sha256sum")
	for _, argv0 := range []string{"/tmp/shadow/sha256sum", "./sha256sum", "/usr/bin/sha256sum"} {
		if u := fx.prepare(t, argv0, "-c"); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
			t.Errorf("%s under a bare-name grant: state %s, want PENDING", argv0, u.GetState())
		}
	}
	if u := fx.prepare(t, "sha256sum", "-c"); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("bare name: state %s, want APPROVED", u.GetState())
	}
}

func TestUseGrantAcceptsAnExactAbsoluteProgram(t *testing.T) {
	fx := newUseFixture(t)
	fx.programGrant(t, "/usr/bin/sha256sum")
	if u := fx.prepare(t, "sha256sum", "-c"); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Errorf("bare name under an absolute grant: state %s, want PENDING", u.GetState())
	}
	if u := fx.prepare(t, "/usr/bin/sha256sum", "-c"); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("exact absolute path: state %s, want APPROVED", u.GetState())
	}
}

func TestUseGrantRefusesRelativeProgramPaths(t *testing.T) {
	fx := newUseFixture(t)
	for _, p := range []string{"bin/sha256sum", "./sha256sum", "/usr/../tmp/x"} {
		_, err := fx.s.CreateUseGrant(context.Background(), &vaultv1.CreateUseGrantRequest{Actor: fx.owner, Grant: &vaultv1.UseGrant{
			TokenId: "utok-1", SecretIds: []string{fx.secret},
			Programs: []*vaultv1.UseGrantProgram{{Program: p, ArgPattern: "*"}}, ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
		}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("program %q: want InvalidArgument, got %v", p, err)
		}
	}
}

func (fx *useFixture) failureAudit(t *testing.T, action, outcome string) {
	t.Helper()
	ev := fx.ca.find(action)
	if ev == nil {
		t.Fatalf("no %s audit event", action)
	}
	if ev.Attributes["outcome"] != outcome || ev.Attributes["reason"] == "" {
		t.Fatalf("%s attrs = %v, want outcome=%s and a reason", action, ev.Attributes, outcome)
	}
	for _, v := range ev.Attributes {
		if v == "s3cret" {
			t.Fatalf("%s audit carries the value", action)
		}
	}
	fx.ca.events = nil
}

func TestRefusedPrepareIsAudited(t *testing.T) {
	fx := newUseFixture(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	hidden := secretIn(t, fx.s, carol, newSharedFolder(t, fx.s), "hidden")
	for _, id := range []string{hidden, "no-such-secret"} {
		_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
			Actor: fx.token, SecretId: id, FieldKey: "password", Argv: []string{"ssh", "h"},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("prepare %s: want PermissionDenied, got %v", id, err)
		}
		fx.failureAudit(t, "secret.use.prepare", "denied")
	}
}

func TestFailedRedeemIsAudited(t *testing.T) {
	fx := newUseFixture(t)
	other := tokenActor("user-ada", false, "g-agents")
	other.TokenId = "utok-2"

	u := fx.prepare(t)
	if _, err := fx.redeem(other, u.GetId()); err == nil {
		t.Fatal("another token redeemed")
	}
	fx.failureAudit(t, "secret.use.redeem", "denied")

	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("an unapproved use redeemed")
	}
	fx.failureAudit(t, "secret.use.redeem", "failed")

	_ = fx.decide(fx.owner, u.GetId(), false)
	fx.ca.events = nil
	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("a denied use redeemed")
	}
	fx.failureAudit(t, "secret.use.redeem", "failed")

	late := fx.prepare(t)
	fx.now = fx.now.Add(secretUseTTL)
	if _, err := fx.redeem(fx.token, late.GetId()); err == nil {
		t.Fatal("an expired use redeemed")
	}
	fx.failureAudit(t, "secret.use.redeem", "failed")
}

func TestRedeemMustFollowApprovalWithinAMinute(t *testing.T) {
	fx := newUseFixture(t)
	u := fx.prepare(t)
	fx.now = fx.now.Add(2 * time.Minute)
	if err := fx.decide(fx.approver, u.GetId(), true); err != nil {
		t.Fatalf("approve inside the 10 minute window: %v", err)
	}
	fx.now = fx.now.Add(redeemAfterApproval)
	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("redeemed a minute after approval")
	}

	v := fx.prepare(t)
	if err := fx.decide(fx.approver, v.GetId(), true); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(redeemAfterApproval - time.Second)
	if _, err := fx.redeem(fx.token, v.GetId()); err != nil {
		t.Fatalf("redeem inside the minute: %v", err)
	}
}

func TestGrantApprovedUseMustBeRedeemedWithinAMinute(t *testing.T) {
	fx := newUseFixture(t)
	fx.programGrant(t, "ssh")
	u := fx.prepare(t)
	if u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("state %s, want APPROVED by grant", u.GetState())
	}
	fx.now = fx.now.Add(redeemAfterApproval)
	if _, err := fx.redeem(fx.token, u.GetId()); err == nil {
		t.Fatal("redeemed a minute after the grant approved it")
	}
}
