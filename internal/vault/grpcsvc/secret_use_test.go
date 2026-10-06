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

type useFixture struct {
	s        *Server
	ca       *capAudit
	secret   string
	folder   string
	owner    *vaultv1.ActorContext
	token    *vaultv1.ActorContext
	approver *vaultv1.ActorContext
	users    *vaultv1.ActiveUsers
	now      time.Time
}

// newUseFixture: a shared folder owned by carol whose g-agents group may read
// one approval-required password secret, and user-ada's personal token in
// that group. ada is not an owner, so her uses wait for carol.
func newUseFixture(t *testing.T) *useFixture {
	t.Helper()
	fx := &useFixture{s: newServer(t), ca: &capAudit{}, now: time.Unix(1790000000, 0)}
	fx.s.audit = fx.ca
	fx.s.uses = newMemUseStore()
	fx.s.now = func() time.Time { return fx.now }
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fx.folder = newSharedFolder(t, fx.s)
	fx.secret = secretIn(t, fx.s, carol, fx.folder, "router-admin")
	grantGroup(t, fx.s, carol, fx.folder, "C")
	if _, err := fx.s.SetSecretTokenApproval(context.Background(), &vaultv1.SetSecretTokenApprovalRequest{Actor: carol, SecretId: fx.secret, Required: true}); err != nil {
		t.Fatalf("SetSecretTokenApproval: %v", err)
	}
	fx.owner = &vaultv1.ActorContext{UserId: "user-ada", GroupNames: []string{"g-agents"}}
	fx.token = tokenActor("user-ada", false, "g-agents")
	fx.approver = carol
	return fx
}

func (fx *useFixture) prepare(t *testing.T, argv ...string) *vaultv1.SecretUse {
	t.Helper()
	if len(argv) == 0 {
		argv = []string{"ssh", "admin@router-01"}
	}
	resp, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: fx.token, SecretId: fx.secret, FieldKey: "password", Argv: argv, ClientLabel: "laptop", ActiveUsers: fx.users,
	})
	if err != nil {
		t.Fatalf("PrepareSecretUse: %v", err)
	}
	return resp.GetUse()
}

func (fx *useFixture) redeem(actor *vaultv1.ActorContext, id string) (*vaultv1.RedeemSecretUseResponse, error) {
	return fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: actor, UseId: id})
}

func (fx *useFixture) decide(actor *vaultv1.ActorContext, id string, approve bool) error {
	_, err := fx.s.DecideSecretUse(context.Background(), &vaultv1.DecideSecretUseRequest{Actor: actor, UseId: id, Approve: approve})
	return err
}

func TestSecretUseIsReleasedOnceAfterAnOwnerApproves(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepare(t)
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING || use.GetSecretName() != "router-admin" {
		t.Fatalf("prepared use = %+v", use)
	}
	if _, err := fx.redeem(fx.token, use.GetId()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("redeem before approval: want FailedPrecondition, got %v", err)
	}
	if err := fx.decide(fx.approver, use.GetId(), true); err != nil {
		t.Fatalf("owner approve: %v", err)
	}
	got, err := fx.redeem(fx.token, use.GetId())
	if err != nil || got.GetValue() != "p" || got.GetUse().GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED {
		t.Fatalf("redeem = %+v, %v", got, err)
	}
	if strings.Join(got.GetUse().GetArgv(), " ") != "ssh admin@router-01" {
		t.Fatalf("released for argv %v, want the prepared command", got.GetUse().GetArgv())
	}
	if _, err := fx.redeem(fx.token, use.GetId()); err == nil {
		t.Fatal("a use can be redeemed only once")
	}
}

func TestSecretUseOnlyTheSameTokenRedeems(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepare(t)
	_ = fx.decide(fx.approver, use.GetId(), true)
	other := tokenActor("user-ada", false, "g-agents")
	other.TokenId = "utok-other"
	if _, err := fx.redeem(other, use.GetId()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("redeem by another token: want PermissionDenied, got %v", err)
	}
}

func TestSecretUseOnlyAnOwnerOfTheSecretDecides(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepare(t)
	admin := &vaultv1.ActorContext{UserId: "user-dan", IsSiteAdmin: true, IsRoot: true}
	if err := fx.decide(admin, use.GetId(), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an admin who isn't an owner approving: want PermissionDenied, got %v", err)
	}
	if err := fx.decide(fx.token, use.GetId(), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a token approving its own use: want PermissionDenied, got %v", err)
	}
	if err := fx.decide(fx.owner, use.GetId(), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the requester approving their own use: want PermissionDenied, got %v", err)
	}
	if err := fx.decide(fx.approver, use.GetId(), true); err != nil {
		t.Fatalf("the secret's owner approving: %v", err)
	}
}

func TestSecretUseDeniedOrExpiredIsNeverReleased(t *testing.T) {
	fx := newUseFixture(t)
	denied := fx.prepare(t)
	_ = fx.decide(fx.owner, denied.GetId(), false)
	if _, err := fx.redeem(fx.token, denied.GetId()); err == nil {
		t.Fatal("a denied use was released")
	}
	late := fx.prepare(t)
	_ = fx.decide(fx.approver, late.GetId(), true)
	fx.now = fx.now.Add(11 * time.Minute)
	if _, err := fx.redeem(fx.token, late.GetId()); err == nil {
		t.Fatal("an expired use was released")
	}
}

func TestSecretUseRechecksAccessAtRedeem(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepare(t)
	_ = fx.decide(fx.approver, use.GetId(), true)
	if _, err := fx.s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, FolderId: fx.folder, Owners: []string{"user-carol"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.redeem(fx.token, use.GetId()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("redeem after access was revoked: want PermissionDenied, got %v", err)
	}
}

func TestSecretUsePrepareNeedsAPersonalTokenWithReadAccess(t *testing.T) {
	fx := newUseFixture(t)
	for name, actor := range map[string]*vaultv1.ActorContext{
		"service account": agentGroupActor("sa-1"),
		"no access":       tokenActor("user-bob", false),
	} {
		_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
			Actor: actor, SecretId: fx.secret, FieldKey: "password", Argv: []string{"ssh", "x"},
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, err)
		}
	}
	if _, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: fx.token, SecretId: fx.secret, FieldKey: "password",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty argv: want InvalidArgument, got %v", err)
	}
	if _, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: fx.owner, SecretId: fx.secret, FieldKey: "password", Argv: []string{"ssh", "x"},
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a person's command use: want InvalidArgument (a person only reveals), got %v", err)
	}
}

func TestSecretUseAuditNeverCarriesTheValue(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepare(t)
	_ = fx.decide(fx.approver, use.GetId(), true)
	if _, err := fx.redeem(fx.token, use.GetId()); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"secret.use.prepare", "secret.use.approve", "secret.use.redeem"} {
		ev := fx.ca.find(action)
		if ev == nil {
			t.Fatalf("no %s audit event", action)
		}
		for k, v := range ev.Attributes {
			if v == "p" {
				t.Fatalf("%s audit attribute %s carries the secret value", action, k)
			}
		}
	}
	if ev := fx.ca.find("secret.use.redeem"); ev.Attributes["token_id"] != "utok-1" || ev.Attributes["argv"] != "ssh admin@router-01" {
		t.Fatalf("redeem audit = %+v", ev.Attributes)
	}
}

// grant creates a use grant. A grant only stands in for the requester's own
// confirmation, so it applies only when nobody else can decide: the fixture
// becomes a single-user install.
func (fx *useFixture) grant(t *testing.T, g *vaultv1.UseGrant) *vaultv1.UseGrant {
	t.Helper()
	fx.users = &vaultv1.ActiveUsers{UserIds: []string{"user-ada"}}
	resp, err := fx.s.CreateUseGrant(context.Background(), &vaultv1.CreateUseGrantRequest{Actor: fx.owner, Grant: g})
	if err != nil {
		t.Fatalf("CreateUseGrant: %v", err)
	}
	return resp.GetGrant()
}

func TestUseGrantPreApprovesUsesInsideItsScopeOnly(t *testing.T) {
	fx := newUseFixture(t)
	g := fx.grant(t, &vaultv1.UseGrant{
		TokenId: "utok-1", SecretIds: []string{fx.secret},
		Programs:      []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "admin@router-*"}},
		ExpiresAtUnix: fx.now.Add(2 * time.Hour).Unix(), MaxUses: 2,
	})
	if in := fx.prepare(t, "ssh", "admin@router-02"); in.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED || in.GetGrantId() != g.GetId() {
		t.Fatalf("in-scope use = %+v", in)
	}
	for name, argv := range map[string][]string{
		"other program": {"curl", "admin@router-02"},
		"other host":    {"ssh", "root@db-01"},
	} {
		if u := fx.prepare(t, argv...); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
			t.Errorf("%s: want pending, got %v", name, u.GetState())
		}
	}
	_ = fx.prepare(t, "ssh", "admin@router-03")
	if u := fx.prepare(t, "ssh", "admin@router-04"); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatalf("past max uses: want pending, got %v", u.GetState())
	}
}

func TestUseGrantStopsWhenRevokedOrExpired(t *testing.T) {
	fx := newUseFixture(t)
	g := fx.grant(t, &vaultv1.UseGrant{
		TokenId: "utok-1", FolderId: fx.folder,
		Programs:      []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "*"}},
		ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
	})
	if _, err := fx.s.RevokeUseGrant(context.Background(), &vaultv1.RevokeUseGrantRequest{Actor: fx.owner, GrantId: g.GetId()}); err != nil {
		t.Fatal(err)
	}
	if u := fx.prepare(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatalf("after revoke: want pending, got %v", u.GetState())
	}
	fx.grant(t, &vaultv1.UseGrant{
		TokenId: "utok-1", FolderId: fx.folder,
		Programs:      []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "*"}},
		ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
	})
	fx.now = fx.now.Add(2 * time.Hour)
	if u := fx.prepare(t); u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatalf("after expiry: want pending, got %v", u.GetState())
	}
}

func TestUseGrantCanOnlyBeCreatedByAPerson(t *testing.T) {
	fx := newUseFixture(t)
	for name, actor := range map[string]*vaultv1.ActorContext{
		"personal token":  fx.token,
		"service account": agentGroupActor("sa-1"),
	} {
		_, err := fx.s.CreateUseGrant(context.Background(), &vaultv1.CreateUseGrantRequest{Actor: actor, Grant: &vaultv1.UseGrant{
			TokenId: "utok-1", SecretIds: []string{fx.secret},
			Programs: []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "*"}}, ExpiresAtUnix: fx.now.Add(time.Hour).Unix(),
		}})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: want PermissionDenied, got %v", name, err)
		}
	}
}

func TestUseGrantWindowIsCappedAt24Hours(t *testing.T) {
	fx := newUseFixture(t)
	_, err := fx.s.CreateUseGrant(context.Background(), &vaultv1.CreateUseGrantRequest{Actor: fx.owner, Grant: &vaultv1.UseGrant{
		TokenId: "utok-1", SecretIds: []string{fx.secret},
		Programs: []*vaultv1.UseGrantProgram{{Program: "ssh", ArgPattern: "*"}}, ExpiresAtUnix: fx.now.Add(25 * time.Hour).Unix(),
	}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a 25h grant: want InvalidArgument, got %v", err)
	}
}
