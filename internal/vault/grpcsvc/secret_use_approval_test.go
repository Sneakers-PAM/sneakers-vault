// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Approval levels a test secret is set to.
const (
	levelNone = iota
	levelApprovalRequired
	levelAlwaysApprove
)

// approvalFixture: a shared folder created by carol, whose owners are set per
// test, where group g-readers may read; one password secret in it.
type approvalFixture struct {
	s      *Server
	ca     *capAudit
	folder string
	secret string
	now    time.Time
}

func newApprovalFixture(t *testing.T, owners []string, level int, extra ...*vaultv1.RaciRule) *approvalFixture {
	t.Helper()
	fx := &approvalFixture{s: newServer(t), ca: &capAudit{}, now: time.Unix(1790000000, 0)}
	fx.s.audit = fx.ca
	fx.s.uses = newMemUseStore()
	fx.s.now = func() time.Time { return fx.now }
	carol := human("user-carol")
	fx.folder = newSharedFolder(t, fx.s)
	fx.secret = secretIn(t, fx.s, carol, fx.folder, "domain-admin")
	if level != levelNone {
		if _, err := fx.s.SetSecretTokenApproval(context.Background(), &vaultv1.SetSecretTokenApprovalRequest{
			Actor: carol, SecretId: fx.secret,
			Required: true, Always: level == levelAlwaysApprove,
		}); err != nil {
			t.Fatalf("SetSecretTokenApproval: %v", err)
		}
	}
	rules := append([]*vaultv1.RaciRule{{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-readers",
		Grants: map[string]string{"C": "allow"},
	}}, extra...)
	if _, err := fx.s.SetFolderRuleset(context.Background(), &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fx.folder, Owners: owners, Rules: rules,
	}); err != nil {
		t.Fatalf("SetFolderRuleset: %v", err)
	}
	return fx
}

func human(uid string, groups ...string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{UserId: uid, GroupNames: groups}
}

func token(uid string, groups ...string) *vaultv1.ActorContext {
	return tokenActor(uid, false, groups...)
}

func active(ids ...string) *vaultv1.ActiveUsers { return &vaultv1.ActiveUsers{UserIds: ids} }

var everyone = active("user-ada", "user-bob", "user-carol", "user-dan")

func (fx *approvalFixture) prepare(t *testing.T, actor *vaultv1.ActorContext, runID string, users *vaultv1.ActiveUsers) *vaultv1.SecretUse {
	t.Helper()
	u, err := fx.tryPrepare(actor, runID, users)
	if err != nil {
		t.Fatalf("PrepareSecretUse(%s): %v", actor.GetUserId(), err)
	}
	return u
}

func (fx *approvalFixture) tryPrepare(actor *vaultv1.ActorContext, runID string, users *vaultv1.ActiveUsers) (*vaultv1.SecretUse, error) {
	req := &vaultv1.PrepareSecretUseRequest{
		Actor: actor, SecretId: fx.secret, FieldKey: "password", ClientLabel: "laptop", RunId: runID, ActiveUsers: users,
	}
	if isUserToken(actor) {
		req.Argv = []string{"ssh", "admin@dc-01"}
	} else {
		req.Reveal = true
	}
	resp, err := fx.s.PrepareSecretUse(context.Background(), req)
	return resp.GetUse(), err
}

func (fx *approvalFixture) decide(actor *vaultv1.ActorContext, id string, approve bool) error {
	_, err := fx.s.DecideSecretUse(context.Background(), &vaultv1.DecideSecretUseRequest{Actor: actor, UseId: id, Approve: approve})
	return err
}

func (fx *approvalFixture) confirm(actor *vaultv1.ActorContext, id string, users *vaultv1.ActiveUsers) (*vaultv1.SecretUse, error) {
	resp, err := fx.s.ConfirmSecretUse(context.Background(), &vaultv1.ConfirmSecretUseRequest{Actor: actor, UseId: id, ActiveUsers: users})
	return resp.GetUse(), err
}

func (fx *approvalFixture) toDecide(t *testing.T, actor *vaultv1.ActorContext) []string {
	t.Helper()
	resp, err := fx.s.ListSecretUsesToDecide(context.Background(), &vaultv1.ListSecretUsesToDecideRequest{Actor: actor})
	if err != nil {
		t.Fatalf("ListSecretUsesToDecide(%s): %v", actor.GetUserId(), err)
	}
	var ids []string
	for _, u := range resp.GetUses() {
		ids = append(ids, u.GetId())
	}
	return ids
}

func (fx *approvalFixture) fresh(a *vaultv1.ActorContext) *vaultv1.ActorContext {
	a.MfaVerifiedAtUnix = fx.now.Unix()
	return a
}

func useReason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}

func wantState(t *testing.T, what string, u *vaultv1.SecretUse, want vaultv1.SecretUseState) {
	t.Helper()
	if u.GetState() != want {
		t.Fatalf("%s: state %s, want %s", what, u.GetState(), want)
	}
}

func TestApprovalOneOwnerNeedsNoApproval(t *testing.T) {
	for _, level := range []int{levelNone, levelApprovalRequired} {
		fx := newApprovalFixture(t, []string{"user-ada"}, level)
		wantState(t, "owner's token use", fx.prepare(t, token("user-ada"), "", everyone), vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
		wantState(t, "owner's web reveal", fx.prepare(t, human("user-ada"), "", everyone), vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
		if _, err := fx.s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{Actor: human("user-ada"), Id: fx.secret, FieldKey: "password"}); err != nil {
			t.Fatalf("level %d: owner's direct web reveal: %v", level, err)
		}
	}
}

func TestApprovalTwoOwnersBothRevealWithoutApproval(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada", "user-bob"}, levelApprovalRequired)
	for _, uid := range []string{"user-ada", "user-bob"} {
		u := fx.prepare(t, token(uid), "", everyone)
		wantState(t, uid, u, vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
		if _, err := fx.s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{
			Actor: token(uid), Id: fx.secret, FieldKey: "password",
		}); err != nil {
			t.Fatalf("%s: direct token reveal: %v", uid, err)
		}
	}
}

func TestApprovalNonOwnerReaderOfANormalSecretNeedsNoApproval(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelNone)
	u := fx.prepare(t, token("user-ada", "g-readers"), "", everyone)
	wantState(t, "command use", u, vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
	got, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: token("user-ada", "g-readers"), UseId: u.GetId()})
	if err != nil || got.GetValue() != "p" {
		t.Fatalf("redeem = %v, %v", got, err)
	}
}

func TestApprovalNonOwnerOnApprovalRequiredWaitsForAnOwner(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol", "user-bob"}, levelApprovalRequired)
	ada := token("user-ada", "g-readers")
	u := fx.prepare(t, ada, "run-1", everyone)
	wantState(t, "non-owner use", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	if u.GetConfirm() {
		t.Fatal("an owner can decide, so the requester must not be offered a confirmation")
	}
	err := fx.decide(human("user-ada", "g-readers"), u.GetId(), true)
	if status.Code(err) != codes.PermissionDenied || useReason(err) != ReasonSelfApproval {
		t.Fatalf("requester approving their own use: %v (reason %q), want SELF_APPROVAL", err, useReason(err))
	}
	if _, err := fx.confirm(fx.fresh(human("user-ada", "g-readers")), u.GetId(), everyone); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("requester confirming while an owner can decide: want FailedPrecondition, got %v", err)
	}
	if err := fx.decide(human("user-dan", "g-readers"), u.GetId(), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another reader approving: want PermissionDenied, got %v", err)
	}
	if ids := fx.toDecide(t, human("user-bob")); len(ids) != 1 || ids[0] != u.GetId() {
		t.Fatalf("owner's queue = %v, want the pending use", ids)
	}
	if ids := fx.toDecide(t, human("user-ada", "g-readers")); len(ids) != 0 {
		t.Fatalf("requester's queue = %v, want empty", ids)
	}
	if err := fx.decide(human("user-bob"), u.GetId(), true); err != nil {
		t.Fatalf("second owner approving: %v", err)
	}
	got, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: ada, UseId: u.GetId()})
	if err != nil || got.GetValue() != "p" || got.GetUse().GetDecidedByUserId() != "user-bob" {
		t.Fatalf("redeem = %+v, %v", got, err)
	}
}

func TestApprovalRequesterMayWithdrawTheirOwnUse(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	u := fx.prepare(t, token("user-ada", "g-readers"), "", everyone)
	if err := fx.decide(human("user-ada", "g-readers"), u.GetId(), false); err != nil {
		t.Fatalf("requester denying their own use: %v", err)
	}
}

func TestApprovalWebRevealByANonOwnerGoesThroughAnOwner(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	ada := human("user-ada", "g-readers")
	_, err := fx.s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{Actor: ada, Id: fx.secret, FieldKey: "password"})
	if status.Code(err) != codes.FailedPrecondition || useReason(err) != ReasonApprovalRequired {
		t.Fatalf("direct web reveal: %v (reason %q), want APPROVAL_REQUIRED", err, useReason(err))
	}
	if _, err := fx.s.CopySecret(context.Background(), &vaultv1.CopySecretRequest{Actor: ada, Id: fx.secret}); useReason(err) != ReasonApprovalRequired {
		t.Fatalf("direct web copy: %v, want APPROVAL_REQUIRED", err)
	}
	u := fx.prepare(t, ada, "web-1", everyone)
	wantState(t, "web reveal use", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	if err := fx.decide(human("user-carol"), u.GetId(), true); err != nil {
		t.Fatalf("owner approving: %v", err)
	}
	if _, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: token("user-ada", "g-readers"), UseId: u.GetId()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a token redeeming a web use: want PermissionDenied, got %v", err)
	}
	got, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: ada, UseId: u.GetId()})
	if err != nil || got.GetValue() != "p" {
		t.Fatalf("web redeem = %+v, %v", got, err)
	}
	if ev := fx.ca.find("secret.reveal"); ev == nil || ev.Attributes["via"] != "web" {
		t.Fatalf("reveal audit = %+v", ev)
	}
}

func TestApprovalAlwaysApproveOwnerWaitsForTheOtherOwner(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada", "user-bob"}, levelAlwaysApprove)
	u := fx.prepare(t, token("user-ada"), "", everyone)
	wantState(t, "owner use on always-approve", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	if err := fx.decide(human("user-ada"), u.GetId(), true); useReason(err) != ReasonSelfApproval {
		t.Fatalf("requesting owner approving: %v, want SELF_APPROVAL", err)
	}
	if _, err := fx.confirm(fx.fresh(human("user-ada")), u.GetId(), everyone); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("requesting owner confirming while another owner exists: want FailedPrecondition, got %v", err)
	}
	if err := fx.decide(human("user-bob"), u.GetId(), true); err != nil {
		t.Fatalf("other owner approving: %v", err)
	}
	if _, err := fx.s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{Actor: human("user-bob"), Id: fx.secret, FieldKey: "password"}); useReason(err) != ReasonApprovalRequired {
		t.Fatalf("owner's direct web reveal of an always-approve secret: %v, want APPROVAL_REQUIRED", err)
	}
}

func TestApprovalAlwaysApproveDesignatedApproverDecides(t *testing.T) {
	approver := &vaultv1.RaciRule{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-dan", Grants: map[string]string{"A": "allow"}}
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove, approver)
	u := fx.prepare(t, token("user-ada"), "", everyone)
	if u.GetConfirm() {
		t.Fatal("a designated approver exists, so no confirmation")
	}
	if err := fx.decide(human("user-dan"), u.GetId(), true); err != nil {
		t.Fatalf("designated approver approving: %v", err)
	}

	lvl1 := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired, approver)
	v := lvl1.prepare(t, token("user-ada", "g-readers"), "", everyone)
	if err := lvl1.decide(human("user-dan"), v.GetId(), true); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a designated approver on an approval-required secret: want PermissionDenied (owners decide), got %v", err)
	}
}

func TestApprovalAlwaysApproveSoleApproverConfirmsOnce(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove)
	tok := token("user-ada")
	u := fx.prepare(t, tok, "run-7", everyone)
	wantState(t, "sole owner's use", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	if !u.GetConfirm() {
		t.Fatal("nobody else can decide: the use must ask the requester to confirm")
	}
	if err := fx.decide(human("user-ada"), u.GetId(), true); useReason(err) != ReasonSelfApproval {
		t.Fatalf("approving through the queue: %v, want SELF_APPROVAL", err)
	}
	for _, uid := range []string{"user-ada", "user-bob", "user-carol"} {
		if ids := fx.toDecide(t, human(uid)); len(ids) != 0 {
			t.Fatalf("%s's queue = %v, want empty: a confirmation is never queued", uid, ids)
		}
	}
	if _, err := fx.confirm(human("user-ada"), u.GetId(), everyone); useReason(err) != ReasonStepUpRequired {
		t.Fatalf("confirming without a fresh factor: %v, want STEP_UP_REQUIRED", err)
	}
	if _, err := fx.confirm(fx.fresh(human("user-bob")), u.GetId(), everyone); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("someone else confirming: want PermissionDenied, got %v", err)
	}
	got, err := fx.confirm(fx.fresh(human("user-ada")), u.GetId(), everyone)
	if err != nil || got.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED || got.GetConfirmedAtUnix() == 0 {
		t.Fatalf("confirm = %+v, %v", got, err)
	}
	if ev := fx.ca.find("secret.use.confirm"); ev == nil {
		t.Fatal("no secret.use.confirm audit event")
	}
	fx.now = fx.now.Add(5 * time.Minute)
	wantState(t, "a later use in the same task", fx.prepare(t, tok, "run-7", everyone), vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
	wantState(t, "a use in a new task", fx.prepare(t, tok, "run-8", everyone), vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	fx.now = fx.now.Add(runConfirmSpan)
	wantState(t, "the same task after the confirmation lapsed", fx.prepare(t, tok, "run-7", everyone), vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
}

func TestApprovalSingleUserInstallConfirmsInsteadOfWaiting(t *testing.T) {
	// The only person is a non-owner of a seeded folder's approval-required
	// secret whose listed owner no longer signs in.
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	ada := token("user-ada", "g-readers")
	u := fx.prepare(t, ada, "", active("user-ada"))
	if !u.GetConfirm() || u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatalf("single-user use = %+v, want pending with confirm", u)
	}
	if got, err := fx.confirm(fx.fresh(human("user-ada", "g-readers")), u.GetId(), active("user-ada")); err != nil || got.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		t.Fatalf("confirm = %+v, %v", got, err)
	}
	if _, err := fx.confirm(fx.fresh(human("user-ada", "g-readers")), fx.prepare(t, ada, "", active("user-ada")).GetId(), active("user-ada", "user-carol")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("confirm once another owner is active again: want FailedPrecondition, got %v", err)
	}
}

func TestApprovalWithNobodyToDecideIsRefusedAtOnce(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-carol"}, levelApprovalRequired)
	_, err := fx.tryPrepare(token("user-ada", "g-readers"), "", active("user-ada", "user-bob"))
	if status.Code(err) != codes.FailedPrecondition || useReason(err) != ReasonNoApprover {
		t.Fatalf("no active owner in a multi-user install: %v (reason %q), want NO_APPROVER", err, useReason(err))
	}
}

func TestApprovalUnknownDirectoryNeverCountsAsSingleUser(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove,
		&vaultv1.RaciRule{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-approvers", Grants: map[string]string{"A": "allow"}})
	u := fx.prepare(t, token("user-ada"), "", nil)
	if u.GetConfirm() {
		t.Fatal("a group approver may exist and the directory is unknown: no confirmation")
	}
}
