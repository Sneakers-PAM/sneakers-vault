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

// The security settings that used to be stored but ignored now change
// behaviour: allow_api_for_sensitive gates machine access to super-sensitive
// fields, and require_mfa_for_reveal (with per-folder overrides) asks a person
// for a fresh MFA before a reveal or copy.

var stepUpNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type sensFixture struct {
	s       *Server
	ca      *capAudit
	folder  string
	pin     string // type-pin secret: its "pin" field is super-sensitive
	pw      string // type-password secret: an ordinary password
	sa, tok *vaultv1.ActorContext
}

func newSensFixture(t *testing.T) *sensFixture {
	t.Helper()
	fx := &sensFixture{s: newServer(t), ca: &capAudit{}}
	fx.s.audit = fx.ca
	fx.s.uses = newMemUseStore()
	fx.s.now = func() time.Time { return stepUpNow }
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fx.folder = newSharedFolder(t, fx.s)
	pin, err := fx.s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{Actor: carol, Name: "door", FolderId: fx.folder, TypeId: "type-pin", Fields: map[string]string{"pin": "4321"}})
	if err != nil {
		t.Fatal(err)
	}
	fx.pin = pin.GetSecret().GetId()
	fx.pw = secretIn(t, fx.s, carol, fx.folder, "router")
	if _, err := fx.s.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
		Actor: carol, FolderId: fx.folder, Owners: []string{"user-carol"},
		Rules: []*vaultv1.RaciRule{
			{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "sa-ci", Grants: map[string]string{"C": "allow"}},
			{SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "g-agents", Grants: map[string]string{"C": "allow"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	fx.sa = &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-ci"}
	fx.tok = tokenActor("user-ada", false, "g-agents")
	return fx
}

func (fx *sensFixture) setAPI(t *testing.T, on bool) {
	t.Helper()
	if _, err := fx.s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, AllowApiForSensitive: &on}); err != nil {
		t.Fatal(err)
	}
}

func (fx *sensFixture) setRevealStepUp(t *testing.T, on bool) {
	t.Helper()
	if _, err := fx.s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, RequireMfaForReveal: &on}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIForSensitiveOffKeepsSuperSensitiveFieldsFromMachines(t *testing.T) {
	fx := newSensFixture(t)
	ctx := context.Background()
	fx.setAPI(t, false)
	for name, a := range map[string]*vaultv1.ActorContext{"service account": fx.sa, "user token": fx.tok} {
		_, err := fx.s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: a, Id: fx.pin, FieldKey: "pin"})
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonAPISensitiveDisabled {
			t.Fatalf("%s: reason %q", name, got)
		}
		if st := status.Convert(err); st.Message() == "" || !containsAll(st.Message(), "API access to sensitive secrets") {
			t.Fatalf("%s: message %q doesn't name the setting", name, st.Message())
		}
		// An ordinary password stays usable.
		if r, err := fx.s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: a, Id: fx.pw, FieldKey: "password"}); err != nil || r.GetValue() != "p" {
			t.Fatalf("%s: password reveal %v %v", name, r, err)
		}
	}
	if ev := fx.ca.find("secret.reveal.denied"); ev == nil || ev.Attributes["reason"] != ReasonAPISensitiveDisabled {
		t.Fatalf("audit = %+v", ev)
	}
	fx.setAPI(t, true)
	for name, a := range map[string]*vaultv1.ActorContext{"service account": fx.sa, "user token": fx.tok} {
		if r, err := fx.s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: a, Id: fx.pin, FieldKey: "pin"}); err != nil || r.GetValue() != "4321" {
			t.Fatalf("%s with API on: %v %v", name, r, err)
		}
	}
}

func TestAPIForSensitiveOffRefusesPreparingAndRedeemingASuperSensitiveUse(t *testing.T) {
	fx := newSensFixture(t)
	ctx := context.Background()
	fx.setAPI(t, false)
	_, err := fx.s.PrepareSecretUse(ctx, &vaultv1.PrepareSecretUseRequest{Actor: fx.tok, SecretId: fx.pin, FieldKey: "pin", Reveal: true})
	if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonAPISensitiveDisabled {
		t.Fatalf("prepare: reason %q", got)
	}
	// Prepared and approved while allowed, then the switch goes off: redeem refuses.
	fx.setAPI(t, true)
	use, err := fx.s.PrepareSecretUse(ctx, &vaultv1.PrepareSecretUseRequest{Actor: fx.tok, SecretId: fx.pin, FieldKey: "pin", Reveal: true})
	if err != nil {
		t.Fatal(err)
	}
	if use.GetUse().GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		if _, err := fx.s.DecideSecretUse(ctx, &vaultv1.DecideSecretUseRequest{Actor: &vaultv1.ActorContext{UserId: "user-ada", GroupNames: []string{"g-agents"}}, UseId: use.GetUse().GetId(), Approve: true}); err != nil {
			t.Fatal(err)
		}
	}
	fx.setAPI(t, false)
	_, err = fx.s.RedeemSecretUse(ctx, &vaultv1.RedeemSecretUseRequest{Actor: fx.tok, UseId: use.GetUse().GetId()})
	if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonAPISensitiveDisabled {
		t.Fatalf("redeem: reason %q", got)
	}
}

func TestRevealStepUpFollowsTheGlobalSettingAndFolderOverrides(t *testing.T) {
	fx := newSensFixture(t)
	ctx := context.Background()
	stale := &vaultv1.ActorContext{UserId: "user-carol", MfaVerifiedAtUnix: stepUpNow.Add(-time.Hour).Unix()}
	fresh := &vaultv1.ActorContext{UserId: "user-carol", MfaVerifiedAtUnix: stepUpNow.Add(-time.Minute).Unix()}
	reveal := func(a *vaultv1.ActorContext) error {
		_, err := fx.s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: a, Id: fx.pw, FieldKey: "password"})
		return err
	}
	copySecret := func(a *vaultv1.ActorContext) error {
		_, err := fx.s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: a, Id: fx.pw})
		return err
	}
	setFolder := func(id string, m vaultv1.StepUpMode) {
		t.Helper()
		if _, err := fx.s.SetFolderRevealStepUp(ctx, &vaultv1.SetFolderRevealStepUpRequest{Actor: siteAdmin, FolderId: id, Mode: m}); err != nil {
			t.Fatal(err)
		}
	}
	for _, op := range []func(*vaultv1.ActorContext) error{reveal, copySecret} {
		// Off globally, no override: no step-up.
		fx.setRevealStepUp(t, false)
		setFolder(fx.folder, vaultv1.StepUpMode_STEP_UP_MODE_UNSPECIFIED)
		if err := op(stale); err != nil {
			t.Fatalf("step-up off: %v", err)
		}
		// On globally: stale MFA refused, fresh allowed.
		fx.setRevealStepUp(t, true)
		if got := reasonOf(t, op(stale), codes.PermissionDenied); got != ReasonStepUpRequired {
			t.Fatalf("global on: reason %q", got)
		}
		if err := op(fresh); err != nil {
			t.Fatalf("global on, fresh MFA: %v", err)
		}
		// A folder override of OFF wins over the global ON.
		setFolder(fx.folder, vaultv1.StepUpMode_STEP_UP_MODE_OFF)
		if err := op(stale); err != nil {
			t.Fatalf("folder off: %v", err)
		}
		// A folder override of REQUIRE wins over the global OFF.
		fx.setRevealStepUp(t, false)
		setFolder(fx.folder, vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE)
		if got := reasonOf(t, op(stale), codes.PermissionDenied); got != ReasonStepUpRequired {
			t.Fatalf("folder require: reason %q", got)
		}
	}
	if ev := fx.ca.find("secret.reveal.step_up_required"); ev == nil || ev.ActorUserID != "user-carol" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestRevealStepUpIsInheritedDownTheTree(t *testing.T) {
	fx := newSensFixture(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	child, err := fx.s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: carol, Name: "child", ParentId: fx.folder})
	if err != nil {
		t.Fatal(err)
	}
	sid := secretIn(t, fx.s, carol, child.GetFolder().GetId(), "nested")
	if _, err := fx.s.SetFolderRevealStepUp(ctx, &vaultv1.SetFolderRevealStepUpRequest{Actor: siteAdmin, FolderId: fx.folder, Mode: vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE}); err != nil {
		t.Fatal(err)
	}
	_, err = fx.s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: carol, Id: sid, FieldKey: "password"})
	if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonStepUpRequired {
		t.Fatalf("reason %q", got)
	}
}

func TestMachinesAreExemptFromRevealStepUp(t *testing.T) {
	fx := newSensFixture(t)
	fx.setRevealStepUp(t, true)
	if _, err := fx.s.RevealSecretFieldForPrincipal(context.Background(), &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: fx.sa, Id: fx.pw, FieldKey: "password"}); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyASiteAdminSetsAFolderStepUp(t *testing.T) {
	fx := newSensFixture(t)
	_, err := fx.s.SetFolderRevealStepUp(context.Background(), &vaultv1.SetFolderRevealStepUpRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, FolderId: fx.folder, Mode: vaultv1.StepUpMode_STEP_UP_MODE_OFF})
	if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonNotSiteAdmin {
		t.Fatalf("folder owner set step-up: %q", got)
	}
	resp, err := fx.s.SetFolderRevealStepUp(context.Background(), &vaultv1.SetFolderRevealStepUpRequest{Actor: siteAdmin, FolderId: fx.folder, Mode: vaultv1.StepUpMode_STEP_UP_MODE_OFF})
	if err != nil || resp.GetFolder().GetRevealStepUp() != vaultv1.StepUpMode_STEP_UP_MODE_OFF {
		t.Fatalf("%v %v", resp, err)
	}
	if ev := fx.ca.find("folder.reveal_step_up.set"); ev == nil || ev.Attributes["mode"] != "STEP_UP_MODE_OFF" {
		t.Fatalf("audit = %+v", ev)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
