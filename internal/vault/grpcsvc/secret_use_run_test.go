// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func (fx *useFixture) prepareInRun(t *testing.T, actor *vaultv1.ActorContext, runID, purpose string) *vaultv1.SecretUse {
	t.Helper()
	resp, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: actor, SecretId: fx.secret, FieldKey: "password", Argv: []string{"ssh", "admin@router-01"},
		ClientLabel: "laptop", RunId: runID, Purpose: purpose,
	})
	if err != nil {
		t.Fatalf("PrepareSecretUse: %v", err)
	}
	return resp.GetUse()
}

func (fx *useFixture) listPending(actor *vaultv1.ActorContext, runID string) ([]string, error) {
	resp, err := fx.s.ListPendingSecretUses(context.Background(), &vaultv1.ListPendingSecretUsesRequest{Actor: actor, RunId: runID})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, u := range resp.GetUses() {
		ids = append(ids, u.GetId())
	}
	slices.Sort(ids)
	return ids, nil
}

func sorted(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestSecretUsePrepareStoresRunIDAndPurpose(t *testing.T) {
	fx := newUseFixture(t)
	use := fx.prepareInRun(t, fx.token, "run_AB-12", "rotate the edge router")
	if use.GetRunId() != "run_AB-12" || use.GetPurpose() != "rotate the edge router" {
		t.Fatalf("prepared use = %+v", use)
	}
	got, err := fx.s.GetSecretUse(context.Background(), &vaultv1.GetSecretUseRequest{Actor: fx.token, UseId: use.GetId()})
	if err != nil || got.GetUse().GetRunId() != "run_AB-12" || got.GetUse().GetPurpose() != "rotate the edge router" {
		t.Fatalf("GetSecretUse = %+v, %v", got, err)
	}
	if plain := fx.prepare(t); plain.GetRunId() != "" || plain.GetPurpose() != "" {
		t.Fatalf("a use without a run = %+v", plain)
	}
}

func TestSecretUsePrepareValidatesRunIDAndPurpose(t *testing.T) {
	fx := newUseFixture(t)
	for name, tc := range map[string]struct{ runID, purpose string }{
		"run id with a space":       {runID: "run 1"},
		"run id with a slash":       {runID: "run/1"},
		"run id with a dot":         {runID: "run.1"},
		"run id not ascii":          {runID: "runé1"},
		"run id over 64":            {runID: strings.Repeat("a", 65)},
		"purpose over 200":          {purpose: strings.Repeat("x", 201)},
		"purpose over 200 runes":    {purpose: strings.Repeat("é", 201)},
		"purpose with a newline":    {purpose: "line one\nline two"},
		"purpose with an escape":    {purpose: "red \x1b[31m text"},
		"purpose not utf-8":         {purpose: "bad \xff byte"},
		"purpose with a nul":        {purpose: "a\x00b"},
		"purpose with a tab":        {purpose: "a\tb"},
		"run id bad, purpose fine":  {runID: "run#1", purpose: "fine"},
		"run id fine, purpose long": {runID: "run_1", purpose: strings.Repeat("x", 201)},
	} {
		_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
			Actor: fx.token, SecretId: fx.secret, FieldKey: "password", Argv: []string{"ssh", "x"},
			RunId: tc.runID, Purpose: tc.purpose,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", name, err)
		}
	}
	edge := fx.prepareInRun(t, fx.token, strings.Repeat("A", 64), strings.Repeat("é", 200))
	if len(edge.GetRunId()) != 64 {
		t.Fatalf("a 64-character run id and a 200-character purpose are allowed: %+v", edge)
	}
}

func TestSecretUseAuditCarriesTheRunID(t *testing.T) {
	fx := newUseFixture(t)
	approved := fx.prepareInRun(t, fx.token, "run_audit", "deploy")
	if err := fx.decide(fx.owner, approved.GetId(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.redeem(fx.token, approved.GetId()); err != nil {
		t.Fatal(err)
	}
	denied := fx.prepareInRun(t, fx.token, "run_audit", "deploy")
	if err := fx.decide(fx.owner, denied.GetId(), false); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"secret.use.prepare", "secret.use.approve", "secret.use.deny", "secret.use.redeem"} {
		ev := fx.ca.find(action)
		if ev == nil {
			t.Fatalf("no %s audit event", action)
		}
		if ev.Attributes["run_id"] != "run_audit" {
			t.Errorf("%s audit run_id = %q, want run_audit", action, ev.Attributes["run_id"])
		}
	}
}

func TestSecretUseRefusalAuditCarriesTheRunID(t *testing.T) {
	fx := newUseFixture(t)
	_, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: tokenActor("user-bob", false), SecretId: fx.secret, FieldKey: "password", Argv: []string{"ssh", "x"}, RunId: "run_refused",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("prepare without access: want PermissionDenied, got %v", err)
	}
	if ev := fx.ca.find("secret.use.prepare"); ev == nil || ev.Attributes["run_id"] != "run_refused" {
		t.Fatalf("refused prepare audit = %+v", ev)
	}
	use := fx.prepareInRun(t, fx.token, "run_other", "")
	other := tokenActor("user-ada", false, "g-agents")
	other.TokenId = "utok-other"
	if _, err := fx.redeem(other, use.GetId()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("redeem by another token: want PermissionDenied, got %v", err)
	}
	if ev := fx.ca.find("secret.use.redeem"); ev == nil || ev.Attributes["run_id"] != "run_other" {
		t.Fatalf("refused redeem audit = %+v", ev)
	}
}

func TestListPendingSecretUsesFiltersByRunForTheOwner(t *testing.T) {
	fx := newUseFixture(t)
	a1 := fx.prepareInRun(t, fx.token, "run_a", "")
	a2 := fx.prepareInRun(t, fx.token, "run_a", "")
	b := fx.prepareInRun(t, fx.token, "run_b", "")
	none := fx.prepare(t)
	if got, err := fx.listPending(fx.owner, "run_a"); err != nil || !slices.Equal(got, sorted(a1.GetId(), a2.GetId())) {
		t.Fatalf("owner run_a = %v, %v", got, err)
	}
	if got, err := fx.listPending(fx.owner, ""); err != nil || !slices.Equal(got, sorted(a1.GetId(), a2.GetId(), b.GetId(), none.GetId())) {
		t.Fatalf("owner without a run = %v, %v", got, err)
	}
	if _, err := fx.listPending(fx.owner, "run a"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a malformed run id filter: want InvalidArgument, got %v", err)
	}
}

func TestListPendingSecretUsesTokenSeesOnlyItsOwnRun(t *testing.T) {
	fx := newUseFixture(t)
	mine := fx.prepareInRun(t, fx.token, "run_shared", "")
	_ = fx.prepareInRun(t, fx.token, "run_elsewhere", "")
	sibling := tokenActor("user-ada", false, "g-agents")
	sibling.TokenId = "utok-sibling"
	_ = fx.prepareInRun(t, sibling, "run_shared", "")
	stranger := tokenActor("user-bob", false, "g-agents")
	stranger.TokenId = "utok-bob"
	theirs := fx.prepareInRun(t, stranger, "run_shared", "")
	decided := fx.prepareInRun(t, fx.token, "run_shared", "")
	if err := fx.decide(fx.owner, decided.GetId(), true); err != nil {
		t.Fatal(err)
	}

	if got, err := fx.listPending(fx.token, "run_shared"); err != nil || !slices.Equal(got, []string{mine.GetId()}) {
		t.Fatalf("token run_shared = %v, %v", got, err)
	}
	if _, err := fx.listPending(fx.token, ""); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("token without a run id: want PermissionDenied, got %v", err)
	}
	if got, err := fx.listPending(stranger, "run_shared"); err != nil || !slices.Equal(got, []string{theirs.GetId()}) {
		t.Fatalf("another user's token in the same run = %v, %v", got, err)
	}
	if got, err := fx.listPending(stranger, "run_elsewhere"); err != nil || len(got) != 0 {
		t.Fatalf("another user's token sees %v, %v", got, err)
	}
	if _, err := fx.listPending(agentGroupActor("sa-1"), "run_shared"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service account: want PermissionDenied, got %v", err)
	}
}

func TestSecretUseStoredWithoutRunFieldsStillLoads(t *testing.T) {
	raw := []byte(`{"id":"use-old","secretId":"s-1","fieldKey":"password","argv":["ssh","h"],"userId":"user-ada","tokenId":"utok-1","state":"SECRET_USE_STATE_PENDING","expiresAtUnix":"4102444800"}`)
	u := &vaultv1.SecretUse{}
	if err := protojson.Unmarshal(raw, u); err != nil {
		t.Fatalf("an old stored use no longer loads: %v", err)
	}
	if u.GetId() != "use-old" || u.GetRunId() != "" || u.GetPurpose() != "" {
		t.Fatalf("old use = %+v", u)
	}
}
