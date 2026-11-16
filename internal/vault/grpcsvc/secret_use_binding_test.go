// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// prepareAs asks for one use with its own command and client label.
func (fx *approvalFixture) prepareAs(actor *vaultv1.ActorContext, runID, label string, argv []string) (*vaultv1.SecretUse, error) {
	resp, err := fx.s.PrepareSecretUse(context.Background(), &vaultv1.PrepareSecretUseRequest{
		Actor: actor, SecretId: fx.secret, FieldKey: "password", ClientLabel: label, RunId: runID,
		Argv: argv, ActiveUsers: everyone,
	})
	return resp.GetUse(), err
}

// confirmedRun prepares and confirms one use of a run, as its requester.
func confirmedRun(t *testing.T, fx *approvalFixture, tok *vaultv1.ActorContext, runID string) *vaultv1.SecretUse {
	t.Helper()
	u, err := fx.prepareAs(tok, runID, "laptop", []string{"ssh", "admin@dc-01"})
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, "first use", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	got, err := fx.confirm(fx.fresh(human(tok.GetUserId())), u.GetId(), everyone)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	wantState(t, "confirmed use", got, vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED)
	return got
}

func TestApprovalIsBoundToTheExactUseNotTheRun(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove)
	tok := token("user-ada")
	confirmedRun(t, fx, tok, "run-7")

	cases := map[string]struct {
		label string
		argv  []string
	}{
		"a second command":       {"laptop", []string{"cat", "/etc/shadow"}},
		"a second client label":  {"other-agent", []string{"ssh", "admin@dc-01"}},
		"the same command again": {"laptop", []string{"ssh", "admin@dc-01"}},
	}
	for name, c := range cases {
		u, err := fx.prepareAs(tok, "run-7", c.label, c.argv)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		wantState(t, name+" with an approved run id", u, vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	}
}

func TestApprovalRunIDCoversNoConcurrentRequests(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove)
	tok := token("user-ada")
	confirmedRun(t, fx, tok, "run-7")

	var wg sync.WaitGroup
	states := make([]vaultv1.SecretUseState, 3)
	for i := range states {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := fx.prepareAs(tok, "run-7", "laptop", []string{"ssh", "host-" + string(rune('a'+i))})
			if err == nil {
				states[i] = u.GetState()
			}
		}()
	}
	wg.Wait()
	for i, st := range states {
		if st != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
			t.Errorf("concurrent request %d = %v, want PENDING", i, st)
		}
	}
}

func TestApprovedUseRedeemsExactlyOnce(t *testing.T) {
	fx := newApprovalFixture(t, []string{"user-ada"}, levelAlwaysApprove)
	tok := token("user-ada")
	u := confirmedRun(t, fx, tok, "run-7")

	var wg sync.WaitGroup
	var mu sync.Mutex
	won, refused := 0, 0
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fx.s.RedeemSecretUse(context.Background(), &vaultv1.RedeemSecretUseRequest{Actor: tok, UseId: u.GetId()})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won++
			} else if status.Code(err) == codes.FailedPrecondition {
				refused++
			}
		}()
	}
	wg.Wait()
	if won != 1 || refused != 2 {
		t.Fatalf("redeemed %d times, refused %d; want exactly 1 and 2", won, refused)
	}
}
