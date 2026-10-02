// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"context"
	"slices"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	vaultsvc "github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"google.golang.org/grpc"
)

func TestSelfMethodsMatchTheVaultsPolicy(t *testing.T) {
	var want []string
	for m, callers := range vaultsvc.CallerPolicy() {
		if callers[vaultsvc.CallerWorkflow] == workloadauth.Self {
			want = append(want, m)
		}
	}
	got := make([]string, 0, len(selfMethods))
	for m := range selfMethods {
		got = append(got, m)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("self methods %v, the vault lists the workflow as self on %v", got, want)
	}
}

func TestAsSelfDropsTheActorOnSelfMethodsOnly(t *testing.T) {
	var sent any
	invoke := func(_ context.Context, _ string, req, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		sent = req
		return nil
	}
	actor := &vaultv1.ActorContext{UserId: "system", IsRoot: true}
	req := &vaultv1.SetSecretRulesetRequest{Actor: actor, SecretId: "s-1"}
	if err := asSelf(context.Background(), vaultv1.VaultService_SetSecretRuleset_FullMethodName, req, nil, nil, invoke); err != nil {
		t.Fatal(err)
	}
	out := sent.(*vaultv1.SetSecretRulesetRequest)
	if out.GetActor() != nil || out.GetSecretId() != "s-1" {
		t.Fatalf("sent %v, want the request without its actor", out)
	}
	if req.GetActor() != actor {
		t.Fatal("the caller's request was changed")
	}

	other := &vaultv1.GetMySecretAccessRequest{Actor: &vaultv1.ActorContext{UserId: "user-1"}, SecretId: "s-1"}
	if err := asSelf(context.Background(), vaultv1.VaultService_GetMySecretAccess_FullMethodName, other, nil, nil, invoke); err != nil {
		t.Fatal(err)
	}
	if sent.(*vaultv1.GetMySecretAccessRequest).GetActor().GetUserId() != "user-1" {
		t.Fatal("an on-behalf method lost its actor")
	}
}
