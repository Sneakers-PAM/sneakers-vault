// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// fakeVaultClient is a minimal vaultv1.VaultServiceClient test double: it
// implements EnqueueRotation (the rotate action), Get/SetSecretRuleset (the
// temporary read grant/revoke the lease lifecycle drives, backed by an
// in-memory per-secret ruleset), and the check-out checks' GetMySecretAccess,
// GetSecret and ListSecretTypes. Every other method is promoted from the nil
// embedded interface and would panic if invoked — no test exercises those.
type fakeVaultClient struct {
	vaultv1.VaultServiceClient

	mu       sync.Mutex
	calls    []*vaultv1.EnqueueRotationRequest
	rulesets map[string][]*vaultv1.RaciRule // secretID -> ordered ruleset
	// noRead lists "secretID|userID" pairs the fake vault denies read on;
	// everyone else may read. checkoutOff lists secrets whose type has
	// check-out off; every other secret's type allows it.
	noRead      map[string]bool
	noApprove   map[string]bool // "secretID|userID" without RACI A
	checkoutOff map[string]bool
	// accessActors records the actor of each GetMySecretAccess call.
	accessActors []*vaultv1.ActorContext
}

func newFakeVaultClient() *fakeVaultClient {
	return &fakeVaultClient{rulesets: map[string][]*vaultv1.RaciRule{}, noRead: map[string]bool{}, noApprove: map[string]bool{}, checkoutOff: map[string]bool{}}
}

func (f *fakeVaultClient) denyRead(secretID, userID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noRead[secretID+"|"+userID] = true
}

func (f *fakeVaultClient) denyApprove(secretID, userID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noApprove[secretID+"|"+userID] = true
}

func (f *fakeVaultClient) disableCheckout(secretID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkoutOff[secretID] = true
}

func (f *fakeVaultClient) GetMySecretAccess(_ context.Context, in *vaultv1.GetMySecretAccessRequest, _ ...grpc.CallOption) (*vaultv1.GetMySecretAccessResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accessActors = append(f.accessActors, in.GetActor())
	key := in.GetSecretId() + "|" + in.GetActor().GetUserId()
	read := !f.noRead[key]
	return &vaultv1.GetMySecretAccessResponse{Access: &vaultv1.FolderAccess{Read: read, Reveal: read, Approve: !f.noApprove[key]}}, nil
}

func (f *fakeVaultClient) GetSecret(_ context.Context, in *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	typeID := "type-checkout"
	if f.checkoutOff[in.GetId()] {
		typeID = "type-no-checkout"
	}
	return &vaultv1.GetSecretResponse{Secret: &vaultv1.Secret{Id: in.GetId(), TypeId: typeID}}, nil
}

func (f *fakeVaultClient) ListSecretTypes(context.Context, *vaultv1.ListSecretTypesRequest, ...grpc.CallOption) (*vaultv1.ListSecretTypesResponse, error) {
	return &vaultv1.ListSecretTypesResponse{Types: []*vaultv1.SecretType{
		{Id: "type-checkout", Name: "Domain account", Checkout: true},
		{Id: "type-no-checkout", Name: "Password", Checkout: false},
	}}, nil
}

func (f *fakeVaultClient) EnqueueRotation(_ context.Context, in *vaultv1.EnqueueRotationRequest, _ ...grpc.CallOption) (*vaultv1.EnqueueRotationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return &vaultv1.EnqueueRotationResponse{Ok: true}, nil
}

func (f *fakeVaultClient) GetSecretRuleset(_ context.Context, in *vaultv1.GetSecretRulesetRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretRulesetResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rules := append([]*vaultv1.RaciRule(nil), f.rulesets[in.GetSecretId()]...)
	return &vaultv1.GetSecretRulesetResponse{Rules: rules}, nil
}

func (f *fakeVaultClient) SetSecretRuleset(_ context.Context, in *vaultv1.SetSecretRulesetRequest, _ ...grpc.CallOption) (*vaultv1.SetSecretRulesetResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rules := append([]*vaultv1.RaciRule(nil), in.GetRules()...)
	f.rulesets[in.GetSecretId()] = rules
	return &vaultv1.SetSecretRulesetResponse{Rules: rules}, nil
}

// secretRuleset returns a copy of the current in-memory ruleset for a secret
// (test assertion helper).
func (f *fakeVaultClient) secretRuleset(secretID string) []*vaultv1.RaciRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*vaultv1.RaciRule(nil), f.rulesets[secretID]...)
}

func (f *fakeVaultClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeVaultClient) lastCall() *vaultv1.EnqueueRotationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeVaultClient) MoveFolder(_ context.Context, in *vaultv1.MoveFolderRequest, _ ...grpc.CallOption) (*vaultv1.MoveFolderResponse, error) {
	return &vaultv1.MoveFolderResponse{Folder: &vaultv1.Folder{Id: in.GetId(), ParentId: in.GetNewParentId()}}, nil
}

func (f *fakeVaultClient) UpdateSecret(_ context.Context, in *vaultv1.UpdateSecretRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecretResponse, error) {
	return &vaultv1.UpdateSecretResponse{Secret: &vaultv1.Secret{Id: in.GetId(), FolderId: in.GetDestFolderId()}}, nil
}
