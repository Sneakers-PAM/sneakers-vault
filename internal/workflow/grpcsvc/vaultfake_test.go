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
// implements EnqueueRotation (the rotate action) plus Get/SetSecretRuleset (the
// temporary read grant/revoke the lease lifecycle drives), backed by an
// in-memory per-secret ruleset. Every other method is promoted from the nil
// embedded interface and would panic if invoked — no test exercises those.
type fakeVaultClient struct {
	vaultv1.VaultServiceClient

	mu       sync.Mutex
	calls    []*vaultv1.EnqueueRotationRequest
	rulesets map[string][]*vaultv1.RaciRule // secretID -> ordered ruleset
}

func newFakeVaultClient() *fakeVaultClient {
	return &fakeVaultClient{rulesets: map[string][]*vaultv1.RaciRule{}}
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
