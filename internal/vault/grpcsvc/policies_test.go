// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// findPolicy returns the policy with id from a ListPasswordPolicies response.
func findPolicy(policies []*vaultv1.PasswordPolicy, id string) *vaultv1.PasswordPolicy {
	for _, p := range policies {
		if p.GetId() == id {
			return p
		}
	}
	return nil
}

// TestBuiltinDefaultPolicyHardLocked covers the shipped "Default" password
// policy (pwpolicy-default): it must remain non-deletable even after the org
// default is re-pointed at another policy, while staying editable.
func TestBuiltinDefaultPolicyHardLocked(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	actor := &vaultv1.ActorContext{UserId: "user-carol"}

	// Create a custom policy and re-point the org default at it.
	saved, err := s.SavePasswordPolicy(ctx, &vaultv1.SavePasswordPolicyRequest{
		Actor: actor,
		Policy: &vaultv1.PasswordPolicy{
			Name: "Custom", MinLength: 16,
		},
	})
	if err != nil {
		t.Fatalf("SavePasswordPolicy (create custom): %v", err)
	}
	customID := saved.GetPolicy().GetId()

	if _, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
		Actor:                   actor,
		DefaultPasswordPolicyId: &customID,
	}); err != nil {
		t.Fatalf("UpdateSecuritySettings: %v", err)
	}

	// The builtin is no longer the org default, but must still be blocked.
	del, err := s.DeletePasswordPolicy(ctx, &vaultv1.DeletePasswordPolicyRequest{
		Actor: actor, Id: builtinDefaultPolicyID,
	})
	if err != nil {
		t.Fatalf("DeletePasswordPolicy(builtin): %v", err)
	}
	if del.GetRemoved() {
		t.Fatalf("builtin default policy was deleted; want Removed=false")
	}

	// Listing must report it as non-deletable, not the org default, unused.
	list, err := s.ListPasswordPolicies(ctx, &vaultv1.ListPasswordPoliciesRequest{})
	if err != nil {
		t.Fatalf("ListPasswordPolicies: %v", err)
	}
	builtin := findPolicy(list.GetPolicies(), builtinDefaultPolicyID)
	if builtin == nil {
		t.Fatalf("builtin default policy missing from list")
	}
	if builtin.GetDeletable() {
		t.Fatalf("builtin default policy reported Deletable=true, want false")
	}
	if builtin.GetIsDefault() {
		t.Fatalf("builtin default policy reported IsDefault=true after re-pointing org default")
	}
	if builtin.GetByTypeFields() != 0 {
		t.Fatalf("builtin default policy unexpectedly referenced by type fields: %d", builtin.GetByTypeFields())
	}

	// Re-point the org default back to the builtin so the custom policy is no
	// longer the org default (and is therefore free to delete).
	builtinID := builtinDefaultPolicyID
	if _, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
		Actor: actor, DefaultPasswordPolicyId: &builtinID,
	}); err != nil {
		t.Fatalf("UpdateSecuritySettings (restore default): %v", err)
	}

	// A normal custom policy (not default, not in-use) stays deletable and
	// actually deletes.
	list2, err := s.ListPasswordPolicies(ctx, &vaultv1.ListPasswordPoliciesRequest{})
	if err != nil {
		t.Fatalf("ListPasswordPolicies (after restore): %v", err)
	}
	customEntry := findPolicy(list2.GetPolicies(), customID)
	if customEntry == nil {
		t.Fatalf("custom policy missing from list")
	}
	if !customEntry.GetDeletable() {
		t.Fatalf("custom policy reported Deletable=false, want true")
	}
	delCustom, err := s.DeletePasswordPolicy(ctx, &vaultv1.DeletePasswordPolicyRequest{
		Actor: actor, Id: customID,
	})
	if err != nil {
		t.Fatalf("DeletePasswordPolicy(custom): %v", err)
	}
	if !delCustom.GetRemoved() {
		t.Fatalf("custom policy was not deleted; want Removed=true")
	}

	// Editing the builtin via SavePasswordPolicy must still work.
	editedName := "Default (Hardened)"
	edited, err := s.SavePasswordPolicy(ctx, &vaultv1.SavePasswordPolicyRequest{
		Actor: actor,
		Policy: &vaultv1.PasswordPolicy{
			Id: builtinDefaultPolicyID, Name: editedName, MinLength: 20,
		},
	})
	if err != nil {
		t.Fatalf("SavePasswordPolicy(builtin edit): %v", err)
	}
	if edited.GetPolicy().GetName() != editedName {
		t.Fatalf("builtin policy name not updated: got %q, want %q", edited.GetPolicy().GetName(), editedName)
	}
	if edited.GetPolicy().GetMinLength() != 20 {
		t.Fatalf("builtin policy min length not updated: got %d, want 20", edited.GetPolicy().GetMinLength())
	}
	if edited.GetPolicy().GetDeletable() {
		t.Fatalf("edited builtin policy reported Deletable=true, want false")
	}
}
