// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestResolve_DraftChainDiffers(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"Contractors"}}
	saved := []CategoryRuleset{rs("IT", nil, rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow}))}
	// Draft adds a deny for Contractors ABOVE the everyone-allow.
	draft := []CategoryRuleset{rs("IT", nil,
		rule(SubjGroup, "Contractors", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow}),
	)}
	if !Resolve(u, saved).Read.Allowed {
		t.Fatalf("saved: contractor should read")
	}
	if Resolve(u, draft).Read.Allowed {
		t.Fatalf("draft: contractor should be denied (dry-run preview)")
	}
}
