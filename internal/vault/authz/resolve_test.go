// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestResolve_InformedIndependentOfRead(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	// Everyone denied read, but IT-Staff granted ack (informed): informed is an
	// awareness tier, not an access tier, so it resolves true even though read
	// is denied — you can notify someone who can't reveal.
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActAck: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if got.Read.Allowed {
		t.Fatalf("read should be denied")
	}
	if !got.Ack.Allowed {
		t.Fatalf("ack (informed) must be independent of read: %+v", got.Ack)
	}
}

func TestResolve_ReadableUserActs(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow, ActAck: GrantAllow}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActApprove: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed || !got.Ack.Allowed || !got.Approve.Allowed {
		t.Fatalf("expected read+ack+approve allowed, got %+v", got)
	}
	if got.Author.Allowed {
		t.Fatalf("author had no allow rule, should be denied")
	}
}
