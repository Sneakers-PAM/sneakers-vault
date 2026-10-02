// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestResolve_ApproverImpliesRead(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActApprove: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed {
		t.Fatalf("approver should imply read, got %+v", got.Read)
	}
	if got.Read.Reason != "approver implies read" {
		t.Fatalf("want reason 'approver implies read', got %q", got.Read.Reason)
	}
	if !got.Approve.Allowed {
		t.Fatalf("approve should be allowed, got %+v", got.Approve)
	}
}

func TestResolve_AckDoesNotImplyRead(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActAck: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if got.Read.Allowed {
		t.Fatalf("ack must NOT confer read, got %+v", got.Read)
	}
	// Ack (informed) is independent of read: a grant is a grant, regardless
	// of the (denied) read outcome.
	if !got.Ack.Allowed {
		t.Fatalf("ack should be allowed independent of read, got %+v", got.Ack)
	}
}
