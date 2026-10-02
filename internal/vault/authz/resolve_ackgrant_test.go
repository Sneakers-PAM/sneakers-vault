// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

// AckGrant is the ack-rule decision: it evaluates only whether an ack rule
// matches the subject. Ack is independent of read (Informed is an awareness
// tier, not an access tier), so AckGrant is equivalent to Resolve(...).Ack.

func TestAckGrant_EveryoneAckAllow_UngatedByRead(t *testing.T) {
	// An everyone ack-allow rule with NO read rule: both AckGrant and
	// Resolve.Ack report the ack match, independent of the (denied) read.
	chain := []CategoryRuleset{{
		Name: "Finance",
		Rules: []Rule{{
			Subject: RuleSubject{Kind: SubjEveryone},
			Grants:  map[Action]Grant{ActAck: GrantAllow},
		}},
	}}
	u := EvalSubject{UserID: "u1"}
	if got := AckGrant(u, chain); !got.Allowed {
		t.Fatalf("AckGrant everyone-ack: Allowed=false, want true (reason %q)", got.Reason)
	}
	// Sanity: Resolve.Ack is independent of read — still allowed even though
	// there is no read grant.
	res := Resolve(u, chain)
	if !res.Ack.Allowed {
		t.Fatalf("Resolve.Ack should be allowed independent of read")
	}
	if res.Read.Allowed {
		t.Fatalf("Resolve.Read should still be denied (no read rule)")
	}
}

func TestAckGrant_NoAckRule_Denied(t *testing.T) {
	chain := []CategoryRuleset{{
		Name: "IT",
		Rules: []Rule{{
			Subject: RuleSubject{Kind: SubjEveryone},
			Grants:  map[Action]Grant{ActRead: GrantAllow},
		}},
	}}
	if AckGrant(EvalSubject{UserID: "u1"}, chain).Allowed {
		t.Fatalf("AckGrant with no ack rule: want denied")
	}
}

func TestAckGrant_GroupAck_MatchesMembership(t *testing.T) {
	chain := []CategoryRuleset{{
		Name: "Finance",
		Rules: []Rule{{
			Subject: RuleSubject{Kind: SubjGroup, Name: "auditors"},
			Grants:  map[Action]Grant{ActAck: GrantAllow},
		}},
	}}
	if !AckGrant(EvalSubject{UserID: "u1", GroupNames: []string{"auditors"}}, chain).Allowed {
		t.Fatalf("AckGrant group-ack member: want allowed")
	}
	if AckGrant(EvalSubject{UserID: "u2", GroupNames: []string{"other"}}, chain).Allowed {
		t.Fatalf("AckGrant group-ack non-member: want denied")
	}
}

func TestAckGrant_OwnerDoesNotAutoAck(t *testing.T) {
	// Owners auto read/approve/author but NOT ack — AckGrant must not grant.
	chain := []CategoryRuleset{{
		Name:   "Finance",
		Owners: []string{"owner1"},
	}}
	if AckGrant(EvalSubject{UserID: "owner1"}, chain).Allowed {
		t.Fatalf("owner should not auto-ack")
	}
}
