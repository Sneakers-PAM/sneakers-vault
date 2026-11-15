// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

// TestResolve_OwnGrantFlagsReadWithoutEscalation covers the "contribute, own
// reveal" shape: Author allowed (R=allow), Read restricted to own (C=own).
// Read must come back Allowed+OwnOnly from the explicit C=own cell, and the
// author-implies-read escalation (which would otherwise hand out a blanket
// read) must never fire, since Read already matched explicitly.
func TestResolve_OwnGrantFlagsReadWithoutEscalation(t *testing.T) {
	u := EvalSubject{UserID: "svc1", GroupNames: []string{"Automation"}}
	chain := []CategoryRuleset{rs("Hosts", nil,
		rule(SubjGroup, "Automation", map[Action]Grant{ActAuthor: GrantAllow, ActRead: GrantOwn}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed || !got.Read.OwnOnly {
		t.Fatalf("want Read allowed+OwnOnly, got %+v", got.Read)
	}
	if !got.Author.Allowed {
		t.Fatalf("want Author allowed, got %+v", got.Author)
	}
}

// TestResolve_OwnGrantAloneNeverImpliesBlanketRead confirms a bare C=own cell
// (no Author) still comes back OwnOnly, never escalating to a blanket read.
func TestResolve_OwnGrantAloneNeverImpliesBlanketRead(t *testing.T) {
	u := EvalSubject{UserID: "svc1"}
	chain := []CategoryRuleset{rs("Hosts", nil,
		rule(SubjUser, "svc1", map[Action]Grant{ActRead: GrantOwn}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed || !got.Read.OwnOnly {
		t.Fatalf("want Read allowed+OwnOnly, got %+v", got.Read)
	}
}

// TestResolve_OwnGrantNeverAppliesToAdminOrOwner: site-admin and category
// owners keep their existing unrestricted read (existing levels unchanged),
// even in a chain that also carries an own-only cell for someone else.
func TestResolve_OwnGrantNeverAppliesToAdminOrOwner(t *testing.T) {
	admin := EvalSubject{UserID: "adm", IsSiteAdmin: true}
	owner := EvalSubject{UserID: "own"}
	chain := []CategoryRuleset{rs("Hosts", []string{"own"},
		rule(SubjGroup, "Automation", map[Action]Grant{ActRead: GrantOwn}),
	)}
	if got := Resolve(admin, chain); !got.Read.Allowed || got.Read.OwnOnly {
		t.Fatalf("admin should read unrestricted, got %+v", got.Read)
	}
	if got := Resolve(owner, chain); !got.Read.Allowed || got.Read.OwnOnly {
		t.Fatalf("owner should read unrestricted, got %+v", got.Read)
	}
}

// TestResolve_OwnGrantDoesNotChangeAllowDenyBehavior: a plain allow/deny
// chain resolves exactly as before — adding GrantOwn to the vocabulary must
// not perturb the existing two states.
func TestResolve_OwnGrantDoesNotChangeAllowDenyBehavior(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActRead: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed || got.Read.OwnOnly {
		t.Fatalf("plain allow must stay unrestricted, got %+v", got.Read)
	}
}
