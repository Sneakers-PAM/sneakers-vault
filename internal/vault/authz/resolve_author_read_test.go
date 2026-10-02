// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestResolve_AuthorImpliesRead(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	// Everyone denied read, but IT-Staff granted author → author must still read.
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActAuthor: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if !got.Read.Allowed {
		t.Fatalf("author should imply read, got %+v", got.Read)
	}
	if got.Read.Reason != "author implies read" {
		t.Fatalf("want reason 'author implies read', got %q", got.Read.Reason)
	}
	if !got.Author.Allowed {
		t.Fatalf("author should be allowed, got %+v", got.Author)
	}
}

func TestResolve_NonAuthorStillReadGated(t *testing.T) {
	// A non-author under the same chain stays read-denied (author-implies-read
	// must not leak to users who aren't authors).
	u := EvalSubject{UserID: "u2", GroupNames: []string{"Contractors"}}
	chain := []CategoryRuleset{rs("IT", nil,
		rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantDeny}),
		rule(SubjGroup, "IT-Staff", map[Action]Grant{ActAuthor: GrantAllow}),
	)}
	got := Resolve(u, chain)
	if got.Read.Allowed {
		t.Fatalf("non-author should stay read-denied, got %+v", got.Read)
	}
	if got.Author.Allowed {
		t.Fatalf("non-author should not author, got %+v", got.Author)
	}
}
