// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

// Group-kind rule subjects match AD group names CASE-INSENSITIVELY: rule
// subjects come from the admin picker and user memberships from the directory,
// and casing drift between the two must not silently drop a user from a rule.
// User-kind subjects
// remain exact — user IDs are opaque identifiers.

func TestSubjectMatches_GroupNameCaseInsensitive(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"Auditors"}}
	if !subjectMatches(u, RuleSubject{Kind: SubjGroup, Name: "auditors"}) {
		t.Fatalf("group match must be case-insensitive (Auditors vs auditors)")
	}
	if !subjectMatches(u, RuleSubject{Kind: SubjGroup, Name: "AUDITORS"}) {
		t.Fatalf("group match must be case-insensitive (Auditors vs AUDITORS)")
	}
	if subjectMatches(u, RuleSubject{Kind: SubjGroup, Name: "engineers"}) {
		t.Fatalf("non-member must not match")
	}
}

func TestSubjectMatches_UserIDStaysExact(t *testing.T) {
	u := EvalSubject{UserID: "AbC-123"}
	if subjectMatches(u, RuleSubject{Kind: SubjUser, Name: "abc-123"}) {
		t.Fatalf("user-id match must remain exact (ids are opaque)")
	}
	if !subjectMatches(u, RuleSubject{Kind: SubjUser, Name: "AbC-123"}) {
		t.Fatalf("exact user-id must match")
	}
}
