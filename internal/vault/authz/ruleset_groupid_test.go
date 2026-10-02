// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

// A GROUP rule that carries a directory group id matches on the id only, so a
// rename changes nothing and a different group that takes the old name gains
// nothing. A legacy rule with only a name keeps matching on the name.

func TestGroupRuleWithAnIDMatchesOnTheID(t *testing.T) {
	rule := RuleSubject{Kind: SubjGroup, Name: "Ops", ID: "g-123"}
	if !subjectMatches(EvalSubject{GroupNames: []string{"Operations"}, GroupIDs: []string{"g-123"}}, rule) {
		t.Fatal("renamed group (same id) must still match")
	}
	if subjectMatches(EvalSubject{GroupNames: []string{"Ops"}, GroupIDs: []string{"g-999"}}, rule) {
		t.Fatal("a different group that took the name must not match")
	}
	if subjectMatches(EvalSubject{GroupNames: []string{"Ops"}}, rule) {
		t.Fatal("a name alone must not match an id rule")
	}
	if subjectMatches(EvalSubject{GroupIDs: []string{"G-123"}}, rule) {
		t.Fatal("group ids are opaque and compare exactly")
	}
}

func TestLegacyNameOnlyGroupRuleStillMatchesByName(t *testing.T) {
	rule := RuleSubject{Kind: SubjGroup, Name: "Ops"}
	if !subjectMatches(EvalSubject{GroupNames: []string{"ops"}, GroupIDs: []string{"g-123"}}, rule) {
		t.Fatal("legacy name rule must match on the name")
	}
}
