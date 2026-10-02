// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestSubjectMatches(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	cases := []struct {
		name string
		subj RuleSubject
		want bool
	}{
		{"everyone matches anyone", RuleSubject{Kind: SubjEveryone}, true},
		{"group the user is in", RuleSubject{Kind: SubjGroup, Name: "IT-Staff"}, true},
		{"group the user is not in", RuleSubject{Kind: SubjGroup, Name: "Ops-Staff"}, false},
		{"exact user id", RuleSubject{Kind: SubjUser, Name: "u1"}, true},
		{"other user id", RuleSubject{Kind: SubjUser, Name: "u2"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := subjectMatches(u, c.subj); got != c.want {
				t.Fatalf("subjectMatches=%v want %v", got, c.want)
			}
		})
	}
}
