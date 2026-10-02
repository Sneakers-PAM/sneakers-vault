// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func TestInformedSubjects(t *testing.T) {
	chain := []CategoryRuleset{
		{Name: "sec", Rules: []Rule{
			{Subject: RuleSubject{Kind: SubjUser, Name: "user-carol"}, Grants: map[Action]Grant{ActAck: GrantAllow}},
			{Subject: RuleSubject{Kind: SubjGroup, Name: "SecOps"}, Grants: map[Action]Grant{ActAck: GrantAllow, ActRead: GrantAllow}},
			{Subject: RuleSubject{Kind: SubjUser, Name: "user-nope"}, Grants: map[Action]Grant{ActRead: GrantAllow}}, // read only, not informed
			{Subject: RuleSubject{Kind: SubjEveryone}, Grants: map[Action]Grant{ActAck: GrantAllow}},                 // everyone excluded
		}},
		{Name: "folder", Rules: []Rule{
			{Subject: RuleSubject{Kind: SubjUser, Name: "user-carol"}, Grants: map[Action]Grant{ActAck: GrantAllow}}, // dup
			{Subject: RuleSubject{Kind: SubjGroup, Name: "Audit"}, Grants: map[Action]Grant{ActAck: GrantDeny}},      // deny, not informed
		}},
	}
	got := InformedSubjects(chain)
	if len(got) != 2 {
		t.Fatalf("want 2 subjects, got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[string(s.Kind)+":"+s.Name] = true
	}
	if !seen["user:user-carol"] || !seen["group:SecOps"] {
		t.Fatalf("missing expected subjects: %+v", got)
	}
}
