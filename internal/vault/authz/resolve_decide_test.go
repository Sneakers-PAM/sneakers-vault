// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

func rs(name string, owners []string, rules ...Rule) CategoryRuleset {
	return CategoryRuleset{Name: name, Owners: owners, Rules: rules}
}
func rule(kind SubjectKind, name string, g map[Action]Grant) Rule {
	return Rule{Subject: RuleSubject{Kind: kind, Name: name}, Grants: g}
}

func TestDecideAction_SingleCategory(t *testing.T) {
	u := EvalSubject{UserID: "u1", GroupNames: []string{"IT-Staff"}}
	admin := EvalSubject{UserID: "adm", IsSiteAdmin: true}
	owner := EvalSubject{UserID: "own"}

	everyoneReads := rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow})
	denyITApprove := rule(SubjGroup, "IT-Staff", map[Action]Grant{ActApprove: GrantDeny})

	t.Run("everyone allow read", func(t *testing.T) {
		d := decideAction(u, []CategoryRuleset{rs("IT", nil, everyoneReads)}, ActRead)
		if !d.Allowed {
			t.Fatalf("want allowed, got %+v", d)
		}
	})
	t.Run("default deny when no rule", func(t *testing.T) {
		d := decideAction(u, []CategoryRuleset{rs("IT", nil, everyoneReads)}, ActApprove)
		if d.Allowed {
			t.Fatalf("want denied, got %+v", d)
		}
	})
	t.Run("explicit deny wins over later allow (top-down)", func(t *testing.T) {
		allowITApprove := rule(SubjGroup, "IT-Staff", map[Action]Grant{ActApprove: GrantAllow})
		d := decideAction(u, []CategoryRuleset{rs("IT", nil, denyITApprove, allowITApprove)}, ActApprove)
		if d.Allowed {
			t.Fatalf("first match (deny) should win, got %+v", d)
		}
	})
	t.Run("blank falls through to next rule", func(t *testing.T) {
		blank := rule(SubjGroup, "IT-Staff", map[Action]Grant{ActApprove: GrantBlank})
		allow := rule(SubjEveryone, "", map[Action]Grant{ActApprove: GrantAllow})
		d := decideAction(u, []CategoryRuleset{rs("IT", nil, blank, allow)}, ActApprove)
		if !d.Allowed {
			t.Fatalf("blank should fall through to allow, got %+v", d)
		}
	})
	t.Run("site-admin reads regardless of rules", func(t *testing.T) {
		d := decideAction(admin, []CategoryRuleset{rs("IT", nil)}, ActRead)
		if !d.Allowed {
			t.Fatalf("site-admin should read, got %+v", d)
		}
	})
	t.Run("site-admin is not an auto-approver", func(t *testing.T) {
		d := decideAction(admin, []CategoryRuleset{rs("IT", nil)}, ActApprove)
		if d.Allowed {
			t.Fatalf("site-admin must not auto-approve, got %+v", d)
		}
	})
	t.Run("owner auto read/approve/author", func(t *testing.T) {
		chain := []CategoryRuleset{rs("IT", []string{"own"})}
		for _, act := range []Action{ActRead, ActApprove, ActAuthor} {
			if d := decideAction(owner, chain, act); !d.Allowed {
				t.Fatalf("owner should have %s, got %+v", act, d)
			}
		}
	})
	t.Run("owner does NOT auto-ack", func(t *testing.T) {
		d := decideAction(owner, []CategoryRuleset{rs("IT", []string{"own"})}, ActAck)
		if d.Allowed {
			t.Fatalf("owner ack must follow rules, got %+v", d)
		}
	})
}
