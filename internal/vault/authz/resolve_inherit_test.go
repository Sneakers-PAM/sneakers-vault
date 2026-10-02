// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "testing"

// chain built as [child, parent] (target first, ancestor after).
func TestResolve_InheritDown(t *testing.T) {
	ops := EvalSubject{UserID: "m1", GroupNames: []string{"Ops-Staff"}}
	it := EvalSubject{UserID: "i1", GroupNames: []string{"IT-Staff"}}

	parentAllowsEveryoneRead := rs("IT", nil, rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow}))
	parentDeniesOps := rs("IT", nil, rule(SubjGroup, "Ops-Staff", map[Action]Grant{ActRead: GrantDeny}))

	t.Run("parent allow inherits to child", func(t *testing.T) {
		child := rs("Servers", nil) // no own rules
		got := Resolve(it, []CategoryRuleset{child, parentAllowsEveryoneRead})
		if !got.Read.Allowed {
			t.Fatalf("child should inherit parent's Everyone-read allow, got %+v", got.Read)
		}
	})
	t.Run("parent deny inherits to child", func(t *testing.T) {
		child := rs("Servers", nil, rule(SubjEveryone, "", map[Action]Grant{ActRead: GrantAllow}))
		got := Resolve(ops, []CategoryRuleset{child, parentDeniesOps})
		// child allows everyone read (evaluated first) -> ops reads. Proves child
		// rule is evaluated BEFORE parent deny (override). See next case for the
		// no-override path.
		if !got.Read.Allowed {
			t.Fatalf("child's own allow should be read first, got %+v", got.Read)
		}
	})
	t.Run("parent deny applies when child is silent", func(t *testing.T) {
		child := rs("Servers", nil) // silent
		got := Resolve(ops, []CategoryRuleset{child, parentDeniesOps})
		if got.Read.Allowed {
			t.Fatalf("parent deny should inherit when child is silent, got %+v", got.Read)
		}
	})
	t.Run("owner inherits down", func(t *testing.T) {
		itOwner := EvalSubject{UserID: "own"}
		child := rs("Servers", nil)
		parent := rs("IT", []string{"own"})
		got := Resolve(itOwner, []CategoryRuleset{child, parent})
		if !got.Read.Allowed || !got.Approve.Allowed {
			t.Fatalf("parent owner should own child (read+approve), got %+v", got)
		}
	})
}
