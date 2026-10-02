// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

// RuleDecision is the outcome for a single action plus a human-readable reason.
type RuleDecision struct {
	Allowed bool
	Reason  string
}

func ownerInChain(u EvalSubject, chain []CategoryRuleset) bool {
	for _, c := range chain {
		for _, o := range c.Owners {
			if o == u.UserID {
				return true
			}
		}
	}
	return false
}

// decideAction resolves one action for one user against the ruleset chain
// (target category first, then ancestors). Pure.
func decideAction(u EvalSubject, chain []CategoryRuleset, act Action) RuleDecision {
	// site-admin / root read everything (never auto-approver/author).
	if act == ActRead && (u.IsSiteAdmin || u.IsRoot) {
		return RuleDecision{true, "site-admin reads all"}
	}
	// owners: auto read + approve + author (not ack), evaluated before rules.
	if act != ActAck && ownerInChain(u, chain) {
		return RuleDecision{true, "owner (auto read/approve/author)"}
	}
	// top-down, target category first then ancestors; first non-blank match wins.
	for ci, c := range chain {
		for ri, r := range c.Rules {
			if !subjectMatches(u, r.Subject) {
				continue
			}
			switch r.Grants[act] {
			case GrantAllow:
				return RuleDecision{true, ruleReason(ci, ri, c.Name, "allow", r.Subject)}
			case GrantDeny:
				return RuleDecision{false, ruleReason(ci, ri, c.Name, "deny", r.Subject)}
			}
		}
	}
	return RuleDecision{false, "no rule → default deny"}
}

func ruleReason(catIdx, ruleIdx int, catName, effect string, s RuleSubject) string {
	loc := "rule #" + itoa(ruleIdx+1)
	if catIdx > 0 {
		loc = "↳ " + catName + " #" + itoa(ruleIdx+1)
	}
	who := string(s.Kind)
	if s.Name != "" {
		who += " " + s.Name
	}
	return loc + " " + effect + " " + who
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// AckGrant returns the ack-rule decision for a user against the chain: it
// evaluates only whether an ack rule matches (owners never auto-ack;
// site-admin/root never auto-ack). Ack is independent of read (Informed is an
// awareness tier, not an access tier — see Resolve), so this is now equivalent
// to `Resolve(u, chain).Ack`; kept as a named entry point for consumers that
// only need the ack decision and not the full four-action resolution.
func AckGrant(u EvalSubject, chain []CategoryRuleset) RuleDecision {
	return decideAction(u, chain, ActAck)
}

// ActionResult is the full four-action resolution for a user in a category.
type ActionResult struct {
	Read    RuleDecision
	Ack     RuleDecision
	Approve RuleDecision
	Author  RuleDecision
}

// Resolve evaluates all four actions. chain[0] is the target category; the rest
// are its ancestors leaf→root. Read gates approve/author. A granted Author OR
// Approve confers Read (you can't author or approve what you can't read). Ack
// (Informed) is INDEPENDENT of read: it's an awareness/"notify me when this
// changes" tier, not an access tier, so a subject with only an Informed grant
// resolves to Ack.Allowed == true even though Read.Allowed == false — you can
// notify someone who can't reveal. Ack never confers Read either.
// Resolve is also the simulator: callers preview unsaved changes by passing a
// DRAFT chain (proposed rules) instead of the persisted one. Same function, no
// separate dry-run path — see resolve_simulate_test.go.
func Resolve(u EvalSubject, chain []CategoryRuleset) ActionResult {
	read := decideAction(u, chain, ActRead)
	if !read.Allowed {
		if decideAction(u, chain, ActAuthor).Allowed {
			read = RuleDecision{true, "author implies read"}
		} else if decideAction(u, chain, ActApprove).Allowed {
			read = RuleDecision{true, "approver implies read"}
		}
	}
	gate := func(act Action) RuleDecision {
		if !read.Allowed {
			return RuleDecision{false, "requires read"}
		}
		return decideAction(u, chain, act)
	}
	return ActionResult{
		Read:    read,
		Ack:     decideAction(u, chain, ActAck),
		Approve: gate(ActApprove),
		Author:  gate(ActAuthor),
	}
}
