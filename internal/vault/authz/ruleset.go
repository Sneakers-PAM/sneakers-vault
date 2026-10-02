// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import "strings"

// Action is one of the four governed actions.
type Action string

const (
	ActRead    Action = "C" // read / view
	ActAck     Action = "I" // acknowledge
	ActApprove Action = "A" // approve
	ActAuthor  Action = "R" // author
)

// Grant is the tri-state value of one action cell in a rule.
type Grant string

const (
	GrantBlank Grant = ""      // no opinion — fall through
	GrantAllow Grant = "allow" // explicitly allowed
	GrantDeny  Grant = "deny"  // explicitly denied
)

// SubjectKind identifies what a rule targets.
type SubjectKind string

const (
	SubjEveryone SubjectKind = "everyone" // all users (built-in; never a group)
	SubjGroup    SubjectKind = "group"
	SubjUser     SubjectKind = "user"
)

// RuleSubject is the target of a rule.
type RuleSubject struct {
	Kind SubjectKind
	Name string // group name or user id; empty for Everyone
}

// Rule is one ordered firewall row: a subject with a tri-state grant per action.
// Grants only holds C/I/A/R keys; a missing key means GrantBlank.
type Rule struct {
	Subject RuleSubject
	Grants  map[Action]Grant
}

// CategoryRuleset is one category's owners + ordered rules. The caller passes a
// chain of these (target first, then ancestors) to Resolve.
type CategoryRuleset struct {
	Name   string
	Owners []string // user ids; auto read+approve+author; inherit down; backstop
	Rules  []Rule   // ordered, top-down
}

// EvalSubject is the user being evaluated.
type EvalSubject struct {
	UserID      string
	IsSiteAdmin bool
	IsRoot      bool
	GroupNames  []string
}

func subjectMatches(u EvalSubject, s RuleSubject) bool {
	switch s.Kind {
	case SubjEveryone:
		return true
	case SubjUser:
		return s.Name == u.UserID
	case SubjGroup:
		// Group names are human directory names: rule subjects come from the
		// admin picker and memberships from the directory, so casing drift must
		// not silently drop a user from a rule, so group names compare
		// case-insensitively. User IDs above stay exact — they are opaque.
		for _, g := range u.GroupNames {
			if strings.EqualFold(g, s.Name) {
				return true
			}
		}
	}
	return false
}
