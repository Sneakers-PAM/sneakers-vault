// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authz

// InformedSubjects returns every subject with an explicit I (Informed/ack)
// allow grant anywhere in the chain, de-duplicated by (kind, name). Everyone is
// excluded: an Informed-to-Everyone grant would notify every user on every
// event, which is noise, not awareness. This is the fan-out counterpart to
// AckGrant — where AckGrant answers "is THIS user informed?", InformedSubjects
// answers "who are ALL the informed subjects?" for pushing notifications.
func InformedSubjects(chain []CategoryRuleset) []RuleSubject {
	seen := map[string]bool{}
	var out []RuleSubject
	for _, c := range chain {
		for _, r := range c.Rules {
			if r.Grants[ActAck] != GrantAllow {
				continue
			}
			if r.Subject.Kind == SubjEveryone {
				continue
			}
			key := string(r.Subject.Kind) + ":" + r.Subject.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, r.Subject)
		}
	}
	return out
}
