// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"encoding/json"
	"sort"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// fieldChange is one non-sensitive field's before/after value, as recorded in
// a secret.update audit event's attributes.
type fieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// diffSecretFields compares a secret's plaintext field maps before/after an
// update and splits the changed keys into non-sensitive (old+new captured) and
// sensitive (per t's SecretFieldDef.Sensitive / FIELD_KIND_PASSWORD) per the
// hard security rule that a sensitive value must NEVER enter the audit log —
// only the fact that it changed. Deterministic (sorted by key) so callers get
// stable output. t may be nil (unknown type): isSensitiveField treats every
// key as non-sensitive in that case, matching its existing fail-open contract
// used elsewhere (e.g. GetSecretFields), so this reuses that same boundary
// rather than introducing a second, divergent one.
func (s *Server) diffSecretFields(t *vaultv1.SecretType, oldFields, newFields map[string]string) (changes []fieldChange, sensitiveChanged []string) {
	seen := make(map[string]bool, len(oldFields)+len(newFields))
	for k := range oldFields {
		seen[k] = true
	}
	for k := range newFields {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ov, nv := oldFields[k], newFields[k]
		if ov == nv {
			continue
		}
		if s.isSensitiveField(t, k) {
			sensitiveChanged = append(sensitiveChanged, k)
			continue
		}
		changes = append(changes, fieldChange{Field: k, Old: ov, New: nv})
	}
	return changes, sensitiveChanged
}

// secretUpdateAttributes packs a set of field changes into the flat
// map[string]string an audit.Event.Attributes carries (the audit contract's
// RecordEventRequest.attributes is map<string, string>, stored as jsonb
// server-side — no proto change needed). "changes" is a JSON array of
// {field,old,new} for non-sensitive fields (plus a rename, if any);
// "sensitiveChanged" is a JSON array of field keys that changed WITHOUT their
// values. Returns nil when nothing changed, matching the prior (pre-diff)
// behavior of emitting no attributes.
func secretUpdateAttributes(changes []fieldChange, sensitiveChanged []string) map[string]string {
	if len(changes) == 0 && len(sensitiveChanged) == 0 {
		return nil
	}
	attrs := map[string]string{}
	if len(changes) > 0 {
		if b, err := json.Marshal(changes); err == nil {
			attrs["changes"] = string(b)
		}
	}
	if len(sensitiveChanged) > 0 {
		if b, err := json.Marshal(sensitiveChanged); err == nil {
			attrs["sensitiveChanged"] = string(b)
		}
	}
	return attrs
}

// typeChangeLabel describes a type change itself (#165), instead of leaving
// its version to read as only "Changed: <field>" the way diffSecretFields'
// generic changed-key list would: "Type changed: Password -> Password
// Account (SSH); added host; renamed username to login; fields carried
// over: password; moved to notes: legacy_note". next is the new type's final
// plaintext field map (post-retype); mapping is the request's explicit
// field_mapping (old key -> new key); moved is the old keys the mapping left
// unmapped and retypeFields appended to the notes field.
func typeChangeLabel(st, nt *vaultv1.SecretType, mapping, next map[string]string, moved []string) string {
	renamedFrom := make(map[string]string, len(mapping))
	for from, to := range mapping {
		if from != to {
			renamedFrom[to] = from
		}
	}
	var added, renamed, carried []string
	for _, key := range sortedKeys(next) {
		if next[key] == "" {
			continue
		}
		switch {
		case renamedFrom[key] != "":
			renamed = append(renamed, renamedFrom[key]+" to "+key)
		case fieldDef(st, key) != nil:
			carried = append(carried, key)
		default:
			added = append(added, key)
		}
	}
	label := "Type changed: " + st.GetName() + " → " + nt.GetName()
	if len(added) > 0 {
		label += "; added " + strings.Join(added, ", ")
	}
	if len(renamed) > 0 {
		label += "; renamed " + strings.Join(renamed, ", ")
	}
	if len(carried) > 0 {
		label += "; fields carried over: " + strings.Join(carried, ", ")
	}
	if len(moved) > 0 {
		label += "; fields moved to notes: " + strings.Join(moved, ", ")
	}
	return label
}
