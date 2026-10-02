// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"encoding/json"
	"sort"

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
