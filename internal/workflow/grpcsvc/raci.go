// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// A lease only issues a time-boxed hold; it does not, by itself, confer the
// firewall-RACI read/reveal grant the vault requires to reveal a secret or load
// its history. So when a lease is granted (on approval) the workflow adds a
// TEMPORARY secret-level RACI rule granting the lease holder read (RACI "C"),
// and removes exactly that rule when the lease ends. The vault already honours
// secret-level rules in resolveSecret (the secret's own ruleset is evaluated
// first in the chain), so a user "C":"allow" rule flips Read.Allowed true for
// that user for the lease window.

// raciReadGrant is the RACI action key for read/reveal ("C") and its allow
// value, matching the vault contract's grant map ({"C|R|A|I":"allow|deny"}) and
// the authz package's ActRead/GrantAllow.
const (
	raciReadAction = "C"
	raciAllow      = "allow"
)

// systemAdminActor is the elevated principal the grant/revoke helpers present to
// the owner/admin-gated Get/SetSecretRuleset RPCs. IsRoot passes the gate; there
// is no human actor behind a lease-lifecycle transition (the workflow engine
// drives it), so a system root principal is the correct caller identity.
func systemAdminActor() *vaultv1.ActorContext {
	return &vaultv1.ActorContext{UserId: "system", IsRoot: true}
}

// isTempReadGrant reports whether r is the exact temporary rule this flow adds:
// a USER-subject rule for userID whose only grant is read=allow. It deliberately
// does NOT match a broader user rule (e.g. one that also grants R/A/I, or that
// denies), so revoke never removes a pre-existing grant an admin set by hand.
func isTempReadGrant(r *vaultv1.RaciRule, userID string) bool {
	if r.GetSubjectKind() != vaultv1.SubjectKind_SUBJECT_KIND_USER || r.GetSubjectName() != userID {
		return false
	}
	g := r.GetGrants()
	return len(g) == 1 && g[raciReadAction] == raciAllow
}

// grantSecretRead adds a temporary secret-level read grant for userID on
// secretID, so the lease holder can actually reveal/copy the secret and load its
// history for the lease window. Idempotent: if a read grant for this user is
// already present, it is a no-op.
func grantSecretRead(ctx context.Context, vault vaultv1.VaultServiceClient, secretID, userID string) error {
	if vault == nil || secretID == "" || userID == "" {
		return nil
	}
	admin := systemAdminActor()
	cur, err := vault.GetSecretRuleset(ctx, &vaultv1.GetSecretRulesetRequest{Actor: admin, SecretId: secretID})
	if err != nil {
		return fmt.Errorf("get secret ruleset: %w", err)
	}
	rules := cur.GetRules()
	for _, r := range rules {
		if isTempReadGrant(r, userID) {
			return nil // already granted
		}
	}
	rules = append(rules, &vaultv1.RaciRule{
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER,
		SubjectName: userID,
		Grants:      map[string]string{raciReadAction: raciAllow},
	})
	if _, err := vault.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: admin, SecretId: secretID, Rules: rules}); err != nil {
		return fmt.Errorf("set secret ruleset: %w", err)
	}
	return nil
}

// revokeSecretRead removes the temporary secret-level read grant this flow added
// for userID on secretID (see isTempReadGrant). It only drops the exact temp
// rule, leaving any broader/pre-existing user rule intact. Idempotent: a no-op
// when no such rule is present.
func revokeSecretRead(ctx context.Context, vault vaultv1.VaultServiceClient, secretID, userID string) error {
	if vault == nil || secretID == "" || userID == "" {
		return nil
	}
	admin := systemAdminActor()
	cur, err := vault.GetSecretRuleset(ctx, &vaultv1.GetSecretRulesetRequest{Actor: admin, SecretId: secretID})
	if err != nil {
		return fmt.Errorf("get secret ruleset: %w", err)
	}
	kept := make([]*vaultv1.RaciRule, 0, len(cur.GetRules()))
	changed := false
	for _, r := range cur.GetRules() {
		if isTempReadGrant(r, userID) {
			changed = true
			continue
		}
		kept = append(kept, r)
	}
	if !changed {
		return nil
	}
	if _, err := vault.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{Actor: admin, SecretId: secretID, Rules: kept}); err != nil {
		return fmt.Errorf("set secret ruleset: %w", err)
	}
	return nil
}
