// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"fmt"
	"strings"
	"unicode"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// KekRotationPrincipalsEnv names the env var listing the SYSTEM principals
// allowed to call RotateKek (comma-separated, e.g. "system:kek-rotation").
// Unset or empty disables the SYSTEM path: only a human site-admin/root can
// rotate.
const KekRotationPrincipalsEnv = "VAULT_KEK_ROTATION_PRINCIPALS"

// systemPrincipalPrefix is required on every allowlisted id, so a human user
// id, a service-account id or the legacy bare "system" seed actor can never
// be allowlisted by mistake.
const systemPrincipalPrefix = "system:"

// kekSchedulerPrincipal is the actor id the in-process KEK scheduler records
// on its kek.rotate audit events. Reserved: it cannot be allowlisted, so an
// RPC caller can never pass itself off as the scheduler in the audit trail.
const kekSchedulerPrincipal = "system:kek-scheduler"

// ParseKekRotationPrincipals parses VAULT_KEK_ROTATION_PRINCIPALS. An empty
// (or all-whitespace) value returns no ids (the SYSTEM path is off). Entries are
// trimmed. Every entry must be "system:<name>" with a non-empty name and no
// whitespace, and must not be the reserved scheduler id. Any other entry,
// including an empty one between commas, is a boot-time config error. A typo
// fails the boot instead of being silently dropped.
func ParseKekRotationPrincipals(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	var ids []string
	for _, raw := range strings.Split(v, ",") {
		id := strings.TrimSpace(raw)
		switch {
		case id == "":
			return nil, fmt.Errorf("%s=%q: empty entry", KekRotationPrincipalsEnv, v)
		case !strings.HasPrefix(id, systemPrincipalPrefix) || len(id) == len(systemPrincipalPrefix):
			return nil, fmt.Errorf("%s: entry %q must be %q followed by a name", KekRotationPrincipalsEnv, id, systemPrincipalPrefix)
		case strings.IndexFunc(id, unicode.IsSpace) >= 0:
			return nil, fmt.Errorf("%s: entry %q must not contain whitespace", KekRotationPrincipalsEnv, id)
		case id == kekSchedulerPrincipal:
			return nil, fmt.Errorf("%s: %q is reserved for the internal KEK scheduler", KekRotationPrincipalsEnv, id)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// SetKekRotationPrincipals installs the parsed SYSTEM allowlist for RotateKek.
// Call it once at boot, before serving. A nil or empty list disables the path.
func (s *Server) SetKekRotationPrincipals(ids []string) {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	s.kekRotators = m
}

// isKekRotationPrincipal reports whether a is an allowlisted SYSTEM principal
// for RotateKek: PrincipalKind WORKLOAD and a UserId exactly in the allowlist.
// It grants RotateKek and nothing else. It is deliberately not folded into
// isHumanAdmin: admin authority stays human-only on every other path,
// and the actor's is_site_admin/is_root flags are ignored here.
// SERVICE_ACCOUNT is never accepted, so agent/API tokens (the gateway's only
// machine kind) can never rotate keys.
//
// Trust caveat: vault gRPC (:9091) trusts the caller-supplied
// ActorContext, so this check is as spoofable as the human-admin one by
// anything that can reach the port. The gateway never builds a WORKLOAD actor
// (only HUMAN session actors and SERVICE_ACCOUNT machine actors) and exposes
// no RotateKek resolver. In practice the only way to present this principal
// is a direct call to :9091 (operator port-forward + grpcurl).
func (s *Server) isKekRotationPrincipal(a *vaultv1.ActorContext) bool {
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD {
		return false
	}
	_, ok := s.kekRotators[a.GetUserId()]
	return ok
}
