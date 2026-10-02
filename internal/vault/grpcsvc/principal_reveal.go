// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// RevealForWorkload is the generalized in-cluster workload reveal path: a
// verified workload (via the existing s.wid.Verify seam — dev token or the OIDC
// projected-token verifier, same interface) may reveal any secret it has RACI-C
// on, not just a heartbeat-scheduled credential — addressing the heartbeat.go
// @todo that every worker verifies to one shared principal with heartbeat-only
// scope.
//
// It shares revealForPrincipal with RevealSecretFieldForPrincipal:
// once the identity is verified, a workload is just another principal kind.
// RevealForHeartbeat is kept unchanged for back-compat (narrower: gated to a
// heartbeat-capable, actually-scheduled secret); new callers should use this
// path instead. No dedicated gRPC RPC carries this yet (a SPIRE deployment and gateway
// workload-bearer wiring are still to come), so this is a Go-level entry point a
// future caller (e.g. a gateway workload-bearer path, mirroring the
// machine bearer path) attaches to once that wiring lands.
func (s *Server) RevealForWorkload(ctx context.Context, identity *vaultv1.WorkerIdentity, id, fieldKey string) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	principal, err := s.verifyWorkerAudited(ctx, identity, "reveal.principal.denied")
	if err != nil {
		return nil, err
	}
	actor := &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
		PrincipalId:   principal.WorkerID,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revealForPrincipal(ctx, actor, id, fieldKey)
}
