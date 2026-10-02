// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"google.golang.org/protobuf/proto"
)

// secretVisibility decides what a caller sees of a secret's metadata. A
// reader sees it. Anyone who can see its folder sees it locked when no rule
// grants or denies read, so they can find it and request access. An explicit
// deny, or a folder in someone else's personal tree, hides it. Caller holds
// s.mu.
func (s *Server) secretVisibility(a *vaultv1.ActorContext, sec *vaultv1.Secret) (visible, canRead bool) {
	read := s.resolveSecret(a, sec).Read
	if read.Allowed {
		return true, true
	}
	if read.Reason != authz.ReasonDefaultDeny {
		return false, false
	}
	f := s.findFolder(sec.GetFolderId())
	return f != nil && folderVisible(a.GetUserId(), f), false
}

// withCanRead returns a copy of sec carrying the caller's can_read, so the
// stored secret never holds a per-caller flag.
func withCanRead(sec *vaultv1.Secret, canRead bool) *vaultv1.Secret {
	cp := proto.Clone(sec).(*vaultv1.Secret)
	cp.CanRead = canRead
	return cp
}

// auditReadDenied records a refused metadata or field read. Never a value.
func (s *Server) auditReadDenied(ctx context.Context, a *vaultv1.ActorContext, secretID, action string) {
	id := a.GetUserId()
	if id == "" {
		id = a.GetPrincipalId()
	}
	s.lg(ctx).Info("secret read refused", log.F("secret_id", secretID), log.F("action", action), log.F("principal_kind", a.GetPrincipalKind().String()))
	s.emitAttrs(ctx, id, "secret.read.denied", secretID, false, map[string]string{
		"reason": "NO_ACCESS", "action": action, "principal_kind": a.GetPrincipalKind().String(),
	})
}
