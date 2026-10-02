// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorDomain is the google.rpc.ErrorInfo domain of the vault's refusals.
const errorDomain = "sneakers.vault"

// Stable authority refusal reasons.
const (
	ReasonNotSiteAdmin   = "NOT_SITE_ADMIN"
	ReasonNotFolderOwner = "NOT_FOLDER_OWNER"
)

// refuse builds a PermissionDenied status carrying an ErrorInfo for reason.
func refuse(reason, msg string) error {
	st := status.New(codes.PermissionDenied, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Domain: errorDomain, Reason: reason}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// deny logs and audits an authority refusal, then returns it.
func (s *Server) deny(ctx context.Context, a *vaultv1.ActorContext, method, subject, reason, msg string) error {
	s.lg(ctx).Warn("authority check refused", log.F("method", method), log.F("reason", reason),
		log.F("user_id", a.GetUserId()), log.F("principal_id", a.GetPrincipalId()), log.F("subject", subject))
	actor := a.GetUserId()
	if actor == "" {
		actor = a.GetPrincipalId()
	}
	s.emitAttrs(ctx, actor, "authz.denied", subject, false, map[string]string{
		"method": method, "reason": reason, "principal_kind": a.GetPrincipalKind().String(),
	})
	return refuse(reason, msg)
}

// requireSiteAdmin refuses unless a is a human site admin or root (see
// isHumanAdmin).
func (s *Server) requireSiteAdmin(ctx context.Context, a *vaultv1.ActorContext, method string) error {
	if isHumanAdmin(a) {
		return nil
	}
	return s.deny(ctx, a, method, "vault", ReasonNotSiteAdmin, "this needs a site admin")
}

// requireFolderOwner refuses unless a owns f (or is a human site admin).
// Callers hold s.mu.
func (s *Server) requireFolderOwner(ctx context.Context, a *vaultv1.ActorContext, f *vaultv1.Folder, method string) error {
	if s.isFolderOwner(a, f) {
		return nil
	}
	return s.deny(ctx, a, method, f.GetId(), ReasonNotFolderOwner, "only the folder's owner can do this")
}
