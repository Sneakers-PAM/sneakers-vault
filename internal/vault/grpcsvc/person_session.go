// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc"
)

// ReasonPersonSessionRequired refuses a person's reveal or break-glass that
// doesn't come from their own signed-in web session.
const ReasonPersonSessionRequired = "PERSON_SESSION_REQUIRED"

const (
	msgPersonSessionRequired = "a person's reveal needs their own signed-in session"
	msgBreakGlassPeopleOnly  = "break-glass needs a person's own signed-in session; agents and tokens can't use it"
)

// personRevealMethods hand a secret's value to a person. PRINCIPAL_KIND_HUMAN
// is the enum's zero value, so an actor that names no kind reads as a
// person's; these calls also need the web session reference, which only a
// signed-in web session has.
var personRevealMethods = map[string]bool{
	vaultv1.VaultService_RevealSecretField_FullMethodName:        true,
	vaultv1.VaultService_RevealSecretVersionField_FullMethodName: true,
	vaultv1.VaultService_CopySecret_FullMethodName:               true,
	vaultv1.VaultService_ExportCertificate_FullMethodName:        true,
	vaultv1.VaultService_BreakGlassSecret_FullMethodName:         true,
}

type actorRequest interface{ GetActor() *vaultv1.ActorContext }

// isPersonInWebSession reports whether a is a person (not a token, service
// account or workload) acting from a signed-in web session.
func isPersonInWebSession(a *vaultv1.ActorContext) bool {
	return a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN && a.GetSessionRef() != ""
}

// PersonSessionUnary refuses a person-kind reveal that carries no web session
// reference, and audits it. Machine kinds keep their own rules in the
// handlers. A caller granted Self (the workflow, sneakers-migrate) is given
// the vault's own actor for it by SelfActorUnary and isn't a person, so it is
// let through; install this after SelfActorUnary.
func (s *Server) PersonSessionUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !personRevealMethods[info.FullMethod] {
		return handler(ctx, req)
	}
	g, granted := workloadauth.GrantFromContext(ctx)
	if granted && g.Access == workloadauth.Self {
		return handler(ctx, req)
	}
	var a *vaultv1.ActorContext
	if r, ok := req.(actorRequest); ok {
		a = r.GetActor()
	}
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || a.GetSessionRef() != "" {
		return handler(ctx, req)
	}
	action, msg := "secret.reveal.denied", msgPersonSessionRequired
	if info.FullMethod == vaultv1.VaultService_BreakGlassSecret_FullMethodName {
		action, msg = "break_glass.denied", msgBreakGlassPeopleOnly
	}
	subject := "vault"
	if r, ok := req.(interface{ GetId() string }); ok && r.GetId() != "" {
		subject = r.GetId()
	} else if r, ok := req.(interface{ GetSecretId() string }); ok && r.GetSecretId() != "" {
		subject = r.GetSecretId()
	}
	s.lg(ctx).Warn("person reveal refused: no web session", log.F("method", info.FullMethod),
		log.F("caller", g.Caller.Name), log.F("user_id", a.GetUserId()), log.F("subject", subject))
	s.emitTier(ctx, audit.TierAudit, a.GetUserId(), action, subject, false, map[string]string{
		"method": info.FullMethod, "reason": ReasonPersonSessionRequired, "caller": g.Caller.Name,
		"principal_kind": a.GetPrincipalKind().String(),
	})
	return nil, refuse(ReasonPersonSessionRequired, msg)
}

// refuseBreakGlassCaller refuses break-glass to anything but a person in
// their own signed-in web session (a personal or agent token, a service
// account, a workload, or a person with no web session), and audits it as
// break_glass.denied. It holds without the gateway or the interceptors.
func (s *Server) refuseBreakGlassCaller(ctx context.Context, a *vaultv1.ActorContext, method, subject string) error {
	if isPersonInWebSession(a) {
		return nil
	}
	actor := a.GetUserId()
	if actor == "" {
		actor = a.GetPrincipalId()
	}
	s.lg(ctx).Warn("break-glass refused: not a person's web session", log.F("method", method),
		log.F("principal_kind", a.GetPrincipalKind().String()), log.F("user_id", actor), log.F("subject", subject))
	s.emitTier(ctx, audit.TierAudit, actor, "break_glass.denied", subject, false, map[string]string{
		"method": method, "reason": ReasonPersonSessionRequired, "principal_kind": a.GetPrincipalKind().String(),
		"token_id": a.GetTokenId(),
	})
	return refuse(ReasonPersonSessionRequired, msgBreakGlassPeopleOnly)
}
