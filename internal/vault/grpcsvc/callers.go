// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strconv"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Caller names, from the service accounts sneakers-<name>.
const (
	CallerGateway   = "gateway"
	CallerWorkflow  = "workflow"
	CallerSSHBroker = "sshbroker"
	CallerConnector = "connector"
	// CallerMigrate is the sneakers-migrate Job: it seals imported values and
	// reads back samples and targets to verify the import.
	CallerMigrate = "migrate"
)

// migrateMethods are the calls sneakers-migrate makes as itself, besides
// SealForImport, to verify an import.
var migrateMethods = []string{
	vaultv1.VaultService_RevealSecretField_FullMethodName,
	vaultv1.VaultService_GetSecret_FullMethodName,
	vaultv1.VaultService_ListTargets_FullMethodName,
	vaultv1.VaultService_ListConnections_FullMethodName,
}

// connectorMethods are the connector pull-API. The connector calls them as
// itself; they carry its worker identity, never an actor.
var connectorMethods = []string{
	vaultv1.VaultService_ClaimDueHeartbeats_FullMethodName,
	vaultv1.VaultService_RevealForHeartbeat_FullMethodName,
	vaultv1.VaultService_ReportHeartbeat_FullMethodName,
	vaultv1.VaultService_ClaimDueRotations_FullMethodName,
	vaultv1.VaultService_RevealForRotation_FullMethodName,
	vaultv1.VaultService_ReportRotation_FullMethodName,
}

// workflowMethods are the calls the workflow service makes as itself: the
// temporary read grant behind a lease, approved moves, rotation on check-in,
// the request-history retention setting and the secret's type for the
// check-out check.
var workflowMethods = []string{
	vaultv1.VaultService_GetSecret_FullMethodName,
	vaultv1.VaultService_ListSecretTypes_FullMethodName,
	vaultv1.VaultService_GetSecretRuleset_FullMethodName,
	vaultv1.VaultService_SetSecretRuleset_FullMethodName,
	vaultv1.VaultService_MoveFolder_FullMethodName,
	vaultv1.VaultService_UpdateSecret_FullMethodName,
	vaultv1.VaultService_EnqueueRotation_FullMethodName,
	vaultv1.VaultService_GetSecuritySettings_FullMethodName,
}

// CallerPolicy is the vault's per-method allow-list. The gateway passes the
// signed-in user's actor on every user-facing method; the SSH broker passes
// the session user's actor to reveal the key it connects with; the workflow
// the connector and sneakers-migrate act only as themselves. Anything else is
// refused.
func CallerPolicy() workloadauth.Policy {
	p := workloadauth.Policy{}
	connector := map[string]bool{}
	for _, m := range connectorMethods {
		connector[m] = true
		p[m] = map[string]workloadauth.Access{CallerConnector: workloadauth.Self}
	}
	for _, md := range vaultv1.VaultService_ServiceDesc.Methods {
		m := "/" + vaultv1.VaultService_ServiceDesc.ServiceName + "/" + md.MethodName
		if !connector[m] {
			p[m] = map[string]workloadauth.Access{CallerGateway: workloadauth.OnBehalf}
		}
	}
	for _, m := range workflowMethods {
		p[m][CallerWorkflow] = workloadauth.Self
	}
	p[vaultv1.VaultService_RevealSecretField_FullMethodName][CallerSSHBroker] = workloadauth.OnBehalf
	p[vaultv1.VaultService_SealForImport_FullMethodName] = map[string]workloadauth.Access{CallerMigrate: workloadauth.Self}
	for _, m := range migrateMethods {
		p[m][CallerMigrate] = workloadauth.Self
	}
	// The gateway's diagnostics read connector builds as itself.
	p[vaultv1.VaultService_ListConnectors_FullMethodName] = map[string]workloadauth.Access{CallerGateway: workloadauth.Self}
	// The check-out check asks for the user's own RACI decision.
	p[vaultv1.VaultService_GetMySecretAccess_FullMethodName][CallerWorkflow] = workloadauth.OnBehalf
	return p
}

// selfActors are the actors the vault acts as for a caller that may only act
// as itself. The workflow drives lease grants, approved moves and rotation on
// check-in, which the RACI gates allow only to an owner, admin or root; the
// workflow decided who may have them before it calls.
var selfActors = map[string]*vaultv1.ActorContext{
	CallerWorkflow: {UserId: "system:" + CallerWorkflow, IsRoot: true},
	// The import tool seals and verifies across every folder.
	CallerMigrate: {UserId: "system:" + CallerMigrate, IsRoot: true},
}

// SelfActorUnary fills in the actor for a caller authenticated as Self: the
// workload-auth interceptor has already refused any actor such a caller sent,
// so the handler sees the vault's own actor for it (or none). Install it
// after the workload-auth interceptor.
func (s *Server) SelfActorUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	g, ok := workloadauth.GrantFromContext(ctx)
	if !ok || g.Access != workloadauth.Self {
		return handler(ctx, req)
	}
	actor := selfActors[g.Caller.Name]
	m, isProto := req.(proto.Message)
	if actor == nil || !isProto {
		return handler(ctx, req)
	}
	r := m.ProtoReflect()
	fd := r.Descriptor().Fields().ByName("actor")
	if fd == nil || fd.Message() == nil || fd.Message().FullName() != actor.ProtoReflect().Descriptor().FullName() {
		return handler(ctx, req)
	}
	r.Set(fd, protoreflect.ValueOfMessage(proto.Clone(actor).ProtoReflect()))
	log.Trace(s.lg(ctx), "acting as the caller's own actor",
		log.F("method", info.FullMethod), log.F("caller", g.Caller.Name), log.F("actor", actor.GetUserId()))
	return handler(ctx, req)
}

// AuditDenial records a call the workload-auth interceptor refused, as
// rpc.denied in the audit tier. The actor is the authenticated caller (or
// "unauthenticated"), never the user a request claimed; the claim is kept as
// attributes so a forged actor shows up for what it is.
func (s *Server) AuditDenial(ctx context.Context, d workloadauth.Denial) {
	caller := d.Caller.Name
	if caller == "" {
		caller = "unauthenticated"
	}
	attrs := map[string]string{
		"method":          d.Method,
		"caller":          d.Caller.Name,
		"service_account": d.Caller.ServiceAccount,
		"code":            d.Code.String(),
		"reason":          d.Reason,
	}
	req := d.Request
	if req == nil {
		req = ctx.Value(requestKey{})
	}
	if r, ok := req.(interface{ GetActor() *vaultv1.ActorContext }); ok && r.GetActor() != nil {
		a := r.GetActor()
		attrs["claimed_user_id"] = a.GetUserId()
		attrs["claimed_root"] = strconv.FormatBool(a.GetIsRoot())
		attrs["claimed_site_admin"] = strconv.FormatBool(a.GetIsSiteAdmin())
		attrs["claimed_principal_kind"] = a.GetPrincipalKind().String()
	}
	s.emitTier(ctx, audit.TierAudit, "service:"+caller, "rpc.denied", d.Method, false, attrs)
}

type requestKey struct{}

// RequestContextUnary keeps the request in the context so AuditDenial can
// record the actor a refused call claimed, even when the refusal came before
// the request was inspected. Install it before the workload-auth interceptor.
func RequestContextUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(context.WithValue(ctx, requestKey{}, req), req)
}
