// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"errors"
	"strings"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Reasons a call is refused, as recorded on a Denial.
const (
	ReasonNoToken          = "no workload token"
	ReasonBadToken         = "workload token rejected"
	ReasonUnavailable      = "workload verifier unavailable"
	ReasonMethodNotAllowed = "caller not allowed on this method"
	ReasonActorNotAllowed  = "caller may not pass an actor on this method"
)

// healthService is always exempt so kubelet and load-balancer probes need no
// token.
const healthService = "/grpc.health.v1.Health/"

// Denial describes a refused call, for the callee to audit.
type Denial struct {
	Method string
	// Caller is empty when the token was missing or rejected.
	Caller Caller
	Code   codes.Code
	Reason string
	// Request is the refused request message, or nil when the call was refused
	// before one was read (a stream). Never log it whole: it may hold values.
	Request any
}

// DenyHook is called for every refused call, before the error is returned.
type DenyHook func(ctx context.Context, d Denial)

type options struct {
	onDeny DenyHook
	exempt []string
}

// Option tunes the interceptors.
type Option func(*options)

// WithDenyHook sets the hook called for each refusal, typically to audit it.
func WithDenyHook(h DenyHook) Option { return func(o *options) { o.onDeny = h } }

// WithExempt exempts methods from authentication: an entry ending in "/" is a
// whole service ("/pkg.v1.Service/"), anything else one full method. The
// health service is always exempt.
func WithExempt(methods ...string) Option {
	return func(o *options) { o.exempt = append(o.exempt, methods...) }
}

type authorizer struct {
	v      TokenVerifier
	policy Policy
	log    log.Logger
	opts   options
}

func newAuthorizer(v TokenVerifier, p Policy, lg log.Logger, opts []Option) *authorizer {
	if lg == nil {
		lg = log.Nop()
	}
	a := &authorizer{v: v, policy: p, log: lg.With(log.F("component", "workloadauth"))}
	for _, o := range opts {
		o(&a.opts)
	}
	return a
}

func (a *authorizer) exempt(method string) bool {
	if strings.HasPrefix(method, healthService) {
		return true
	}
	for _, e := range a.opts.exempt {
		if e == method || (strings.HasSuffix(e, "/") && strings.HasPrefix(method, e)) {
			return true
		}
	}
	return false
}

func (a *authorizer) deny(ctx context.Context, d Denial) error {
	a.log.Ctx(ctx).Warn("call refused",
		log.F("method", d.Method), log.F("caller", d.Caller.Name),
		log.F("service_account", d.Caller.ServiceAccount), log.F("code", d.Code.String()), log.F("reason", d.Reason))
	if a.opts.onDeny != nil {
		a.opts.onDeny(ctx, d)
	}
	return status.Error(d.Code, d.Reason)
}

// authenticate verifies the bearer token and looks the caller up in the
// policy for method.
func (a *authorizer) authenticate(ctx context.Context, method string) (Grant, error) {
	tok, ok := bearer(ctx)
	if !ok {
		return Grant{}, a.deny(ctx, Denial{Method: method, Code: codes.Unauthenticated, Reason: ReasonNoToken})
	}
	c, err := a.v.Verify(tok)
	switch {
	case errors.Is(err, ErrUnavailable):
		return Grant{}, a.deny(ctx, Denial{Method: method, Code: codes.Unavailable, Reason: ReasonUnavailable})
	case err != nil:
		return Grant{}, a.deny(ctx, Denial{Method: method, Code: codes.Unauthenticated, Reason: ReasonBadToken})
	}
	acc, ok := a.policy.Lookup(method, c.Name)
	if !ok {
		return Grant{}, a.deny(ctx, Denial{Method: method, Caller: c, Code: codes.PermissionDenied, Reason: ReasonMethodNotAllowed})
	}
	return Grant{Caller: c, Access: acc}, nil
}

// checkMessage refuses an actor from a Self caller. A request that can't be
// inspected is refused for a Self caller too.
func (a *authorizer) checkMessage(ctx context.Context, method string, g Grant, req any) error {
	if g.Access != Self {
		return nil
	}
	has, known := carriesActor(req)
	if has || !known {
		return a.deny(ctx, Denial{Method: method, Caller: g.Caller, Code: codes.PermissionDenied, Reason: ReasonActorNotAllowed, Request: req})
	}
	return nil
}

// bearer returns the token from the single "authorization: Bearer <token>"
// metadata value.
func bearer(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get("authorization")
	if len(vals) != 1 {
		return "", false
	}
	scheme, tok, found := strings.Cut(strings.TrimSpace(vals[0]), " ")
	tok = strings.TrimSpace(tok)
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}

// UnaryServerInterceptor authenticates every unary call except the exempt
// ones, checks the caller against p, refuses an actor from a Self caller, and
// runs the handler with the Grant in its context.
func UnaryServerInterceptor(v TokenVerifier, p Policy, lg log.Logger, opts ...Option) grpc.UnaryServerInterceptor {
	a := newAuthorizer(v, p, lg, opts)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if a.exempt(info.FullMethod) {
			return handler(ctx, req)
		}
		g, err := a.authenticate(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		if err := a.checkMessage(ctx, info.FullMethod, g, req); err != nil {
			return nil, err
		}
		log.Trace(a.log.Ctx(ctx), "call authorized",
			log.F("method", info.FullMethod), log.F("caller", g.Caller.Name), log.F("access", g.Access.String()))
		return handler(ContextWithGrant(ctx, g), req)
	}
}

// StreamServerInterceptor is the streaming counterpart: the token and policy
// are checked when the stream opens, and every message received from a Self
// caller is checked for an actor.
func StreamServerInterceptor(v TokenVerifier, p Policy, lg log.Logger, opts ...Option) grpc.StreamServerInterceptor {
	a := newAuthorizer(v, p, lg, opts)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if a.exempt(info.FullMethod) {
			return handler(srv, ss)
		}
		g, err := a.authenticate(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &grantStream{ServerStream: ss, ctx: ContextWithGrant(ss.Context(), g), a: a, method: info.FullMethod, g: g})
	}
}

type grantStream struct {
	grpc.ServerStream
	ctx    context.Context
	a      *authorizer
	method string
	g      Grant
}

func (s *grantStream) Context() context.Context { return s.ctx }

func (s *grantStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return s.a.checkMessage(s.ctx, s.method, s.g, m)
}
