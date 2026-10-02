// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Access is what a caller may do on one method.
type Access uint8

const (
	// Self lets the caller call the method as itself only. A request that
	// carries an `actor` is refused.
	Self Access = iota + 1
	// OnBehalf lets the caller pass an end-user actor, which the callee
	// trusts because the caller is authenticated and listed.
	OnBehalf
)

func (a Access) String() string {
	switch a {
	case Self:
		return "self"
	case OnBehalf:
		return "on-behalf"
	default:
		return "none"
	}
}

// Policy is the per-method allow-list: full gRPC method name
// ("/pkg.v1.Service/Method") to caller name to Access. A method that isn't in
// the policy, or a caller that isn't in a method's entry, is refused.
type Policy map[string]map[string]Access

// Lookup returns the caller's access to method; ok is false when the caller
// isn't listed for it.
func (p Policy) Lookup(method, caller string) (Access, bool) {
	a, ok := p[method][caller]
	return a, ok && (a == Self || a == OnBehalf)
}

// Grant is the verified caller and its access to the method being served.
type Grant struct {
	Caller Caller
	Access Access
}

type grantKey struct{}

// ContextWithGrant returns ctx carrying g. The interceptors call it; tests of
// handlers that read the grant may too.
func ContextWithGrant(ctx context.Context, g Grant) context.Context {
	return context.WithValue(ctx, grantKey{}, g)
}

// GrantFromContext returns the grant the interceptor attached; ok is false when
// the call wasn't authenticated (an exempt method, or authentication off).
func GrantFromContext(ctx context.Context) (Grant, bool) {
	g, ok := ctx.Value(grantKey{}).(Grant)
	return g, ok
}

// actorField is the request field that carries an end-user actor in every
// Sneakers API.
const actorField = "actor"

// carriesActor reports whether req sets a non-empty top-level `actor` field.
// known is false when req isn't a protobuf message, so it can't be inspected.
func carriesActor(req any) (has, known bool) {
	m, ok := req.(proto.Message)
	if !ok || m == nil {
		return false, false
	}
	r := m.ProtoReflect()
	if !r.IsValid() {
		return false, true
	}
	fd := r.Descriptor().Fields().ByName(actorField)
	if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
		return false, true
	}
	if !r.Has(fd) {
		return false, true
	}
	return proto.Size(r.Get(fd).Message().Interface()) > 0, true
}
