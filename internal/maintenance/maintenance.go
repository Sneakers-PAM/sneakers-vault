// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package maintenance is the read-only maintenance mode the vault and the
// workflow share. While it's on, every mutating RPC is refused with the stable
// reason MAINTENANCE_READONLY; reads keep working, and the services' scheduled
// writers pause.
//
// Which RPCs are reads is declared in the protos: a method with
// `option idempotency_level = NO_SIDE_EFFECTS;` is a read. A service may also
// name methods it serves anyway, most of which write (reveals record the
// access, the connector finishes work it already claimed); every other method
// is a mutation.
package maintenance

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	// EnvVar is the setting that turns the mode on at start.
	EnvVar = "MAINTENANCE_READONLY"
	// Reason is the google.rpc.ErrorInfo reason of a refused call.
	Reason = "MAINTENANCE_READONLY"
	// Message is the refusal's message.
	Message = "the install is in read-only maintenance; changes are refused until it ends"
)

// Mode is the switch. A nil *Mode reads as off.
type Mode struct{ on atomic.Bool }

// New returns a mode that starts on or off.
func New(on bool) *Mode {
	m := &Mode{}
	m.on.Store(on)
	return m
}

// FromEnv reads EnvVar: empty is off, otherwise it must parse as a bool.
func FromEnv(getenv func(string) string) (*Mode, error) {
	raw := strings.TrimSpace(getenv(EnvVar))
	if raw == "" {
		return New(false), nil
	}
	on, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%s=%q: want true or false", EnvVar, raw)
	}
	return New(on), nil
}

// On reports whether the mode is on.
func (m *Mode) On() bool { return m != nil && m.on.Load() }

// Set turns the mode on or off.
func (m *Mode) Set(on bool) { m.on.Store(on) }

// Class is how the mode treats one RPC.
type Class uint8

const (
	// Mutation is refused while the mode is on.
	Mutation Class = iota + 1
	// Read is declared NO_SIDE_EFFECTS on the proto and always served.
	Read
	// Allowed is served anyway, for the reason the service gives.
	Allowed
)

func (c Class) String() string {
	switch c {
	case Mutation:
		return "mutation"
	case Read:
		return "read"
	case Allowed:
		return "allowed"
	default:
		return "unknown"
	}
}

// Classify returns the class of every method of sd, by full method name
// ("/pkg.Service/Method"). allowed names the unmarked methods served anyway,
// each with its reason.
func Classify(sd protoreflect.ServiceDescriptor, allowed map[string]string) map[string]Class {
	out := make(map[string]Class, sd.Methods().Len())
	for i := 0; i < sd.Methods().Len(); i++ {
		md := sd.Methods().Get(i)
		full := "/" + string(sd.FullName()) + "/" + string(md.Name())
		opts, _ := md.Options().(*descriptorpb.MethodOptions)
		switch {
		case opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS:
			out[full] = Read
		case allowed[full] != "":
			out[full] = Allowed
		default:
			out[full] = Mutation
		}
	}
	return out
}

// Refusal is the error a refused call returns: FailedPrecondition with an
// ErrorInfo carrying Reason in domain.
func Refusal(domain string) error {
	st := status.New(codes.FailedPrecondition, Message)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Domain: domain, Reason: Reason}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// refuse reports whether method must be refused now. A method that isn't in
// classes (health, reflection) is never refused.
func refuse(m *Mode, classes map[string]Class, method string) bool {
	return m.On() && classes[method] == Mutation
}

// UnaryServerInterceptor refuses mutating unary calls while m is on.
func UnaryServerInterceptor(m *Mode, classes map[string]Class, domain string, lg log.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if refuse(m, classes, info.FullMethod) {
			lg.Ctx(ctx).Info("call refused: read-only maintenance", log.F("method", info.FullMethod), log.F("reason", Reason))
			return nil, Refusal(domain)
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor refuses mutating streaming calls while m is on.
func StreamServerInterceptor(m *Mode, classes map[string]Class, domain string, lg log.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if refuse(m, classes, info.FullMethod) {
			lg.Ctx(ss.Context()).Info("stream refused: read-only maintenance", log.F("method", info.FullMethod), log.F("reason", Reason))
			return Refusal(domain)
		}
		return handler(srv, ss)
	}
}
