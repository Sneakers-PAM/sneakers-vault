// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadauth

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	methodUser    = "/test.v1.Svc/RevealThing"
	methodConnect = "/test.v1.Svc/ClaimJobs"
)

// testRequest builds a request message shaped like the services' requests:
// an `actor` message field plus an id, without importing any service's protos.
var testRequestDesc = func() protoreflect.MessageDescriptor {
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	boolT := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	msgT := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	fd := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/v1/test.proto"),
		Package: proto.String("test.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Actor"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("user_id"), Number: proto.Int32(1), Type: &str, Label: &opt, JsonName: proto.String("userId")},
				{Name: proto.String("is_root"), Number: proto.Int32(2), Type: &boolT, Label: &opt, JsonName: proto.String("isRoot")},
			}},
			{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("actor"), Number: proto.Int32(1), Type: &msgT, TypeName: proto.String(".test.v1.Actor"), Label: &opt, JsonName: proto.String("actor")},
				{Name: proto.String("id"), Number: proto.Int32(2), Type: &str, Label: &opt, JsonName: proto.String("id")},
			}},
		},
	}
	f, err := protodesc.NewFile(fd, nil)
	if err != nil {
		panic(err)
	}
	return f.Messages().ByName("Request")
}()

func newRequest(userID string, isRoot bool) proto.Message {
	m := dynamicpb.NewMessage(testRequestDesc)
	m.Set(testRequestDesc.Fields().ByName("id"), protoreflect.ValueOfString("s-1"))
	if userID != "" || isRoot {
		ad := testRequestDesc.Fields().ByName("actor").Message()
		a := dynamicpb.NewMessage(ad)
		if userID != "" {
			a.Set(ad.Fields().ByName("user_id"), protoreflect.ValueOfString(userID))
		}
		if isRoot {
			a.Set(ad.Fields().ByName("is_root"), protoreflect.ValueOfBool(true))
		}
		m.Set(testRequestDesc.Fields().ByName("actor"), protoreflect.ValueOfMessage(a))
	}
	return m
}

var testPolicy = Policy{
	methodUser:    {"gateway": OnBehalf, "sshbroker": OnBehalf, "workflow": Self},
	methodConnect: {"connector": Self},
}

type denials struct {
	mu   sync.Mutex
	list []Denial
}

func (d *denials) record(_ context.Context, x Denial) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.list = append(d.list, x)
}

func (d *denials) last(t *testing.T) Denial {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.list) == 0 {
		t.Fatal("no denial recorded")
	}
	return d.list[len(d.list)-1]
}

type fixture struct {
	iss   *testIssuer
	denly *denials
	unary grpc.UnaryServerInterceptor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	iss := newTestIssuer(t)
	v := newVerifier(t, iss,
		testNS+"/sneakers-gateway", testNS+"/sneakers-sshbroker", testNS+"/sneakers-workflow",
		testNS+"/sneakers-connector", testNS+"/sneakers-mcp")
	d := &denials{}
	return &fixture{iss: iss, denly: d, unary: UnaryServerInterceptor(v, testPolicy, log.Nop(), WithDenyHook(d.record))}
}

func (f *fixture) call(t *testing.T, sa, method string, req any) (Grant, error) {
	t.Helper()
	ctx := context.Background()
	if sa != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+f.iss.token(t, testNS, sa)))
	}
	var got Grant
	_, err := f.unary(ctx, req, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
		g, ok := GrantFromContext(ctx)
		if !ok {
			t.Fatal("handler ran without a grant in its context")
		}
		got = g
		return "ok", nil
	})
	return got, err
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("code %v (%v), want %v", status.Code(err), err, want)
	}
}

func TestOnBehalfCallerMayPassAnActor(t *testing.T) {
	f := newFixture(t)
	for _, sa := range []string{"sneakers-gateway", "sneakers-sshbroker"} {
		g, err := f.call(t, sa, methodUser, newRequest("user-1", true))
		if err != nil {
			t.Fatalf("%s: %v", sa, err)
		}
		if g.Access != OnBehalf || g.Caller.ServiceAccount != testNS+"/"+sa {
			t.Fatalf("%s: grant %+v", sa, g)
		}
	}
}

func TestSelfCallerWithoutActorIsAllowed(t *testing.T) {
	f := newFixture(t)
	g, err := f.call(t, "sneakers-workflow", methodUser, newRequest("", false))
	if err != nil {
		t.Fatal(err)
	}
	if g.Access != Self || g.Caller.Name != "workflow" {
		t.Fatalf("grant %+v", g)
	}
}

func TestSelfCallerSendingAnActorIsRefused(t *testing.T) {
	f := newFixture(t)
	for name, req := range map[string]proto.Message{"is_root": newRequest("", true), "user id": newRequest("user-1", false)} {
		t.Run(name, func(t *testing.T) {
			_, err := f.call(t, "sneakers-workflow", methodUser, req)
			wantCode(t, err, codes.PermissionDenied)
			d := f.denly.last(t)
			if d.Caller.Name != "workflow" || d.Method != methodUser || d.Code != codes.PermissionDenied || d.Reason != ReasonActorNotAllowed || d.Request == nil {
				t.Fatalf("denial %+v", d)
			}
		})
	}
}

func TestUnlistedCallerIsRefusedEvenWithAValidToken(t *testing.T) {
	f := newFixture(t)
	_, err := f.call(t, "sneakers-mcp", methodUser, newRequest("user-1", true))
	wantCode(t, err, codes.PermissionDenied)
	if d := f.denly.last(t); d.Caller.Name != "mcp" || d.Reason != ReasonMethodNotAllowed {
		t.Fatalf("denial %+v", d)
	}
	_, err = f.call(t, "sneakers-gateway", methodConnect, newRequest("", false))
	wantCode(t, err, codes.PermissionDenied)
}

func TestMethodMissingFromPolicyIsRefused(t *testing.T) {
	f := newFixture(t)
	_, err := f.call(t, "sneakers-gateway", "/test.v1.Svc/NotListed", newRequest("", false))
	wantCode(t, err, codes.PermissionDenied)
}

func TestMissingOrBadTokenIsUnauthenticated(t *testing.T) {
	f := newFixture(t)
	_, err := f.call(t, "", methodUser, newRequest("user-1", false))
	wantCode(t, err, codes.Unauthenticated)
	if d := f.denly.last(t); d.Reason != ReasonNoToken {
		t.Fatalf("denial %+v", d)
	}
	for name, md := range map[string]metadata.MD{
		"not bearer": metadata.Pairs("authorization", "Basic abc"),
		"garbage":    metadata.Pairs("authorization", "Bearer not-a-jwt"),
		"two values": metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b"),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), md)
			_, err := f.unary(ctx, newRequest("", false), &grpc.UnaryServerInfo{FullMethod: methodUser}, func(context.Context, any) (any, error) {
				t.Fatal("handler ran")
				return nil, nil
			})
			wantCode(t, err, codes.Unauthenticated)
		})
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "bearer "+f.iss.token(t, testNS, "sneakers-gateway")))
	if _, err := f.unary(ctx, newRequest("u", false), &grpc.UnaryServerInfo{FullMethod: methodUser}, func(context.Context, any) (any, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierUnavailableIsUnavailable(t *testing.T) {
	iss := newTestIssuer(t)
	iss.fail.Store(true)
	v, err := NewVerifier(Config{Issuer: iss.URL, CAFile: iss.CAFile, AllowedServiceAccounts: []string{testNS + "/sneakers-gateway"}}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	in := UnaryServerInterceptor(v, testPolicy, log.Nop())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+iss.token(t, testNS, "sneakers-gateway")))
	_, err = in(ctx, newRequest("", false), &grpc.UnaryServerInfo{FullMethod: methodUser}, func(context.Context, any) (any, error) { return nil, nil })
	wantCode(t, err, codes.Unavailable)
}

func TestHealthIsExempt(t *testing.T) {
	f := newFixture(t)
	ran := false
	_, err := f.unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(context.Context, any) (any, error) {
		ran = true
		return nil, nil
	})
	if err != nil || !ran {
		t.Fatalf("health: err=%v ran=%v", err, ran)
	}
}

func TestNonProtoRequestWithActorPolicyIsRefusedForSelf(t *testing.T) {
	f := newFixture(t)
	_, err := f.call(t, "sneakers-workflow", methodUser, "not a proto")
	wantCode(t, err, codes.PermissionDenied)
}

type testStream struct {
	grpc.ServerStream
	ctx  context.Context
	recv []any
}

func (s *testStream) Context() context.Context { return s.ctx }
func (s *testStream) RecvMsg(m any) error {
	src := s.recv[0]
	s.recv = s.recv[1:]
	proto.Merge(m.(proto.Message), src.(proto.Message))
	return nil
}

func TestStreamChecksTokenAndEveryMessage(t *testing.T) {
	f := newFixture(t)
	v := newVerifier(t, f.iss, testNS+"/sneakers-workflow")
	in := StreamServerInterceptor(v, testPolicy, log.Nop())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+f.iss.token(t, testNS, "sneakers-workflow")))
	ss := &testStream{ctx: ctx, recv: []any{newRequest("", false), newRequest("", true)}}
	err := in(nil, ss, &grpc.StreamServerInfo{FullMethod: methodUser}, func(_ any, s grpc.ServerStream) error {
		if _, ok := GrantFromContext(s.Context()); !ok {
			t.Fatal("no grant on the stream context")
		}
		if err := s.RecvMsg(dynamicpb.NewMessage(testRequestDesc)); err != nil {
			t.Fatalf("first message refused: %v", err)
		}
		return s.RecvMsg(dynamicpb.NewMessage(testRequestDesc))
	})
	wantCode(t, err, codes.PermissionDenied)

	ss = &testStream{ctx: context.Background()}
	err = in(nil, ss, &grpc.StreamServerInfo{FullMethod: methodUser}, func(any, grpc.ServerStream) error {
		t.Fatal("handler ran")
		return nil
	})
	wantCode(t, err, codes.Unauthenticated)
}

func TestTokenCredentialsRereadTheFileOnEveryCall(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewTokenCredentials(p)
	md, err := c.GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer first" {
		t.Fatalf("md=%v err=%v", md, err)
	}
	if err := os.WriteFile(p, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	md, err = c.GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer second" {
		t.Fatalf("after rotation md=%v err=%v", md, err)
	}
	if err := os.WriteFile(p, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("an empty token file should fail the call")
	}
	if c.RequireTransportSecurity() {
		t.Fatal("in-cluster gRPC is plaintext; the credentials must not demand TLS")
	}
}

func TestDialOptionFromEnv(t *testing.T) {
	if opt, ok, err := DialOptionFromEnv(envMap(nil)); opt != nil || ok || err != nil {
		t.Fatalf("unset: opt=%v ok=%v err=%v", opt, ok, err)
	}
	if _, _, err := DialOptionFromEnv(envMap(map[string]string{EnvTokenFile: "/nonexistent/token"})); err == nil {
		t.Fatal("a missing token file should fail at start")
	}
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if opt, ok, err := DialOptionFromEnv(envMap(map[string]string{EnvTokenFile: p})); opt == nil || !ok || err != nil {
		t.Fatalf("set: opt=%v ok=%v err=%v", opt, ok, err)
	}
}
