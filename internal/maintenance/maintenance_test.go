// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/descriptorpb"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

func TestModeNilIsOffAndSetFlips(t *testing.T) {
	var nilMode *Mode
	if nilMode.On() {
		t.Fatal("a nil mode must read as off")
	}
	m := New(false)
	if m.On() {
		t.Fatal("New(false) is on")
	}
	m.Set(true)
	if !m.On() {
		t.Fatal("Set(true) did not turn it on")
	}
	m.Set(false)
	if m.On() {
		t.Fatal("Set(false) did not turn it off")
	}
}

func TestFromEnv(t *testing.T) {
	for _, tc := range []struct {
		val     string
		on, err bool
	}{{"", false, false}, {"false", false, false}, {"true", true, false}, {"1", true, false}, {"yes please", false, true}} {
		m, err := FromEnv(func(k string) string {
			if k != EnvVar {
				t.Fatalf("read %q", k)
			}
			return tc.val
		})
		if (err != nil) != tc.err {
			t.Fatalf("%q: err = %v, want error %v", tc.val, err, tc.err)
		}
		if err == nil && m.On() != tc.on {
			t.Fatalf("%q: on = %v, want %v", tc.val, m.On(), tc.on)
		}
	}
}

// The workflow's protos mark its reads; everything else is a mutation.
func TestClassifyFromIdempotencyLevel(t *testing.T) {
	sd := workflowv1.File_sneakers_workflow_v1_workflow_proto.Services().ByName("WorkflowService")
	c := Classify(sd, nil)
	if got := c[workflowv1.WorkflowService_GetActiveLease_FullMethodName]; got != Read {
		t.Fatalf("GetActiveLease = %v, want read", got)
	}
	if got := c[workflowv1.WorkflowService_CheckoutSecret_FullMethodName]; got != Mutation {
		t.Fatalf("CheckoutSecret = %v, want mutation", got)
	}
	c = Classify(sd, map[string]string{workflowv1.WorkflowService_CheckinSecret_FullMethodName: "test"})
	if got := c[workflowv1.WorkflowService_CheckinSecret_FullMethodName]; got != Allowed {
		t.Fatalf("CheckinSecret with an exemption = %v, want allowed", got)
	}
	if len(c) != sd.Methods().Len() {
		t.Fatalf("classified %d of %d methods", len(c), sd.Methods().Len())
	}
}

func TestReadOnlyRPCsAreMarkedOnTheProto(t *testing.T) {
	md := workflowv1.File_sneakers_workflow_v1_workflow_proto.Services().ByName("WorkflowService").Methods().ByName("GetActiveLease")
	opts, _ := md.Options().(*descriptorpb.MethodOptions)
	if opts.GetIdempotencyLevel() != descriptorpb.MethodOptions_NO_SIDE_EFFECTS {
		t.Fatalf("GetActiveLease idempotency = %v", opts.GetIdempotencyLevel())
	}
}

func classes() map[string]Class {
	return map[string]Class{"/svc/Read": Read, "/svc/Write": Mutation, "/svc/Drain": Allowed}
}

func TestUnaryRefusesMutationsOnlyWhileOn(t *testing.T) {
	m := New(true)
	icpt := UnaryServerInterceptor(m, classes(), "test-domain", log.Nop())
	called := 0
	handler := func(context.Context, any) (any, error) { called++; return "ok", nil }
	call := func(method string) error {
		_, err := icpt(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
		return err
	}
	for _, method := range []string{"/svc/Read", "/svc/Drain", "/grpc.health.v1.Health/Check"} {
		if err := call(method); err != nil {
			t.Fatalf("%s refused while on: %v", method, err)
		}
	}
	err := call("/svc/Write")
	assertRefusal(t, err, "test-domain")
	if called != 3 {
		t.Fatalf("handler called %d times, want 3", called)
	}
	m.Set(false)
	if err := call("/svc/Write"); err != nil {
		t.Fatalf("mutation refused after the mode went off: %v", err)
	}
}

type fakeStream struct{ grpc.ServerStream }

func (fakeStream) Context() context.Context { return context.Background() }

func TestStreamRefusesMutationsWhileOn(t *testing.T) {
	icpt := StreamServerInterceptor(New(true), classes(), "test-domain", log.Nop())
	handler := func(any, grpc.ServerStream) error { return nil }
	if err := icpt(nil, fakeStream{}, &grpc.StreamServerInfo{FullMethod: "/svc/Read"}, handler); err != nil {
		t.Fatalf("read stream refused: %v", err)
	}
	assertRefusal(t, icpt(nil, fakeStream{}, &grpc.StreamServerInfo{FullMethod: "/svc/Write"}, handler), "test-domain")
}

func assertRefusal(t *testing.T, err error, domain string) {
	t.Helper()
	if err == nil {
		t.Fatal("mutation allowed while in maintenance")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == Reason && info.GetDomain() == domain {
			return
		}
	}
	t.Fatalf("no ErrorInfo %s/%s in %v", domain, Reason, st.Details())
}
