// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"maps"
	"testing"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
)

func TestCallerPolicyPerMethod(t *testing.T) {
	p := CallerPolicy()
	desc := workflowv1.WorkflowService_ServiceDesc
	if len(desc.Streams) != 0 || len(p) != len(desc.Methods) {
		t.Fatalf("policy covers %d of %d methods (%d streams)", len(p), len(desc.Methods), len(desc.Streams))
	}
	want := map[string]workloadauth.Access{CallerGateway: workloadauth.OnBehalf}
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		if got := p[full]; !maps.Equal(got, want) {
			t.Errorf("%s: allow-list %v, want %v", md.MethodName, got, want)
		}
		for _, c := range []string{"mcp", "vault", "connector", "sshbroker", "identity"} {
			if _, ok := p.Lookup(full, c); ok {
				t.Errorf("%s: %s must not be allowed", md.MethodName, c)
			}
		}
	}
}
