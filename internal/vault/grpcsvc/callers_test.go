// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"maps"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
)

// TestCallerPolicyPerMethod pins the allow-list of every vault method: who may
// call it, and whether they may pass an end-user actor.
func TestCallerPolicyPerMethod(t *testing.T) {
	gw := workloadauth.OnBehalf
	self := workloadauth.Self
	special := map[string]map[string]workloadauth.Access{
		"ClaimDueHeartbeats":  {CallerConnector: self},
		"RevealForHeartbeat":  {CallerConnector: self},
		"ReportHeartbeat":     {CallerConnector: self},
		"ClaimDueRotations":   {CallerConnector: self},
		"RevealForRotation":   {CallerConnector: self},
		"ReportRotation":      {CallerConnector: self},
		"RevealSecretField":   {CallerGateway: gw, CallerSSHBroker: gw, CallerMigrate: self},
		"ListTargets":         {CallerGateway: gw, CallerMigrate: self},
		"ListConnections":     {CallerGateway: gw, CallerMigrate: self},
		"SealForImport":       {CallerMigrate: self},
		"GetSecretRuleset":    {CallerGateway: gw, CallerWorkflow: self},
		"SetSecretRuleset":    {CallerGateway: gw, CallerWorkflow: self},
		"MoveFolder":          {CallerGateway: gw, CallerWorkflow: self},
		"UpdateSecret":        {CallerGateway: gw, CallerWorkflow: self},
		"EnqueueRotation":     {CallerGateway: gw, CallerWorkflow: self},
		"GetSecuritySettings": {CallerGateway: gw, CallerWorkflow: self},
		"GetSecret":           {CallerGateway: gw, CallerWorkflow: self, CallerMigrate: self},
		"ListSecretTypes":     {CallerGateway: gw, CallerWorkflow: self},
		"GetMySecretAccess":   {CallerGateway: gw, CallerWorkflow: gw},
	}
	p := CallerPolicy()
	desc := vaultv1.VaultService_ServiceDesc
	if len(desc.Streams) != 0 {
		t.Fatalf("the vault has streaming methods now; give them an allow-list: %v", desc.Streams)
	}
	if len(p) != len(desc.Methods) {
		t.Fatalf("policy covers %d methods, the service has %d", len(p), len(desc.Methods))
	}
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		want, ok := special[md.MethodName]
		if !ok {
			want = map[string]workloadauth.Access{CallerGateway: gw}
		}
		if got := p[full]; !maps.Equal(got, want) {
			t.Errorf("%s: allow-list %v, want %v", md.MethodName, got, want)
		}
		for _, c := range []string{"mcp", "identity", "notify", "audit"} {
			if _, ok := p.Lookup(full, c); ok {
				t.Errorf("%s: %s must not be allowed", md.MethodName, c)
			}
		}
	}
}
