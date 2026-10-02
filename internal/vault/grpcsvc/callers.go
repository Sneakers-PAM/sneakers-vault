// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
)

// Caller names, from the service accounts sneakers-<name>.
const (
	CallerGateway   = "gateway"
	CallerWorkflow  = "workflow"
	CallerSSHBroker = "sshbroker"
	CallerConnector = "connector"
)

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
// temporary read grant behind a lease, approved moves, rotation on check-in
// and the request-history retention setting.
var workflowMethods = []string{
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
// and the connector act only as themselves. Anything else is refused.
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
	return p
}
