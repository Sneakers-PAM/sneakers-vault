// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	workloadauth "github.com/Bugs5382/go-workload-identity"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

// CallerGateway is the gateway's caller name, from its service account
// sneakers-gateway.
const CallerGateway = "gateway"

// CallerPolicy is the workflow service's per-method allow-list: only the
// gateway calls it, passing the signed-in user's actor.
func CallerPolicy() workloadauth.Policy {
	p := workloadauth.Policy{}
	for _, md := range workflowv1.WorkflowService_ServiceDesc.Methods {
		m := "/" + workflowv1.WorkflowService_ServiceDesc.ServiceName + "/" + md.MethodName
		p[m] = map[string]workloadauth.Access{CallerGateway: workloadauth.OnBehalf}
	}
	return p
}
