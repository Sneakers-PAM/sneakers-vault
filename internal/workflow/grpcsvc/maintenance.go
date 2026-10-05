// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	log "github.com/Bugs5382/go-log"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
	"google.golang.org/grpc"
)

// MaintenanceClasses is how the read-only mode treats each workflow method:
// the reads are declared on the proto, everything else is refused.
func MaintenanceClasses() map[string]maintenance.Class {
	sd := workflowv1.File_sneakers_workflow_v1_workflow_proto.Services().ByName("WorkflowService")
	return maintenance.Classify(sd, nil)
}

// SetMaintenance installs the read-only maintenance switch the reaper and the
// history purge check. Without one the mode is off.
func (s *Server) SetMaintenance(m *maintenance.Mode) { s.maint = m }

// MaintenanceInterceptors are the unary and stream interceptors that refuse
// mutating calls while m is on, with the reason in this service's error
// domain. Install them after workload authentication.
func MaintenanceInterceptors(m *maintenance.Mode, lg log.Logger) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	classes := MaintenanceClasses()
	return maintenance.UnaryServerInterceptor(m, classes, errorDomain, lg),
		maintenance.StreamServerInterceptor(m, classes, errorDomain, lg)
}
