// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
	"google.golang.org/grpc"
)

// maintenanceAllowed are the vault methods that keep working in read-only
// maintenance without a NO_SIDE_EFFECTS mark on the proto, each with why:
// most of them write, but must still be served.
var maintenanceAllowed = map[string]string{
	vaultv1.VaultService_RevealSecretField_FullMethodName:              "a reveal; it only counts the view",
	vaultv1.VaultService_RevealSecretFieldForPrincipal_FullMethodName:  "a reveal; it only counts the view",
	vaultv1.VaultService_RevealSecretVersionField_FullMethodName:       "a reveal; it only counts the view",
	vaultv1.VaultService_CopySecret_FullMethodName:                     "a reveal; it only counts the view",
	vaultv1.VaultService_ExportCertificate_FullMethodName:              "a reveal; it only counts the view",
	vaultv1.VaultService_ClaimDueHeartbeats_FullMethodName:             "answers with no jobs while the mode is on",
	vaultv1.VaultService_ClaimDueRotations_FullMethodName:              "answers with no jobs while the mode is on",
	vaultv1.VaultService_RevealForHeartbeat_FullMethodName:             "finishes a heartbeat claimed before the mode went on",
	vaultv1.VaultService_ReportHeartbeat_FullMethodName:                "finishes a heartbeat claimed before the mode went on",
	vaultv1.VaultService_ReportRotation_FullMethodName:                 "records a password the connector already changed on the target",
	vaultv1.VaultService_GetHeartbeatStatusForPrincipal_FullMethodName: "a status read, served without a proto mark",
	vaultv1.VaultService_CloseBreakGlassSession_FullMethodName:         "ends a break-glass session; it changes no vault data",
}

// MaintenanceClasses is how the read-only mode treats each vault method.
func MaintenanceClasses() map[string]maintenance.Class {
	sd := vaultv1.File_sneakers_vault_v1_vault_proto.Services().ByName("VaultService")
	return maintenance.Classify(sd, maintenanceAllowed)
}

// SetMaintenance installs the read-only maintenance switch the pull-API and
// the KEK schedule check. Without one the mode is off.
func (s *Server) SetMaintenance(m *maintenance.Mode) { s.maint = m }

// MaintenanceInterceptors are the unary and stream interceptors that refuse
// mutating calls while m is on, with the reason in this service's error
// domain. Install them after workload authentication.
func MaintenanceInterceptors(m *maintenance.Mode, lg log.Logger) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	classes := MaintenanceClasses()
	return maintenance.UnaryServerInterceptor(m, classes, errorDomain, lg),
		maintenance.StreamServerInterceptor(m, classes, errorDomain, lg)
}
