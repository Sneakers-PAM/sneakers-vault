// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maintenanceGolden pins how the read-only mode treats every vault method. A
// new RPC fails this test until it's placed: a read gets
// `idempotency_level = NO_SIDE_EFFECTS` on the proto, a writing method that
// must keep working goes in maintenanceAllowed, and anything else is refused.
var maintenanceGolden = map[maintenance.Class][]string{
	maintenance.Read: {
		"ListConnections", "ListTargets", "GetTargetRuleset", "ListSecretTypes", "ListAvailableExtensions",
		"ListFolders", "ListFolderRules", "GetInheritedFolderRules", "GetFolderRuleset", "GetMyAccess",
		"SimulateFolder", "SimulateSecret", "ListSecretsInFolder", "GetSecret", "GetSecretFields",
		"ListSecretsForPrincipal", "ListFoldersForPrincipal", "ListSecretVersions", "GetSecretStats",
		"GetTopAccessedSecrets", "ListSecretsByStatus", "FindSecretsByPublicKey", "GetSecretRuleset",
		"GetMySecretAccess", "ListConnectors", "ListPasswordPolicies", "GetSecuritySettings",
		"GenerateKeyPair", "GetSecretUse", "ListPendingSecretUses", "ListUseGrants",
	},
	maintenance.Allowed: {
		"RevealSecretField", "RevealSecretFieldForPrincipal", "RevealSecretVersionField", "CopySecret",
		"ExportCertificate", "ClaimDueHeartbeats", "RevealForHeartbeat", "ReportHeartbeat",
		"ClaimDueRotations", "ReportRotation", "GetHeartbeatStatusForPrincipal",
	},
	maintenance.Mutation: {
		"SaveConnection", "DeleteConnection", "SaveTarget", "DeleteTarget", "SetTargetRuleset",
		"ImportCertificate", "ReplaceCertificate", "CreateSecretType", "UpdateSecretType",
		"DeleteSecretType", "CloneSecretType", "ImportExtension", "ImportExtensionFromJson",
		"CreateFolder", "RenameFolder", "MoveFolder", "DeleteFolder", "ReorderFolders", "AddFolderRule",
		"RemoveFolderRule", "SetFolderRuleset", "SetFolderRevealStepUp", "CreateSecret", "UpdateSecret",
		"SetSecretAutomation", "CreateSecretForPrincipal", "GenerateSecretForPrincipal",
		"MoveSecretForPrincipal", "ChangeSecretTypeForPrincipal", "RenameSecretForPrincipal",
		"UpdateSecretFieldsForPrincipal", "CreateFolderForPrincipal", "RenameFolderForPrincipal",
		"MoveFolderForPrincipal", "RestoreSecretVersion", "BreakGlassSecret", "RetireSecret",
		"RestoreSecret", "DeleteSecret", "SetSecretRuleset", "EnqueueRotation", "RevealForRotation",
		"SavePasswordPolicy", "DeletePasswordPolicy", "UpdateSecuritySettings", "SeedBuiltins",
		"RotateKek", "SealForImport", "PrepareSecretUse", "DecideSecretUse", "RedeemSecretUse",
		"CreateUseGrant", "RevokeUseGrant", "SetSecretTokenApproval", "SetSecretTargetForPrincipal",
		"SetSecretAutomationForPrincipal", "RequestHeartbeatForPrincipal",
	},
}

func TestMaintenanceClassifiesEveryVaultMethod(t *testing.T) {
	got := MaintenanceClasses()
	desc := vaultv1.VaultService_ServiceDesc
	want := map[string]maintenance.Class{}
	for class, names := range maintenanceGolden {
		for _, n := range names {
			want["/"+desc.ServiceName+"/"+n] = class
		}
	}
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		w, ok := want[full]
		if !ok {
			t.Errorf("%s isn't classified for maintenance: add it to maintenanceGolden (and mark it on the proto if it's a read)", md.MethodName)
			continue
		}
		if got[full] != w {
			t.Errorf("%s: class %v, want %v", md.MethodName, got[full], w)
		}
	}
	if len(want) != len(desc.Methods) {
		t.Errorf("golden lists %d methods, the service has %d", len(want), len(desc.Methods))
	}
}

// A method that persists vault state can never be declared a read.
func TestMaintenanceNoPersistingMethodIsARead(t *testing.T) {
	got := MaintenanceClasses()
	for m := range mutatingMethods {
		full := "/" + vaultv1.VaultService_ServiceDesc.ServiceName + "/" + m
		if got[full] == maintenance.Read {
			t.Errorf("%s persists state but is marked NO_SIDE_EFFECTS", m)
		}
	}
}

// While the mode is on the connector is handed no heartbeat or rotation jobs;
// once it's off the due work is claimed again.
func TestMaintenancePausesHeartbeatAndRotationClaims(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	ctx := context.Background()
	if _, err := fx.s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: id, Reason: "manual"}); err != nil {
		t.Fatalf("EnqueueRotation: %v", err)
	}
	mode := maintenance.New(true)
	fx.s.SetMaintenance(mode)
	worker := &vaultv1.WorkerIdentity{Token: "ok"}
	hb, err := fx.s.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{Identity: worker})
	if err != nil || len(hb.GetJobs()) != 0 {
		t.Fatalf("heartbeat claim in maintenance = %v, %v; want no jobs", hb.GetJobs(), err)
	}
	rot, err := fx.s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: worker})
	if err != nil || len(rot.GetJobs()) != 0 {
		t.Fatalf("rotation claim in maintenance = %v, %v; want no jobs", rot.GetJobs(), err)
	}
	mode.Set(false)
	claimedJob(t, fx.s, id)
	rot, err = fx.s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: worker})
	if err != nil || len(rot.GetJobs()) != 1 {
		t.Fatalf("rotation claim after maintenance = %v, %v; want the due job", rot.GetJobs(), err)
	}
}

// The KEK rotation schedule doesn't rotate while the mode is on and catches
// up on the first tick after.
func TestMaintenancePausesKekScheduler(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	s.store = &recordingStore{}
	s.mu.Lock()
	s.settings.KekRotationDays = 30
	s.mu.Unlock()
	fx.ks.mu.Lock()
	for i := range fx.ks.rows {
		if fx.ks.rows[i].Ref == "kek-v1" {
			fx.ks.rows[i].CreatedAt = time.Now().Add(-40 * 24 * time.Hour)
		}
	}
	fx.ks.mu.Unlock()
	mode := maintenance.New(true)
	s.SetMaintenance(mode)
	if err := s.kekSchedulerTick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if got := s.keyring.ActiveRef(); got != "kek-v1" {
		t.Fatalf("rotated to %q during maintenance", got)
	}
	mode.Set(false)
	if err := s.kekSchedulerTick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if got := s.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef after maintenance = %q, want kek-v2", got)
	}
}

// The vault's interceptor refuses a mutation with the reason in the vault's
// error domain and serves reads and reveals.
func TestMaintenanceInterceptorRefusesVaultMutations(t *testing.T) {
	unary, _ := MaintenanceInterceptors(maintenance.New(true), log.Nop())
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	for _, m := range []string{vaultv1.VaultService_ListFolders_FullMethodName, vaultv1.VaultService_RevealSecretField_FullMethodName} {
		if _, err := unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: m}, handler); err != nil {
			t.Fatalf("%s refused: %v", m, err)
		}
	}
	for _, m := range []string{vaultv1.VaultService_CreateFolder_FullMethodName, vaultv1.VaultService_BreakGlassSecret_FullMethodName} {
		_, err := unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: m}, handler)
		st := status.Convert(err)
		if st.Code() != codes.FailedPrecondition {
			t.Fatalf("%s: code %v, want FailedPrecondition", m, st.Code())
		}
		found := false
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == errorDomain && info.GetReason() == maintenance.Reason {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: no %s ErrorInfo in %v", m, maintenance.Reason, st.Details())
		}
	}
}
