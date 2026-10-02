// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refused reveal, copy, version reveal or field read carries its reason as
// an ErrorInfo, so a client can tell "no access" from "retired".

func wantReason(t *testing.T, err error, code codes.Code, reason, what string) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != code {
		t.Fatalf("%s: code %v, want %v (%v)", what, st.Code(), code, err)
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == errorDomain && info.GetReason() == reason {
			return
		}
	}
	t.Fatalf("%s: no %s ErrorInfo on %v", what, reason, err)
}

func TestRefusedReadsCarryTheirReason(t *testing.T) {
	ctx := context.Background()
	s := newServerWithVersions(t)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	sid := secretIn(t, s, carol, newSharedFolder(t, s), "db")
	nobody := &vaultv1.ActorContext{UserId: "user-nobody", IsRecovery: true, MfaVerifiedAtUnix: time.Now().Unix()}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x"}

	_, err := s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: nobody, Id: sid, FieldKey: "password"})
	wantReason(t, err, codes.PermissionDenied, ReasonNoAccess, "reveal")
	_, err = s.RevealSecretFieldForPrincipal(ctx, &vaultv1.RevealSecretFieldForPrincipalRequest{Actor: sa, Id: sid, FieldKey: "password"})
	wantReason(t, err, codes.PermissionDenied, ReasonNoAccess, "principal reveal")
	_, err = s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: nobody, Id: sid})
	wantReason(t, err, codes.PermissionDenied, ReasonNoAccess, "copy")
	_, err = s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{Actor: nobody, SecretId: sid, VersionNo: 1, FieldKey: "password"})
	wantReason(t, err, codes.PermissionDenied, ReasonNoAccess, "version reveal")
	_, err = s.GetSecretFields(ctx, &vaultv1.GetSecretFieldsRequest{Actor: nobody, Id: sid})
	wantReason(t, err, codes.PermissionDenied, ReasonNoAccess, "fields")

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: sid}); err != nil {
		t.Fatal(err)
	}
	_, err = s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: carol, Id: sid, FieldKey: "password"})
	wantReason(t, err, codes.FailedPrecondition, ReasonRetired, "retired reveal")
	_, err = s.CopySecret(ctx, &vaultv1.CopySecretRequest{Actor: carol, Id: sid})
	wantReason(t, err, codes.FailedPrecondition, ReasonRetired, "retired copy")
	_, err = s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol", IsRecovery: true, MfaVerifiedAtUnix: time.Now().Unix()}, SecretId: sid, VersionNo: 1, FieldKey: "password"})
	wantReason(t, err, codes.FailedPrecondition, ReasonRetired, "retired version reveal")
}
