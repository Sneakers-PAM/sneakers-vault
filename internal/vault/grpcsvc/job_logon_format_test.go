// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// Heartbeat and rotation jobs carry the Active Directory type's logon format
// fields, so the connector binds with the logon name the domain expects.

func (fx *noTargetFixture) createAD(t *testing.T, fields map[string]string) string {
	t.Helper()
	all := map[string]string{"domain": "ad.example.org", "username": "svc_app", "password": "Init1alP@ss-2026"}
	for k, v := range fields {
		all[k] = v
	}
	c, err := fx.s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "svc_app", FolderId: fx.folder, TypeId: "type-active-directory", TargetId: fx.target, Fields: all,
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return c.GetSecret().GetId()
}

func TestJobsCarryTheADLogonFormat(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createAD(t, map[string]string{"logonFormat": ADLogonFormatUPN, "netbios": "EXAMPLE", "upnSuffix": "example.org"})
	want := &vaultv1.LogonFormat{Format: ADLogonFormatUPN, Netbios: "EXAMPLE", UpnSuffix: "example.org"}
	for name, got := range map[string]*vaultv1.LogonFormat{
		"heartbeat": claimedJob(t, fx.s, id).GetLogon(),
		"rotation":  claimedRotation(t, fx.s, id).GetLogon(),
	} {
		if got.GetFormat() != want.GetFormat() || got.GetNetbios() != want.GetNetbios() || got.GetUpnSuffix() != want.GetUpnSuffix() {
			t.Fatalf("%s job logon = %+v, want %+v", name, got, want)
		}
	}
}

func TestJobsWithoutALogonFormatCarryNone(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createAD(t, nil)
	if got := claimedJob(t, fx.s, id).GetLogon(); got != nil {
		t.Fatalf("heartbeat job logon = %+v, want unset", got)
	}
	human := fx.createHuman(t, fx.target)
	if got := claimedRotation(t, fx.s, human).GetLogon(); got != nil {
		t.Fatalf("rotation job for a non-AD secret logon = %+v, want unset", got)
	}
}
