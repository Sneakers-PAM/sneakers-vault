// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func networks(cidrs ...string) *vaultv1.NetworkList { return &vaultv1.NetworkList{Cidrs: cidrs} }

func TestNetworkSettingsAreOffByDefault(t *testing.T) {
	s := newServer(t)
	got, err := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	st := got.GetSettings()
	if st.GetInternalOnly() || st.GetRequireManaged() || len(st.GetAllowedNetworks()) != 0 {
		t.Fatalf("defaults = %+v", st)
	}
}

func TestNetworkSettingsAreSiteAdminOnly(t *testing.T) {
	on := true
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		"admin's token":   adminTokenActor("user-ada"),
		"service account": agentGroupActor("sa-1"),
	} {
		s := newServer(t)
		_, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: a, RequireManaged: &on, AllowedNetworks: networks("192.0.2.0/24"), InternalOnly: &on})
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonNotSiteAdmin {
			t.Fatalf("%s: reason %q", name, got)
		}
		if s.settings.GetRequireManaged() || s.settings.GetInternalOnly() || len(s.settings.GetAllowedNetworks()) != 0 {
			t.Fatalf("%s: a refused update must change nothing", name)
		}
	}
}

func TestInternalOnlyAndAllowedNetworksChangeTogetherAndAreAudited(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	on := true
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{
		Actor: siteAdmin, InternalOnly: &on, AllowedNetworks: networks("192.0.2.0/24", "198.51.100.7", "2001:db8::/32", "192.0.2.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	st := resp.GetSettings()
	want := []string{"192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32"}
	if !st.GetInternalOnly() || len(st.GetAllowedNetworks()) != len(want) {
		t.Fatalf("settings = %+v", st)
	}
	for i, n := range want {
		if st.GetAllowedNetworks()[i] != n {
			t.Fatalf("networks = %v, want %v (canonical, in order, no duplicates)", st.GetAllowedNetworks(), want)
		}
	}
	got, _ := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if !got.GetSettings().GetInternalOnly() || len(got.GetSettings().GetAllowedNetworks()) != 3 {
		t.Fatal("GetSecuritySettings must read the new values back")
	}
	ev := ca.find("settings.update")
	if ev == nil || ev.ActorUserID != "user-admin" ||
		ev.Attributes["internal_only.from"] != "false" || ev.Attributes["internal_only.to"] != "true" ||
		ev.Attributes["allowed_networks.from"] != "" || ev.Attributes["allowed_networks.to"] != "192.0.2.0/24,198.51.100.7/32,2001:db8::/32" {
		t.Fatalf("settings audit = %+v", ev)
	}

	// A partial update of another field keeps both and reports neither.
	ca2 := &capAudit{}
	s.audit = ca2
	ttl := int32(1200)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if !s.settings.GetInternalOnly() || len(s.settings.GetAllowedNetworks()) != 3 {
		t.Fatal("an update without the fields must keep them")
	}
	if ev := ca2.find("settings.update"); ev == nil || ev.Attributes["internal_only.to"] != "" || ev.Attributes["allowed_networks.to"] != "" {
		t.Fatalf("settings audit = %+v", ev)
	}
}

func TestInternalOnlyRefusesAnInvalidNetworkAndAnEmptyList(t *testing.T) {
	on, off := true, false
	s := newServer(t)
	for name, req := range map[string]*vaultv1.UpdateSecuritySettingsRequest{
		"not an address":            {AllowedNetworks: networks("office")},
		"bad prefix length":         {AllowedNetworks: networks("192.0.2.0/33")},
		"an empty entry":            {AllowedNetworks: networks("")},
		"too many networks":         {AllowedNetworks: networks(manyNetworks()...)},
		"internal only, no network": {InternalOnly: &on},
		"internal only, empty list": {InternalOnly: &on, AllowedNetworks: networks()},
	} {
		req.Actor = siteAdmin
		if _, err := s.UpdateSecuritySettings(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err %v, want InvalidArgument", name, err)
		}
		if s.settings.GetInternalOnly() || len(s.settings.GetAllowedNetworks()) != 0 {
			t.Fatalf("%s: a refused update must change nothing", name)
		}
	}

	// With it on, the list can't be emptied underneath it, but switching it off first works.
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, InternalOnly: &on, AllowedNetworks: networks("192.0.2.0/24")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, AllowedNetworks: networks()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("emptying the list while on: err %v, want InvalidArgument", err)
	}
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, InternalOnly: &off, AllowedNetworks: networks()}); err != nil {
		t.Fatalf("turning it off and clearing the list: %v", err)
	}
	if s.settings.GetInternalOnly() || len(s.settings.GetAllowedNetworks()) != 0 {
		t.Fatalf("settings = %+v", s.settings)
	}
}

func manyNetworks() []string {
	out := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		out = append(out, "2001:db8:"+string(rune('a'+i%26))+string(rune('a'+i/26))+"::/48")
	}
	return out
}

func TestRequireManagedIsAuditedAndPartial(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	on := true
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, RequireManaged: &on})
	if err != nil || !resp.GetSettings().GetRequireManaged() {
		t.Fatalf("UpdateSecuritySettings: %v %v", resp, err)
	}
	if ev := ca.find("settings.update"); ev == nil || ev.Attributes["require_managed.from"] != "false" || ev.Attributes["require_managed.to"] != "true" {
		t.Fatalf("settings audit = %+v", ev)
	}
	ttl := int32(1200)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if !s.settings.GetRequireManaged() {
		t.Fatal("an update without the field must keep it")
	}
}
