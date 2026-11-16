// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func mcpTools(names ...string) *vaultv1.McpToolList { return &vaultv1.McpToolList{Names: names} }

func TestDisabledMcpToolsAreEmptyByDefault(t *testing.T) {
	s := newServer(t)
	got, err := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := got.GetSettings().GetDisabledMcpTools(); len(n) != 0 {
		t.Fatalf("default = %v, want none", n)
	}
}

func TestDisabledMcpToolsAreSiteAdminOnly(t *testing.T) {
	for name, a := range map[string]*vaultv1.ActorContext{
		"ordinary person": {UserId: "user-bob"},
		"admin's token":   adminTokenActor("user-ada"),
		"service account": agentGroupActor("sa-1"),
	} {
		s := newServer(t)
		_, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: a, DisabledMcpTools: mcpTools("sneakers_rotate_secret")})
		if got := reasonOf(t, err, codes.PermissionDenied); got != ReasonNotSiteAdmin {
			t.Fatalf("%s: reason %q", name, got)
		}
		if len(s.settings.GetDisabledMcpTools()) != 0 {
			t.Fatalf("%s: a refused update must change nothing", name)
		}
	}
}

func TestDisabledMcpToolsAreCleanedStoredReadBackAndAudited(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{
		Actor: siteAdmin, DisabledMcpTools: mcpTools("  sneakers_rotate_secret ", "", "sneakers_get_secret", "sneakers_rotate_secret", "   "),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sneakers_rotate_secret", "sneakers_get_secret"}
	if got := resp.GetSettings().GetDisabledMcpTools(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("settings = %v, want %v (trimmed, no empties, no duplicates, in order)", got, want)
	}
	got, _ := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if strings.Join(got.GetSettings().GetDisabledMcpTools(), ",") != strings.Join(want, ",") {
		t.Fatal("GetSecuritySettings must read the new list back")
	}
	ev := ca.find("settings.update")
	if ev == nil || ev.ActorUserID != "user-admin" ||
		ev.Attributes["disabled_mcp_tools.from"] != "" ||
		ev.Attributes["disabled_mcp_tools.to"] != "sneakers_rotate_secret,sneakers_get_secret" {
		t.Fatalf("settings audit = %+v", ev)
	}

	// An update without the field keeps the list and reports nothing for it.
	ca2 := &capAudit{}
	s.audit = ca2
	ttl := int32(1200)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if len(s.settings.GetDisabledMcpTools()) != 2 {
		t.Fatal("an update without the field must keep the list")
	}
	if ev := ca2.find("settings.update"); ev == nil || ev.Attributes["disabled_mcp_tools.to"] != "" {
		t.Fatalf("settings audit = %+v", ev)
	}

	// An empty list present turns every function back on, audited old and new.
	ca3 := &capAudit{}
	s.audit = ca3
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, DisabledMcpTools: mcpTools()}); err != nil {
		t.Fatal(err)
	}
	if len(s.settings.GetDisabledMcpTools()) != 0 {
		t.Fatalf("settings = %v, want none", s.settings.GetDisabledMcpTools())
	}
	if ev := ca3.find("settings.update"); ev == nil ||
		ev.Attributes["disabled_mcp_tools.from"] != "sneakers_rotate_secret,sneakers_get_secret" || ev.Attributes["disabled_mcp_tools.to"] != "" {
		t.Fatalf("settings audit = %+v", ev)
	}
}

func TestDisabledMcpToolsRefuseTooManyAndTooLongAndChangeNothing(t *testing.T) {
	s := newServer(t)
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, DisabledMcpTools: mcpTools("keep_me")}); err != nil {
		t.Fatal(err)
	}
	many := make([]string, 0, maxDisabledMcpTools+1)
	for i := 0; i <= maxDisabledMcpTools; i++ {
		many = append(many, fmt.Sprintf("tool_%d", i))
	}
	for name, names := range map[string][]string{
		"too many names": many,
		"name too long":  {strings.Repeat("a", maxMcpToolNameBytes+1)},
	} {
		_, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, DisabledMcpTools: mcpTools(names...)})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err %v, want InvalidArgument", name, err)
		}
		if got := s.settings.GetDisabledMcpTools(); len(got) != 1 || got[0] != "keep_me" {
			t.Fatalf("%s: a refused update must change nothing, got %v", name, got)
		}
	}
	// Exactly at the limits is fine.
	if _, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, DisabledMcpTools: mcpTools(strings.Repeat("a", maxMcpToolNameBytes))}); err != nil {
		t.Fatalf("a name at the limit: %v", err)
	}
}
