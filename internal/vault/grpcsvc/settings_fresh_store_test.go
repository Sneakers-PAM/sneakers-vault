// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// A production store starts empty and holds no security settings until
// first-run setup. Reading them must give the defaults, not a panic: the
// gateway and the workflow read them on a timer from the first minute.

// freshProdServer is a production vault on an empty store, before setup.
func freshProdServer(t *testing.T) *Server {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kek), nil, "production")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	return s
}

func TestGetSecuritySettingsBeforeSetupReturnsTheDefaults(t *testing.T) {
	t.Setenv("KEK_ROTATION_DAYS", "")
	s := freshProdServer(t)
	if s.settings != nil {
		t.Fatal("precondition: a production store has no settings before setup")
	}
	resp, err := s.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		t.Fatalf("GetSecuritySettings: %v", err)
	}
	got := resp.GetSettings()
	if got.GetRequestHistoryRetentionDays() != 90 || got.GetSessionTtlSeconds() != 1800 ||
		got.GetKekRotationDays() != 90 || !got.GetRequireMfaForSensitiveCheckout() || got.GetAllowApiForSensitive() ||
		got.GetDefaultPasswordPolicyId() != "pwpolicy-default" {
		t.Fatalf("settings = %v, want the defaults setup would install", got)
	}
	if s.settings != nil {
		t.Fatal("a read must not install settings")
	}
}

func TestUpdateSecuritySettingsBeforeSetupStartsFromTheDefaults(t *testing.T) {
	s := freshProdServer(t)
	ttl := int32(1200)
	resp, err := s.UpdateSecuritySettings(context.Background(), &vaultv1.UpdateSecuritySettingsRequest{Actor: siteAdmin, SessionTtlSeconds: &ttl})
	if err != nil {
		t.Fatalf("UpdateSecuritySettings: %v", err)
	}
	if resp.GetSettings().GetSessionTtlSeconds() != 1200 || resp.GetSettings().GetRequestHistoryRetentionDays() != 90 {
		t.Fatalf("settings = %v", resp.GetSettings())
	}
}
