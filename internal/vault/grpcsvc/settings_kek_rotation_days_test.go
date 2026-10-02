// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// TestEnsureSecuritySettingsSeedsKekRotationDays verifies that a fresh
// instance's seeded SecuritySettings.kek_rotation_days resolves from
// KEK_ROTATION_DAYS (falling back to 90 when unset/invalid) — the env default
// applies to FRESH instances only, at seed time.
func TestEnsureSecuritySettingsSeedsKekRotationDays(t *testing.T) {
	t.Run("env-unset", func(t *testing.T) {
		s := newServer(t)
		if got := s.settings.GetKekRotationDays(); got != defaultKekRotationDays() {
			t.Fatalf("seeded KekRotationDays = %d, want %d", got, defaultKekRotationDays())
		}
		if got := s.settings.GetKekRotationDays(); got != 90 {
			t.Fatalf("seeded KekRotationDays = %d, want 90 (default)", got)
		}
	})

	t.Run("env-set", func(t *testing.T) {
		t.Setenv("KEK_ROTATION_DAYS", "45")
		s := newServer(t)
		if got := s.settings.GetKekRotationDays(); got != 45 {
			t.Fatalf("seeded KekRotationDays = %d, want 45", got)
		}
	})
}

// TestUpdateSecuritySettingsKekRotationDays verifies UpdateSecuritySettings
// persists an admin-supplied kek_rotation_days verbatim — 0 is a valid "off"
// value and must NOT be coerced to the default, unlike session_ttl_seconds.
func TestUpdateSecuritySettingsKekRotationDays(t *testing.T) {
	ctx := context.Background()
	actor := &vaultv1.ActorContext{UserId: "user-carol"}

	t.Run("set-30", func(t *testing.T) {
		s := newServer(t)
		days := int32(30)
		resp, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
			Actor:           actor,
			KekRotationDays: &days,
		})
		if err != nil {
			t.Fatalf("UpdateSecuritySettings: %v", err)
		}
		if got := resp.GetSettings().GetKekRotationDays(); got != 30 {
			t.Fatalf("KekRotationDays = %d, want 30", got)
		}
		got, err := s.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
		if err != nil {
			t.Fatalf("GetSecuritySettings: %v", err)
		}
		if v := got.GetSettings().GetKekRotationDays(); v != 30 {
			t.Fatalf("persisted KekRotationDays = %d, want 30", v)
		}
	})

	t.Run("set-0-is-off-not-coerced", func(t *testing.T) {
		s := newServer(t)
		zero := int32(0)
		resp, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
			Actor:           actor,
			KekRotationDays: &zero,
		})
		if err != nil {
			t.Fatalf("UpdateSecuritySettings: %v", err)
		}
		if got := resp.GetSettings().GetKekRotationDays(); got != 0 {
			t.Fatalf("KekRotationDays = %d, want 0 (off, not coerced to default)", got)
		}
		got, err := s.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
		if err != nil {
			t.Fatalf("GetSecuritySettings: %v", err)
		}
		if v := got.GetSettings().GetKekRotationDays(); v != 0 {
			t.Fatalf("persisted KekRotationDays = %d, want 0", v)
		}
	})

	t.Run("nil-field-unchanged", func(t *testing.T) {
		s := newServer(t)
		before := s.settings.GetKekRotationDays()
		mfa := true
		if _, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
			Actor:                          actor,
			RequireMfaForSensitiveCheckout: &mfa,
		}); err != nil {
			t.Fatalf("UpdateSecuritySettings: %v", err)
		}
		if got := s.settings.GetKekRotationDays(); got != before {
			t.Fatalf("KekRotationDays changed to %d, want unchanged %d", got, before)
		}
	})
}

// TestSettingsWithDefaultsDoesNotCoerceKekRotationDays verifies read-time
// defaulting never touches kek_rotation_days: 0 (off) stays 0, unlike
// session_ttl_seconds / request_history_retention_days which default on read.
func TestSettingsWithDefaultsDoesNotCoerceKekRotationDays(t *testing.T) {
	in := &vaultv1.SecuritySettings{KekRotationDays: 0}
	out := settingsWithDefaults(in)
	if got := out.GetKekRotationDays(); got != 0 {
		t.Fatalf("settingsWithDefaults coerced KekRotationDays to %d, want 0", got)
	}
}
