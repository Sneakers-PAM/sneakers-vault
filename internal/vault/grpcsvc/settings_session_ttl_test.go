// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// TestSessionTTLDefault verifies that an unset (zero) session TTL resolves to
// the 30-minute default on read.
func TestSessionTTLDefault(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	resp, err := s.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		t.Fatalf("GetSecuritySettings: %v", err)
	}
	if got := resp.GetSettings().GetSessionTtlSeconds(); got != defaultSessionTTLSeconds {
		t.Fatalf("default session TTL = %d, want %d", got, defaultSessionTTLSeconds)
	}
}

// TestSessionTTLClamp verifies UpdateSecuritySettings clamps the stored TTL to
// the [15m, 60m] policy bounds and passes valid values through unchanged.
func TestSessionTTLClamp(t *testing.T) {
	ctx := context.Background()
	actor := &vaultv1.ActorContext{UserId: "user-carol"}

	cases := []struct {
		name string
		in   int32
		want int32
	}{
		{"below-min", 60, minSessionTTLSeconds},
		{"at-min", 900, 900},
		{"in-range", 1200, 1200},
		{"at-max", 3600, 3600},
		{"above-max", 100000, maxSessionTTLSeconds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			ttl := tc.in
			resp, err := s.UpdateSecuritySettings(ctx, &vaultv1.UpdateSecuritySettingsRequest{
				Actor:             actor,
				SessionTtlSeconds: &ttl,
			})
			if err != nil {
				t.Fatalf("UpdateSecuritySettings: %v", err)
			}
			if got := resp.GetSettings().GetSessionTtlSeconds(); got != tc.want {
				t.Fatalf("session TTL = %d, want %d", got, tc.want)
			}
			// A subsequent read must return the same clamped, persisted value.
			got, err := s.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
			if err != nil {
				t.Fatalf("GetSecuritySettings: %v", err)
			}
			if v := got.GetSettings().GetSessionTtlSeconds(); v != tc.want {
				t.Fatalf("persisted session TTL = %d, want %d", v, tc.want)
			}
		})
	}
}
