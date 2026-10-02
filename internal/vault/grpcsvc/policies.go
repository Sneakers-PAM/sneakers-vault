// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"strconv"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// env reads k from the environment, falling back to def when unset (or
// empty). Mirrors the identical helper in cmd/vault/main.go and
// cmd/seed/main.go, which live in package main and so can't be shared here.
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---- Password policies ------------------------------------------------------

// builtinDefaultPolicyID is the shipped "Default" password policy seeded at
// startup. It is hard-locked to always be non-deletable (though still
// editable), regardless of which policy is the current org default.
const builtinDefaultPolicyID = "pwpolicy-default"

// isBuiltinPolicy reports whether id is a shipped, always-non-deletable policy.
func isBuiltinPolicy(id string) bool { return id == builtinDefaultPolicyID }

// byTypeFields counts secret-type password fields referencing a policy.
func (s *Server) byTypeFields(policyID string) int32 {
	var n int32
	for _, t := range s.types {
		for _, f := range t.GetFields() {
			if f.GetPolicyId() == policyID {
				n++
			}
		}
	}
	return n
}

// withUsage clones a policy and fills its output-only usage fields.
func (s *Server) withUsage(p *vaultv1.PasswordPolicy) *vaultv1.PasswordPolicy {
	cp := proto.Clone(p).(*vaultv1.PasswordPolicy)
	cp.IsDefault = s.settings.GetDefaultPasswordPolicyId() == p.GetId()
	cp.ByTypeFields = s.byTypeFields(p.GetId())
	cp.Deletable = !isBuiltinPolicy(cp.Id) && !cp.IsDefault && cp.ByTypeFields == 0
	return cp
}

func (s *Server) ListPasswordPolicies(_ context.Context, _ *vaultv1.ListPasswordPoliciesRequest) (*vaultv1.ListPasswordPoliciesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*vaultv1.PasswordPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, s.withUsage(p))
	}
	return &vaultv1.ListPasswordPoliciesResponse{Policies: out}, nil
}

func (s *Server) SavePasswordPolicy(ctx context.Context, req *vaultv1.SavePasswordPolicyRequest) (*vaultv1.SavePasswordPolicyResponse, error) {
	in := req.GetPolicy()
	if in == nil || in.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.GetId() == "" {
		in.Id = s.nextID("pwpolicy")
		s.policies = append(s.policies, in)
	} else {
		existing := findByID(s.policies, in.GetId())
		if existing == nil {
			return nil, errNotFound("password policy")
		}
		// Replace mutable fields (usage fields are output-only, recomputed).
		existing.Name, existing.MinLength, existing.MaxLength = in.GetName(), in.GetMinLength(), in.MaxLength
		existing.RequireUpper, existing.RequireLower = in.GetRequireUpper(), in.GetRequireLower()
		existing.RequireDigit, existing.RequireSymbol = in.GetRequireDigit(), in.GetRequireSymbol()
		existing.RotationDays, existing.StartClass = in.RotationDays, in.GetStartClass()
		existing.EndLiteral, existing.ExcludeChars = in.GetEndLiteral(), in.GetExcludeChars()
		in = existing
	}
	s.emit(ctx, req.GetActor().GetUserId(), "policy.save", in.GetId(), false)
	return &vaultv1.SavePasswordPolicyResponse{Policy: s.withUsage(in)}, nil
}

func (s *Server) DeletePasswordPolicy(ctx context.Context, req *vaultv1.DeletePasswordPolicyRequest) (*vaultv1.DeletePasswordPolicyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := findByID(s.policies, req.GetId())
	if p == nil {
		return &vaultv1.DeletePasswordPolicyResponse{Removed: false}, nil
	}
	// Blocked for the shipped built-in policy, while it's the instance
	// default, or while referenced by a type field.
	if isBuiltinPolicy(req.GetId()) || s.settings.GetDefaultPasswordPolicyId() == req.GetId() || s.byTypeFields(req.GetId()) > 0 {
		return &vaultv1.DeletePasswordPolicyResponse{Removed: false}, nil
	}
	s.policies = removeByID(s.policies, req.GetId())
	s.emit(ctx, req.GetActor().GetUserId(), "policy.delete", req.GetId(), false)
	return &vaultv1.DeletePasswordPolicyResponse{Removed: true}, nil
}

// ---- Security settings ------------------------------------------------------

func (s *Server) GetSecuritySettings(_ context.Context, _ *vaultv1.GetSecuritySettingsRequest) (*vaultv1.GetSecuritySettingsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &vaultv1.GetSecuritySettingsResponse{Settings: settingsWithDefaults(s.settings)}, nil
}

// defaultRequestHistoryRetentionDays is applied when the stored value is 0
// (unset): resolved access requests are kept 90 days before the purge job.
const defaultRequestHistoryRetentionDays int32 = 90

// Session-timeout bounds for the gateway sliding-session TTL. The gateway reads
// SecuritySettings.session_ttl_seconds and applies it to session create and each
// sliding renewal. 0 (unset) resolves to the default; writes are clamped to the
// [min, max] range so the admin cannot store an out-of-policy value.
const (
	defaultSessionTTLSeconds int32 = 1800 // 30m
	minSessionTTLSeconds     int32 = 900  // 15m
	maxSessionTTLSeconds     int32 = 3600 // 60m
)

// clampSessionTTLSeconds constrains a session TTL to [min, max] seconds.
func clampSessionTTLSeconds(v int32) int32 {
	if v < minSessionTTLSeconds {
		return minSessionTTLSeconds
	}
	if v > maxSessionTTLSeconds {
		return maxSessionTTLSeconds
	}
	return v
}

// defaultKekRotationDays resolves the KEK auto-rotation interval seeded onto
// a FRESH instance's SecuritySettings.kek_rotation_days (see
// ensureSecuritySettings): KEK_ROTATION_DAYS if it parses as a valid
// non-negative integer, else 90. This default is a SEED-TIME value only — it
// is never applied to an existing instance's stored setting, where 0 means
// auto-rotation is off (not "unset"; see settingsWithDefaults).
func defaultKekRotationDays() int32 {
	v := env("KEK_ROTATION_DAYS", "")
	if v == "" {
		return 90
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 90
	}
	return safeconv.Int32(n)
}

// settingsWithDefaults returns a clone of the settings with derived defaults
// applied for read/response (0 request-history retention -> 90; 0 session TTL ->
// 1800s / 30m). kek_rotation_days is deliberately NOT defaulted here: 0 is a
// valid, persisted "auto-rotation off" — unlike the other two fields, it is
// never "unset" once ensureSecuritySettings has seeded the instance.
func settingsWithDefaults(in *vaultv1.SecuritySettings) *vaultv1.SecuritySettings {
	out := proto.Clone(in).(*vaultv1.SecuritySettings)
	if out.GetRequestHistoryRetentionDays() == 0 {
		out.RequestHistoryRetentionDays = defaultRequestHistoryRetentionDays
	}
	if out.GetSessionTtlSeconds() == 0 {
		out.SessionTtlSeconds = defaultSessionTTLSeconds
	}
	return out
}

// UpdateSecuritySettings applies only the fields present on the request.
func (s *Server) UpdateSecuritySettings(ctx context.Context, req *vaultv1.UpdateSecuritySettingsRequest) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.DefaultPasswordPolicyId != nil {
		s.settings.DefaultPasswordPolicyId = req.GetDefaultPasswordPolicyId()
	}
	if req.RequireMfaForSensitiveCheckout != nil {
		s.settings.RequireMfaForSensitiveCheckout = req.GetRequireMfaForSensitiveCheckout()
	}
	if req.AllowApiForSensitive != nil {
		s.settings.AllowApiForSensitive = req.GetAllowApiForSensitive()
	}
	if req.RequestHistoryRetentionDays != nil {
		s.settings.RequestHistoryRetentionDays = req.GetRequestHistoryRetentionDays()
	}
	if req.SessionTtlSeconds != nil {
		clamped := clampSessionTTLSeconds(req.GetSessionTtlSeconds())
		if clamped != req.GetSessionTtlSeconds() {
			l := log.Ctx(ctx)
			l.Info().
				Int32("requested", req.GetSessionTtlSeconds()).
				Int32("clamped", clamped).
				Msg("session TTL clamped to policy bounds")
		}
		s.settings.SessionTtlSeconds = clamped
	}
	if req.KekRotationDays != nil {
		days := req.GetKekRotationDays()
		if days < 0 {
			days = 0
		}
		s.settings.KekRotationDays = days
	}
	s.emit(ctx, req.GetActor().GetUserId(), "settings.update", "security", false)
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: settingsWithDefaults(s.settings)}, nil
}
