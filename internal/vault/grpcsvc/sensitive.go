// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// ReasonAPISensitiveDisabled refuses a machine principal a super-sensitive
// field while "allow API access to sensitive secrets" is off.
const ReasonAPISensitiveDisabled = "API_SENSITIVE_DISABLED"

// isSuperSensitiveField reports whether the type marks key super-sensitive.
func isSuperSensitiveField(t *vaultv1.SecretType, key string) bool {
	for _, f := range t.GetFields() {
		if f.GetKey() == key {
			return f.GetSuperSensitive()
		}
	}
	return false
}

// checkAPIForSensitive refuses a machine principal (service account or
// personal token) a super-sensitive field while allow_api_for_sensitive is
// off. Ordinary password and sensitive fields are unaffected. Caller holds
// s.mu.
func (s *Server) checkAPIForSensitive(ctx context.Context, actor *vaultv1.ActorContext, sec *vaultv1.Secret, fieldKey, action string) error {
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN ||
		!isSuperSensitiveField(s.findType(sec.GetTypeId()), fieldKey) ||
		settingsWithDefaults(s.settings).GetAllowApiForSensitive() {
		return nil
	}
	s.lg(ctx).Warn("super-sensitive field refused to a machine principal", log.F("secret_id", sec.GetId()),
		log.F("field_key", fieldKey), log.F("principal_kind", actor.GetPrincipalKind().String()))
	id := actor.GetUserId()
	if id == "" {
		id = actor.GetPrincipalId()
	}
	s.emitAttrs(ctx, id, "secret.reveal.denied", sec.GetId()+"#"+fieldKey, true, map[string]string{
		"reason": ReasonAPISensitiveDisabled, "action": action,
		"principal_kind": actor.GetPrincipalKind().String(), "token_id": actor.GetTokenId(),
	})
	return refuse(ReasonAPISensitiveDisabled,
		`"Allow API access to sensitive secrets" is off: tokens and service accounts can't reveal or use super-sensitive fields`)
}

// revealStepUpRequired resolves step-up for a reveal in sec's folder: the
// nearest folder that sets REQUIRE or OFF wins, else the global
// require_mfa_for_reveal. Caller holds s.mu.
func (s *Server) revealStepUpRequired(sec *vaultv1.Secret) bool {
	for _, f := range s.ancestorsInclusive(sec.GetFolderId()) {
		switch f.GetRevealStepUp() {
		case vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE:
			return true
		case vaultv1.StepUpMode_STEP_UP_MODE_OFF:
			return false
		}
	}
	return settingsWithDefaults(s.settings).GetRequireMfaForReveal()
}

// checkRevealStepUp refuses a person's reveal or copy without a fresh MFA
// when step-up applies to the secret. Machine principals are exempt (they
// have no MFA; allow_api_for_sensitive covers them). Caller holds s.mu.
func (s *Server) checkRevealStepUp(ctx context.Context, actor *vaultv1.ActorContext, sec *vaultv1.Secret, action string) error {
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || !s.revealStepUpRequired(sec) || s.mfaFresh(actor) {
		return nil
	}
	s.lg(ctx).Info("reveal needs step-up", log.F("secret_id", sec.GetId()), log.F("user_id", actor.GetUserId()), log.F("action", action))
	s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal.step_up_required", sec.GetId(), false, map[string]string{
		"reason": ReasonStepUpRequired, "action": action,
	})
	return refuse(ReasonStepUpRequired, "confirm your MFA again to reveal this secret")
}

// SetFolderRevealStepUp sets a folder's step-up-on-reveal override, inherited
// by its subfolders. Human site admin only.
func (s *Server) SetFolderRevealStepUp(ctx context.Context, req *vaultv1.SetFolderRevealStepUpRequest) (*vaultv1.SetFolderRevealStepUpResponse, error) {
	if err := s.requireSiteAdmin(ctx, req.GetActor(), "SetFolderRevealStepUp"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetFolderId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	f.RevealStepUp = req.GetMode()
	s.lg(ctx).Info("folder reveal step-up set", log.F("folder_id", f.GetId()), log.F("mode", req.GetMode().String()))
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "folder.reveal_step_up.set", f.GetId(), false, map[string]string{"mode": req.GetMode().String()})
	return &vaultv1.SetFolderRevealStepUpResponse{Folder: f}, nil
}
