// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/config"
)

// ReasonStepUpRequired refuses an action that needs a fresher MFA.
const ReasonStepUpRequired = "STEP_UP_REQUIRED"

// SetMFAMaxAge sets how recent MFA must be (MFA_MAX_AGE); 0 means every
// sensitive action needs its own step-up.
func (s *Server) SetMFAMaxAge(d time.Duration) { s.mfaMaxAge, s.mfaMaxAgeSet = d, true }

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// mfaFresh reports whether a's MFA falls within the MFA_MAX_AGE window.
func (s *Server) mfaFresh(a *workflowv1.ActorContext) bool {
	window := config.DefaultMFAMaxAge
	if s.mfaMaxAgeSet {
		window = s.mfaMaxAge
	}
	return config.MFAFresh(a.GetMfaVerifiedAtUnix(), s.clock(), window)
}
