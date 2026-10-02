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

// mfaClockSkew tolerates an MFA time slightly ahead of the workflow's clock.
const mfaClockSkew = 30 * time.Second

// SetMFAMaxAge sets how recent MFA must be (MFA_MAX_AGE); <= 0 keeps the
// default.
func (s *Server) SetMFAMaxAge(d time.Duration) { s.mfaMaxAge = d }

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// mfaFresh reports whether a's MFA falls within the MFA_MAX_AGE window.
func (s *Server) mfaFresh(a *workflowv1.ActorContext) bool {
	at := a.GetMfaVerifiedAtUnix()
	if at <= 0 {
		return false
	}
	window := s.mfaMaxAge
	if window <= 0 {
		window = config.DefaultMFAMaxAge
	}
	age := s.clock().Sub(time.Unix(at, 0))
	return age >= -mfaClockSkew && age <= window
}
