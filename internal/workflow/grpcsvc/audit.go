// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
)

// Auditor records workflow events in the audit service. Never put a secret
// value or a token in an event.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// SetAuditor installs the audit sink (cmd/workflow). Without one, events are
// only logged.
func (s *Server) SetAuditor(a Auditor) { s.audit = a }

// emit records an activity-tier event. Best-effort: a failed emit is logged,
// never returned, so the audit service being down doesn't block a workflow.
func (s *Server) emit(ctx context.Context, actor, action, subject string, attrs map[string]string) {
	s.lg(ctx).Info("workflow event", log.F("action", action), log.F("actor", actor), log.F("subject", subject))
	if s.audit == nil {
		return
	}
	if err := s.audit.Emit(ctx, audit.Event{Tier: audit.TierActivity, Action: action, ActorUserID: actor, Subject: subject, Attributes: attrs}); err != nil {
		s.lg(ctx).Error(err, "audit emit failed", log.F("action", action), log.F("subject", subject))
	}
}
