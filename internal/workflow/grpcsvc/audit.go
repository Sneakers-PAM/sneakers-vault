// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strconv"

	log "github.com/Bugs5382/go-log"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
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

// auditRequestCreated records a new access or move request, by id: never its
// reason text.
func (s *Server) auditRequestCreated(ctx context.Context, r *workflowv1.ApprovalRequest) {
	attrs := map[string]string{"kind": r.GetKind().String()}
	for k, v := range map[string]string{"secret_id": r.GetSecretId(), "folder_id": r.GetFolderId(), "dest_parent_id": r.GetDestParentId()} {
		if v != "" {
			attrs[k] = v
		}
	}
	s.emit(ctx, r.GetRequestedByUserId(), "request.create", r.GetId(), attrs)
}

// auditResolved records an approval or a denial.
func (s *Server) auditResolved(ctx context.Context, by string, r *workflowv1.ApprovalRequest, approve bool, grantHours int32) {
	action := "request.deny"
	attrs := map[string]string{"kind": r.GetKind().String(), "requested_by": r.GetRequestedByUserId()}
	if r.GetSecretId() != "" {
		attrs["secret_id"] = r.GetSecretId()
	}
	if approve {
		action = "request.approve"
		if r.GetKind() == workflowv1.RequestKind_REQUEST_KIND_UNSPECIFIED {
			attrs["grant_hours"] = strconv.Itoa(clampGrantHours(grantHours))
		}
	}
	s.emit(ctx, by, action, r.GetId(), attrs)
}
