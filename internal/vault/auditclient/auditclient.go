// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package auditclient adapts the vault's and the workflow's Auditor seams onto
// the audit service's gRPC contract. audit.Event is the vault-side domain type; the audit
// service speaks auditv1.RecordEventRequest.
package auditclient

import (
	"context"

	auditv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/thirdparty/audit/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
)

// Client records audit events through the audit service.
type Client struct{ c auditv1.AuditServiceClient }

// New returns an auditor backed by the audit service.
func New(c auditv1.AuditServiceClient) *Client { return &Client{c: c} }

// Emit records ev.
func (a *Client) Emit(ctx context.Context, ev audit.Event) error {
	_, err := a.c.RecordEvent(ctx, toRequest(ev))
	return err
}

func toRequest(ev audit.Event) *auditv1.RecordEventRequest {
	return &auditv1.RecordEventRequest{
		Tier:        toProtoTier(ev.Tier),
		Action:      ev.Action,
		ActorUserId: ev.ActorUserID,
		Subject:     ev.Subject,
		GroupId:     ev.GroupID,
		Sensitive:   ev.Sensitive,
		Attributes:  ev.Attributes,
	}
}

func toProtoTier(t audit.Tier) auditv1.Tier {
	switch t {
	case audit.TierAudit:
		return auditv1.Tier_TIER_AUDIT
	case audit.TierActivity:
		return auditv1.Tier_TIER_ACTIVITY
	default:
		return auditv1.Tier_TIER_UNSPECIFIED
	}
}
