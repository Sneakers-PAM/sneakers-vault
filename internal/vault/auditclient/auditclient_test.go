// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package auditclient

import (
	"testing"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
)

func TestToProtoTier(t *testing.T) {
	if got := toProtoTier(audit.TierActivity); got != auditv1.Tier_TIER_ACTIVITY {
		t.Fatalf("activity: got %v", got)
	}
	if got := toProtoTier(audit.TierAudit); got != auditv1.Tier_TIER_AUDIT {
		t.Fatalf("audit: got %v", got)
	}
}

func TestToRequestMapsFields(t *testing.T) {
	req := toRequest(audit.Event{
		Tier: audit.TierActivity, Action: "secret.reveal",
		ActorUserID: "user-carol", Subject: "sec-1", Sensitive: true,
		GroupID:    "group-1",
		Attributes: map[string]string{"ip": "192.0.2.1"},
	})
	if req.GetAction() != "secret.reveal" || req.GetActorUserId() != "user-carol" ||
		req.GetSubject() != "sec-1" || !req.GetSensitive() ||
		req.GetTier() != auditv1.Tier_TIER_ACTIVITY ||
		req.GetGroupId() != "group-1" ||
		req.GetAttributes()["ip"] != "192.0.2.1" {
		t.Fatalf("bad mapping: %+v", req)
	}
}
