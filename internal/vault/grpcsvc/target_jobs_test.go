// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// attachSecondTarget attaches a second usable target (its own connection) to
// secID, returning its id, for a #168 multi-target scenario.
func attachSecondTarget(t *testing.T, s *Server, secID, name, hostname string) string {
	t.Helper()
	ctx := context.Background()
	tgtID := saveTestTarget(t, s, name, hostname)
	if _, err := s.AttachSecretTarget(ctx, &vaultv1.AttachSecretTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-carol"}, SecretId: secID, TargetId: tgtID,
	}); err != nil {
		t.Fatalf("AttachSecretTarget: %v", err)
	}
	return tgtID
}

// TestClaimDueRotations_JobCarriesEveryAttachedTarget proves a multi-target
// secret's RotationJob lists every attached target (#168), primary first,
// not just the one connTargetFor still exposes for a legacy connector.
func TestClaimDueRotations_JobCarriesEveryAttachedTarget(t *testing.T) {
	s, _, secID := newRotationServer(t)
	primary := s.findSecret(secID).GetTargetId()
	second := attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, Limit: 10})
	if err != nil {
		t.Fatalf("ClaimDueRotations: %v", err)
	}
	if len(resp.GetJobs()) != 1 {
		t.Fatalf("want 1 job, got %d", len(resp.GetJobs()))
	}
	job := resp.GetJobs()[0]
	if got := job.GetTargets(); len(got) != 2 || got[0].GetTargetId() != primary || got[1].GetTargetId() != second {
		t.Fatalf("want targets [%s, %s], got %+v", primary, second, got)
	}
	// The legacy singular fields still carry the PRIMARY target, for a
	// connector that hasn't moved to the targets list.
	if job.GetTarget().GetHostname() != "dc1.example.org" {
		t.Fatalf("legacy target field = %q, want the primary target's hostname", job.GetTarget().GetHostname())
	}
}

// TestReportRotation_PartialTargetFailureIsDegradedNotOK is #168's "partial
// rotation failure" Done-when line: a secret attached to two targets rotates
// (the new value is committed — it's already live on at least one target and
// is never rolled back), but the connector's target_results shows one
// target still failing, so the result is DEGRADED, never OK, and the
// per-target breakdown is kept for the secret's own page.
func TestReportRotation_PartialTargetFailureIsDegradedNotOK(t *testing.T) {
	s, _, secID := newRotationServer(t)
	primary := s.findSecret(secID).GetTargetId()
	second := attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()
	np, v := revealNewVer(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
		Version: v,
		TargetResults: []*vaultv1.TargetOutcome{
			{TargetId: primary, Ok: true},
			{TargetId: second, Ok: false, Detail: "connection refused"},
		},
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}

	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_DEGRADED {
		t.Fatalf("LastRotationResult = %v, want DEGRADED (one target still failing)", sec.GetLastRotationResult())
	}
	outcomes := sec.GetTargetRotationOutcomes()
	if len(outcomes) != 2 {
		t.Fatalf("want 2 target outcomes, got %d: %+v", len(outcomes), outcomes)
	}
	byTarget := map[string]bool{outcomes[0].GetTargetId(): outcomes[0].GetOk(), outcomes[1].GetTargetId(): outcomes[1].GetOk()}
	if !byTarget[primary] || byTarget[second] {
		t.Fatalf("want primary ok, second failed, got %+v", byTarget)
	}
	// The committed value is live on at least the primary target and is
	// never rolled back just because another target hasn't caught up yet.
	if got := activePassword(t, s, secID); got != np {
		t.Fatalf("active password = %q, want the new value %q (never rolled back)", got, np)
	}
}

// TestReportRotation_AllTargetsOKStaysOK proves the aggregation only
// downgrades on an actual failure: every target ok keeps the result OK.
func TestReportRotation_AllTargetsOKStaysOK(t *testing.T) {
	s, _, secID := newRotationServer(t)
	primary := s.findSecret(secID).GetTargetId()
	second := attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()
	_, v := revealNewVer(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
		Version: v,
		TargetResults: []*vaultv1.TargetOutcome{
			{TargetId: primary, Ok: true},
			{TargetId: second, Ok: true},
		},
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("LastRotationResult = %v, want OK (every target succeeded)", sec.GetLastRotationResult())
	}
	if len(sec.GetTargetRotationOutcomes()) != 2 {
		t.Fatalf("want 2 target outcomes recorded even when all ok, got %d", len(sec.GetTargetRotationOutcomes()))
	}
}

// TestReportRotation_NoTargetResultsUnchangedBehavior proves a connector
// that hasn't moved to multi-target reporting (target_results empty) keeps
// the exact single-target behavior: change/validate alone decide the
// result, never downgraded.
func TestReportRotation_NoTargetResultsUnchangedBehavior(t *testing.T) {
	s, _, secID := newRotationServer(t)
	attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()
	_, v := revealNewVer(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
		Version: v,
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("LastRotationResult = %v, want OK (legacy connector, no target_results)", sec.GetLastRotationResult())
	}
	if len(sec.GetTargetRotationOutcomes()) != 0 {
		t.Fatalf("want no per-target outcomes recorded without target_results, got %+v", sec.GetTargetRotationOutcomes())
	}
}

// TestClaimDueHeartbeats_JobCarriesEveryAttachedTarget mirrors the rotation
// job test for heartbeat.
func TestClaimDueHeartbeats_JobCarriesEveryAttachedTarget(t *testing.T) {
	s, _, secID := newHeartbeatTestServer(t)
	primary := s.findSecret(secID).GetTargetId()
	second := attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()
	if err := s.hb.Reschedule(ctx, secID, s.clock()); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, Limit: 10})
	if err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	if len(resp.GetJobs()) != 1 {
		t.Fatalf("want 1 job, got %d", len(resp.GetJobs()))
	}
	job := resp.GetJobs()[0]
	if got := job.GetTargets(); len(got) != 2 || got[0].GetTargetId() != primary || got[1].GetTargetId() != second {
		t.Fatalf("want targets [%s, %s], got %+v", primary, second, got)
	}
}

// TestReportHeartbeat_PartialTargetFailureIsFailedNotOK mirrors the rotation
// partial-failure test for heartbeat: an overall OK is downgraded to FAILED
// when target_results shows one target not confirmed working, and the
// per-target breakdown is kept.
func TestReportHeartbeat_PartialTargetFailureIsFailedNotOK(t *testing.T) {
	s, _, secID := newHeartbeatTestServer(t)
	primary := s.findSecret(secID).GetTargetId()
	second := attachSecondTarget(t, s, secID, "dc2", "dc2.example.org")
	ctx := context.Background()

	if _, err := s.ReportHeartbeat(ctx, &vaultv1.ReportHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK,
		TargetResults: []*vaultv1.TargetOutcome{
			{TargetId: primary, Ok: true},
			{TargetId: second, Ok: false, Detail: "bind refused"},
		},
	}); err != nil {
		t.Fatalf("ReportHeartbeat: %v", err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastHeartbeatResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED {
		t.Fatalf("LastHeartbeatResult = %v, want FAILED (one target still failing)", sec.GetLastHeartbeatResult())
	}
	if len(sec.GetTargetHeartbeatOutcomes()) != 2 {
		t.Fatalf("want 2 target outcomes, got %d", len(sec.GetTargetHeartbeatOutcomes()))
	}
}
