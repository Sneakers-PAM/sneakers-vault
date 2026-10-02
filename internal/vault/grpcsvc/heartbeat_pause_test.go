// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// A FAILED heartbeat is a bind with a wrong password. Retrying it every
// interval can lock the account out, so the schedule pauses until someone
// changes the stored credential or asks for a check.

func reportHB(t *testing.T, s *Server, id string, result vaultv1.HeartbeatResult, detail string) {
	t.Helper()
	if _, err := s.ReportHeartbeat(context.Background(), &vaultv1.ReportHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: id, Result: result, Detail: detail,
	}); err != nil {
		t.Fatalf("ReportHeartbeat(%v): %v", result, err)
	}
}

func hbPausedRow(t *testing.T, s *Server, id string) bool {
	t.Helper()
	var paused bool
	if err := s.hb.db.QueryRow(context.Background(),
		`SELECT next_heartbeat_at = 'infinity' FROM heartbeat_schedule WHERE secret_id = $1`, id).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	return paused
}

func claimsHB(t *testing.T, s *Server, id string) bool {
	t.Helper()
	resp, err := s.ClaimDueHeartbeats(context.Background(), &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
	if err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	for _, j := range resp.GetJobs() {
		if j.GetSecretId() == id {
			return true
		}
	}
	return false
}

func hbDetail(s *Server, id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findSecret(id).GetLastHeartbeatDetail()
}

// pausedFixture is a reachable heartbeat secret whose last check FAILED.
func pausedFixture(t *testing.T) (*noTargetFixture, string) {
	t.Helper()
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	if !claimsHB(t, fx.s, id) {
		t.Fatal("precondition: a new heartbeat secret is due")
	}
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, "LDAP bind: invalid credentials")
	return fx, id
}

func TestReportHeartbeat_FailedPausesTheSchedule(t *testing.T) {
	fx, id := pausedFixture(t)
	if !hbPausedRow(t, fx.s, id) {
		t.Fatal("a FAILED heartbeat must pause the schedule, not reschedule it")
	}
	if _, err := fx.s.hb.db.Exec(context.Background(), `UPDATE heartbeat_schedule SET claimed_until = NULL`); err != nil {
		t.Fatal(err)
	}
	if claimsHB(t, fx.s, id) {
		t.Fatal("a paused heartbeat must never be claimed automatically")
	}
	d := hbDetail(fx.s, id)
	if !strings.HasPrefix(d, "LDAP bind: invalid credentials") || !strings.Contains(d, "paused") {
		t.Fatalf("detail = %q, want the connector's reason plus the pause", d)
	}
	ev := fx.ca.find("secret.heartbeat.pause")
	if ev == nil || ev.Subject != id || ev.Sensitive {
		t.Fatalf("pause audit = %+v", ev)
	}
}

func TestReportHeartbeat_FailedPauseShowsInPrincipalStatus(t *testing.T) {
	fx, id := pausedFixture(t)
	st, err := fx.s.GetHeartbeatStatusForPrincipal(context.Background(), &vaultv1.GetHeartbeatStatusForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED || st.GetPending() || !strings.Contains(st.GetDetail(), "paused") {
		t.Fatalf("status = result %v pending %v detail %q", st.GetResult(), st.GetPending(), st.GetDetail())
	}
}

func TestReportHeartbeat_FailedPauseDetailFitsTheLimit(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, strings.Repeat("x", 2000))
	if d := hbDetail(fx.s, id); len(d) > maxHeartbeatDetail || !strings.Contains(d, "paused") {
		t.Fatalf("detail is %d bytes, paused=%v; want at most %d with the pause kept", len(d), strings.Contains(d, "paused"), maxHeartbeatDetail)
	}
}

func TestReportHeartbeat_UnreachableKeepsBackoff(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE, "dial timeout")
	var finite bool
	if err := fx.s.hb.db.QueryRow(context.Background(),
		`SELECT next_heartbeat_at > now() AND next_heartbeat_at < now() + interval '5 minutes' FROM heartbeat_schedule WHERE secret_id = $1`, id,
	).Scan(&finite); err != nil {
		t.Fatal(err)
	}
	if !finite {
		t.Fatal("UNREACHABLE must keep its short backoff, not pause")
	}
	if fx.ca.find("secret.heartbeat.pause") != nil {
		t.Fatal("UNREACHABLE must not be audited as a pause")
	}
}

// A machine principal can only edit notes/description on a heartbeat type,
// which never fixes the credential, so only the human edit and rotation paths
// change the value.
func TestHeartbeatPause_ResumesWhenTheValueChanges(t *testing.T) {
	cases := map[string]func(t *testing.T, fx *noTargetFixture, id string) string{
		"UpdateSecret": func(t *testing.T, fx *noTargetFixture, id string) string {
			if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
				Actor: orgCarol, Id: id, TargetId: fx.target, Fields: map[string]string{"password": "N3w-Pa55word!value"},
			}); err != nil {
				t.Fatalf("UpdateSecret: %v", err)
			}
			return orgCarol.GetUserId()
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fx, id := pausedFixture(t)
			actor := change(t, fx, id)
			if hbPausedRow(t, fx.s, id) || !claimsHB(t, fx.s, id) {
				t.Fatal("a value change must resume the heartbeat and make it due")
			}
			if d := hbDetail(fx.s, id); strings.Contains(d, "paused") {
				t.Fatalf("detail after resume = %q, want the pause cleared", d)
			}
			ev := fx.ca.find("secret.heartbeat.resume")
			if ev == nil || ev.Subject != id || ev.ActorUserID != actor || ev.Sensitive {
				t.Fatalf("resume audit = %+v", ev)
			}
			if ev.Attributes["reason"] != "credential_updated" {
				t.Fatalf("resume reason = %q", ev.Attributes["reason"])
			}
		})
	}
}

func TestHeartbeatPause_StaysPausedWithoutAValueChange(t *testing.T) {
	fx, id := pausedFixture(t)
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Name: "svc-renamed", TargetId: fx.target,
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if !hbPausedRow(t, fx.s, id) {
		t.Fatal("an edit that leaves the credential unchanged must not resume the heartbeat")
	}
	if fx.ca.find("secret.heartbeat.resume") != nil {
		t.Fatal("no resume may be audited without a value change")
	}
}

func TestHeartbeatPause_ResumesOnManualRequest(t *testing.T) {
	fx, id := pausedFixture(t)
	actor := agentGroupActor("sa-1")
	if err := requestHB(fx.s, actor, id); err != nil {
		t.Fatalf("request: %v", err)
	}
	if hbPausedRow(t, fx.s, id) || !claimsHB(t, fx.s, id) {
		t.Fatal("a manual request must resume the heartbeat and make it due")
	}
	if d := hbDetail(fx.s, id); strings.Contains(d, "paused") {
		t.Fatalf("detail after resume = %q, want the pause cleared", d)
	}
	ev := fx.ca.find("secret.heartbeat.resume")
	if ev == nil || ev.ActorUserID != principalActorID(actor) || ev.Attributes["reason"] != "check_requested" {
		t.Fatalf("resume audit = %+v", ev)
	}
}

func TestHeartbeatPause_RateLimitedRequestStaysPaused(t *testing.T) {
	fx, id := pausedFixture(t)
	if _, err := fx.s.hb.db.Exec(context.Background(), `UPDATE heartbeat_schedule SET last_manual_at = now()`); err != nil {
		t.Fatal(err)
	}
	if err := requestHB(fx.s, agentGroupActor("sa-1"), id); err == nil {
		t.Fatal("a request within the minute must be rate-limited")
	}
	if !hbPausedRow(t, fx.s, id) {
		t.Fatal("a rate-limited request must not resume the heartbeat")
	}
}

func TestHeartbeatPause_ResumesAfterRotation(t *testing.T) {
	s, ca, id := newHeartbeatTestServer(t)
	ctx := context.Background()
	if _, err := s.hb.db.Exec(ctx, `UPDATE heartbeat_schedule SET next_heartbeat_at = now()`); err != nil {
		t.Fatal(err)
	}
	if !claimsHB(t, s, id) {
		t.Fatal("precondition: the heartbeat is due")
	}
	reportHB(t, s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, "LDAP bind: invalid credentials")
	revealNew(t, s, id)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: id,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	if hbPausedRow(t, s, id) {
		t.Fatal("a committed rotation stores a new credential, so it must resume the heartbeat")
	}
	if ev := ca.find("secret.heartbeat.resume"); ev == nil || ev.Attributes["reason"] != "credential_rotated" {
		t.Fatalf("resume audit = %+v", ev)
	}
}
