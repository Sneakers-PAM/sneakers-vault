// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// Routine machine heartbeats flood the audit trail: every check wrote both a
// "heartbeat" (credential fetch) and a "heartbeat.report" record, even when
// nothing changed. #161 folds a run of same-day, same-result checks into one
// "heartbeat.summary" record, flushed at the first state change or when the
// day closes — while every person/agent action, every failure or refusal,
// and every state change still gets its own record, same as before.

func (fx *noTargetFixture) summaryEvents(action string) []string {
	var out []string
	fx.ca.mu.Lock()
	defer fx.ca.mu.Unlock()
	for _, ev := range fx.ca.events {
		if ev.Action == action {
			out = append(out, ev.Subject)
		}
	}
	return out
}

func TestHeartbeatAuditSummary_FoldsRoutineChecksUntilAFailure(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	if !claimsHB(t, fx.s, id) {
		t.Fatal("precondition: a new heartbeat secret is due")
	}
	for i := 0; i < 100; i++ {
		reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")
	}
	if got := fx.summaryEvents("heartbeat.report"); len(got) != 0 {
		t.Fatalf("100 routine checks emitted %d individual heartbeat.report records, want 0", len(got))
	}
	if got := fx.summaryEvents("heartbeat.summary"); len(got) != 0 {
		t.Fatalf("a rollup must not flush before a state change or a day close, got %v", got)
	}
	pending, open, err := fx.s.hbSummary.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !open || pending.Checks != 100 {
		t.Fatalf("pending rollup = %+v open=%v, want 100 checks", pending, open)
	}

	// A failure in between: flushes the 100-check rollup as one summary
	// record, and is itself audited as its own pause record.
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, "bind failed")
	summaries := fx.summaryEvents("heartbeat.summary")
	if len(summaries) != 1 {
		t.Fatalf("summaries after the failure = %v, want exactly 1", summaries)
	}
	if fx.ca.find("secret.heartbeat.pause") == nil {
		t.Fatal("the failure itself must still be audited on its own")
	}
	if _, open, err := fx.s.hbSummary.Get(context.Background(), id); err != nil || open {
		t.Fatalf("rollup must be cleared after flush: open=%v err=%v", open, err)
	}
}

func TestHeartbeatAuditSummary_RecoveryIsIndividualAndStartsAFreshRollup(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, "bind failed")

	// Recovery: the first OK after a failure is its own record, not folded.
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")
	if got := fx.summaryEvents("heartbeat.report"); len(got) == 0 {
		t.Fatal("the recovery check (failing -> ok) must be audited on its own")
	}

	// The next routine OK folds into a fresh rollup, not a new individual record.
	before := len(fx.summaryEvents("heartbeat.report"))
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")
	if got := len(fx.summaryEvents("heartbeat.report")); got != before {
		t.Fatalf("a routine check right after the recovery must fold, got %d individual records (was %d)", got, before)
	}
	pending, open, err := fx.s.hbSummary.Get(context.Background(), id)
	if err != nil || !open || pending.Checks != 2 {
		t.Fatalf("pending rollup = %+v open=%v err=%v, want 2 checks (the recovery check plus the one after it)", pending, open, err)
	}
}

func TestHeartbeatAuditSummary_DayCloseFlushesWithoutAnIndividualRecord(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")
	pending, open, err := fx.s.hbSummary.Get(context.Background(), id)
	if err != nil || !open || pending.Checks != 1 {
		t.Fatalf("precondition: one-check rollup open, got %+v open=%v err=%v", pending, open, err)
	}
	// Back-date the rollup to simulate yesterday's checks, without touching
	// the clock: the next check's day no longer matches the rollup's.
	if _, err := fx.s.hb.db.Exec(context.Background(),
		`UPDATE heartbeat_audit_summary SET day = day - 1 WHERE secret_id = $1`, id); err != nil {
		t.Fatal(err)
	}

	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")

	summaries := fx.summaryEvents("heartbeat.summary")
	if len(summaries) != 1 {
		t.Fatalf("the closed day must flush as one summary record, got %v", summaries)
	}
	if got := fx.summaryEvents("heartbeat.report"); len(got) != 0 {
		t.Fatalf("a plain day rollover (still ok) must not be audited on its own, got %v", got)
	}
	pending, open, err = fx.s.hbSummary.Get(context.Background(), id)
	if err != nil || !open || pending.Checks != 1 || !pending.Day.Equal(time.Now().UTC().Truncate(24*time.Hour)) {
		t.Fatalf("today's rollup = %+v open=%v err=%v, want today's 1 check", pending, open, err)
	}
}

func TestHeartbeatAuditSummary_HostKeyRefusalFlushesAndIsIndividual(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, "bind ok")
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED, "host offered SHA256:abc")
	if len(fx.summaryEvents("heartbeat.summary")) != 1 {
		t.Fatal("the open rollup must flush when a host-key refusal interrupts it")
	}
	if fx.ca.find("secret.heartbeat.host_key") == nil {
		t.Fatal("a host-key refusal must still get its own dedicated record")
	}
}

// A chain of entirely routine, never-folded heartbeat types keeps behaving:
// every person/agent action is unaffected by the rollup (existing coverage
// in heartbeat_pause_test.go / heartbeat_request_test.go stays green — this
// just pins that the rollup table itself is additive, not a replacement for
// those paths).
func TestHeartbeatAuditSummary_UnreachableIsNeverFolded(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE, "dial timeout")
	reportHB(t, fx.s, id, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE, "dial timeout")
	if got := len(fx.summaryEvents("heartbeat.report")); got != 2 {
		t.Fatalf("unreachable checks = %d individual records, want 2 (never folded)", got)
	}
	if _, open, err := fx.s.hbSummary.Get(context.Background(), id); err != nil || open {
		t.Fatalf("unreachable must never open a rollup: open=%v err=%v", open, err)
	}
}
