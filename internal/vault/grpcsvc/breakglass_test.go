// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc/codes"
)

// failAudit always fails Emit, simulating an unreachable/down audit sink so
// break-glass's fail-closed guarantee can be exercised.
type failAudit struct{}

func (failAudit) Emit(context.Context, audit.Event) error { return errors.New("audit sink down") }

// breakGlassEventsDDL mirrors migrations/0006_break_glass.up.sql (idempotent),
// applied here directly because that migration only runs on vault boot.
const breakGlassEventsDDL = `
CREATE TABLE IF NOT EXISTS break_glass_events (
  id                      TEXT        PRIMARY KEY,
  secret_id               TEXT        NOT NULL,
  actor_user_id           TEXT        NOT NULL,
  reason                  TEXT        NOT NULL DEFAULT '',
  occurred_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  post_rotation_scheduled BOOLEAN     NOT NULL DEFAULT false,
  notified                BOOLEAN     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS break_glass_events_secret ON break_glass_events (secret_id);
`

// newBreakGlassServer extends newRotationServer with a break-glass ledger store
// and a capturing notifier. The returned secret is a rotation-capable Windows
// domain account in a SHARED folder owned (RACI) by user-carol.
func newBreakGlassServer(t *testing.T) (*Server, *capAudit, *recNotifier, string) {
	t.Helper()
	s, ca, secID := newRotationServer(t)
	if _, err := s.rot.db.Exec(context.Background(), breakGlassEventsDDL); err != nil {
		t.Fatalf("bootstrap break_glass_events: %v", err)
	}
	if _, err := s.rot.db.Exec(context.Background(), "TRUNCATE break_glass_events"); err != nil {
		t.Fatal(err)
	}
	s.bg = newBreakGlassStore(s.rot.db)
	rn := &recNotifier{}
	s.SetNotifier(rn)
	return s, ca, rn, secID
}

func breakGlassRowCount(t *testing.T, s *Server, secID string) int {
	t.Helper()
	var n int
	if err := s.bg.db.QueryRow(context.Background(),
		`SELECT count(*) FROM break_glass_events WHERE secret_id=$1`, secID).Scan(&n); err != nil {
		t.Fatalf("count break_glass_events: %v", err)
	}
	return n
}

func TestBreakGlassRevealsRecordsAuditsAndRotates(t *testing.T) {
	s, ca, _, secID := newBreakGlassServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"} // RACI owner → read-eligible

	resp, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: carol, SecretId: secID, Reason: "prod outage, DBA locked out",
	})
	if err != nil {
		t.Fatalf("BreakGlassSecret: %v", err)
	}

	// Fields revealed (all of them, incl. the sensitive password).
	if got := resp.GetFields()["password"]; got != "OldP@ss1" {
		t.Fatalf("password field = %q, want OldP@ss1", got)
	}
	if resp.GetFields()["username"] != "svc-rotate" {
		t.Fatalf("username field = %q", resp.GetFields()["username"])
	}

	// Ledger row present.
	if n := breakGlassRowCount(t, s, secID); n != 1 {
		t.Fatalf("break_glass_events rows = %d, want 1", n)
	}
	// The shared-folder secret has no owner_user_id → not notified; rotation-capable
	// → post-rotation scheduled.
	var postRot, notified bool
	if err := s.bg.db.QueryRow(ctx,
		`SELECT post_rotation_scheduled, notified FROM break_glass_events WHERE secret_id=$1`, secID).
		Scan(&postRot, &notified); err != nil {
		t.Fatal(err)
	}
	if !postRot {
		t.Fatal("post_rotation_scheduled should be true for a rotation-capable secret")
	}
	if notified {
		t.Fatal("shared-folder secret has no owner → notified should be false")
	}

	// Forced rotation enqueued (reason=break-glass) and due now.
	due, _ := s.rot.ClaimDue(ctx, 10, rotClaimTTL)
	if len(due) != 1 || due[0] != secID {
		t.Fatalf("expected secret due for rotation, got %v", due)
	}

	// HIGH-severity audit: tamper-evident tier, sensitive, reason attr, NO values.
	ev := ca.find("break_glass")
	if ev == nil {
		t.Fatal("no break_glass audit event emitted")
	}
	if ev.Tier != audit.TierAudit {
		t.Fatalf("break_glass tier = %q, want %q (high severity)", ev.Tier, audit.TierAudit)
	}
	if !ev.Sensitive {
		t.Fatal("break_glass audit must be marked sensitive")
	}
	if ev.ActorUserID != "user-carol" || ev.Subject != secID {
		t.Fatalf("audit actor/subject = %q/%q", ev.ActorUserID, ev.Subject)
	}
	if ev.Attributes["reason"] != "prod outage, DBA locked out" {
		t.Fatalf("audit reason attr = %q", ev.Attributes["reason"])
	}
	for k, v := range ev.Attributes {
		if v == "OldP@ss1" {
			t.Fatalf("audit attr %q leaked the password value", k)
		}
	}
}

// TestBreakGlassAuditFailClosedDeniesReveal guards the fail-closed audit:
// the break_glass audit is the compensating control for this deliberate policy
// bypass, so if it can't be recorded (audit sink down), the secret must NOT be
// disclosed — no fields, Internal error, and neither the ledger nor rotation
// nor notify should have run.
func TestBreakGlassAuditFailClosedDeniesReveal(t *testing.T) {
	s, _, rn, secID := newBreakGlassServer(t)
	ctx := context.Background()
	s.audit = failAudit{}
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	resp, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: carol, SecretId: secID, Reason: "prod outage, DBA locked out",
	})
	if code(err) != codes.Internal {
		t.Fatalf("want Internal on audit failure, got resp=%v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatal("no fields must be revealed when the break-glass audit can't be recorded")
	}
	if n := breakGlassRowCount(t, s, secID); n != 0 {
		t.Fatalf("audit-fail-closed break-glass wrote %d ledger rows, want 0", n)
	}
	if rn.last != nil {
		t.Fatal("audit-fail-closed break-glass must not notify the owner")
	}
	due, _ := s.rot.ClaimDue(ctx, 10, rotClaimTTL)
	if len(due) != 0 {
		t.Fatalf("audit-fail-closed break-glass must not enqueue rotation, got %v", due)
	}
}

// TestBreakGlassLedgerAndRotationBestEffort covers the best-effort side:
// once the audit is recorded, a downstream DB outage (rotation
// enqueue / ledger insert both live on the same pool here) must NOT deny the
// already-authorized emergency reveal — the fields are still returned.
func TestBreakGlassLedgerAndRotationBestEffort(t *testing.T) {
	s, ca, _, secID := newBreakGlassServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	s.rot.db.Close() // also bg.db: same pool (see newBreakGlassServer)

	resp, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: carol, SecretId: secID, Reason: "prod outage, pool down",
	})
	if err != nil {
		t.Fatalf("BreakGlassSecret must succeed despite ledger/rotation outage: %v", err)
	}
	if resp.GetFields()["password"] != "OldP@ss1" {
		t.Fatalf("password field = %q, want OldP@ss1 (best-effort failures must not deny reveal)", resp.GetFields()["password"])
	}
	if ev := ca.find("break_glass"); ev == nil {
		t.Fatal("break_glass audit must still be recorded even when the ledger/rotation DB is down")
	}
}

func TestBreakGlassDeniedForNonReadActor(t *testing.T) {
	s, ca, _, secID := newBreakGlassServer(t)
	ctx := context.Background()
	stranger := &vaultv1.ActorContext{UserId: "user-nobody"}

	resp, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: stranger, SecretId: secID, Reason: "curious",
	})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got resp=%v err=%v", resp, err)
	}
	if resp != nil {
		t.Fatal("no fields must be revealed on denial")
	}
	// No ledger row, no audit event.
	if n := breakGlassRowCount(t, s, secID); n != 0 {
		t.Fatalf("denied break-glass wrote %d ledger rows, want 0", n)
	}
	if ev := ca.find("break_glass"); ev != nil {
		t.Fatal("denied break-glass must not emit a break_glass audit")
	}
}

func TestBreakGlassSiteAdminIntoPersonalFolderAllowedAndNotifiesOwner(t *testing.T) {
	s, _, rn, _ := newBreakGlassServer(t)
	ctx := context.Background()
	seedPersonalFolder(s, "user-turing")

	// Turing creates a secret in their OWN personal folder (owner auto-author).
	turing := &vaultv1.ActorContext{UserId: "user-turing"}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: turing, Name: "turing-laptop", FolderId: "folder-personal-turing", TypeId: "type-password",
		Fields: map[string]string{"username": "alan", "password": "Enigma#42", "notes": ""},
	})
	if err != nil {
		t.Fatalf("CreateSecret (personal): %v", err)
	}
	secID := created.GetSecret().GetId()

	// A site-admin (not the owner) breaks glass into the personal folder → allowed
	// (auto-read-all), and the owner (user-turing) is notified.
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	resp, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: admin, SecretId: secID, Reason: "offboarding audit",
	})
	if err != nil {
		t.Fatalf("BreakGlassSecret (site-admin): %v", err)
	}
	if resp.GetFields()["password"] != "Enigma#42" {
		t.Fatalf("password field = %q, want Enigma#42", resp.GetFields()["password"])
	}

	// Owner notified.
	if rn.last == nil {
		t.Fatal("owner notification not fired")
	}
	if len(rn.last.Subjects) != 1 || rn.last.Subjects[0].Name != "user-turing" {
		t.Fatalf("notify subjects = %+v, want [user-turing]", rn.last.Subjects)
	}
	// Ledger records notified=true; type-password is not rotation-capable so no
	// post rotation was scheduled.
	var postRot, notified bool
	if err := s.bg.db.QueryRow(ctx,
		`SELECT post_rotation_scheduled, notified FROM break_glass_events WHERE secret_id=$1`, secID).
		Scan(&postRot, &notified); err != nil {
		t.Fatal(err)
	}
	if !notified {
		t.Fatal("personal-folder owner present → notified should be true")
	}
	if postRot {
		t.Fatal("non-rotation-capable secret → post_rotation_scheduled should be false")
	}
}

func TestBreakGlassRetiredRejected(t *testing.T) {
	s, _, _, secID := newBreakGlassServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: secID}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	if _, err := s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: carol, SecretId: secID, Reason: "too late",
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("break-glass on retired: want FailedPrecondition, got %v", err)
	}
}
