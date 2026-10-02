// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
)

// capAudit captures emitted audit events for assertion.
type capAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *capAudit) Emit(_ context.Context, ev audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *capAudit) find(action string) *audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.events {
		if c.events[i].Action == action {
			return &c.events[i]
		}
	}
	return nil
}

// newRotationServer builds a mem-backed Server (random KEK) with pool-backed
// rotation + version stores, an accepting worker verifier, a capturing auditor,
// and a rotation-capable (Windows domain) secret pointed at an LDAPS target.
func newRotationServer(t *testing.T) (*Server, *capAudit, string) {
	t.Helper()
	ctx := context.Background()
	pool := rotTestPool(t)
	if _, err := pool.Querier().Exec(ctx, secretVersionsDDL); err != nil {
		t.Fatalf("bootstrap secret_versions: %v", err)
	}
	if _, err := pool.Querier().Exec(ctx, "TRUNCATE secret_versions"); err != nil {
		t.Fatal(err)
	}

	ca := &capAudit{}
	s := newServer(t)
	s.audit = ca
	s.vers = newVersionStore(pool)
	s.rot = newRotationStore(pool.Querier())
	s.wid = acceptVerifier{principal: workloadid.Principal{WorkerID: "worker-1"}}

	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	conn, err := s.SaveConnection(ctx, &vaultv1.SaveConnectionRequest{
		Actor: siteAdmin, Connection: &vaultv1.Connection{Name: "AD LDAPS", Protocol: "ldap", Port: 636, UseTls: true},
	})
	if err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	tgt, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
		Actor: carol, Target: &vaultv1.Target{
			Name: "dc1", Hostname: "dc1.example.org", ConnectionId: conn.GetConnection().GetId(),
			Kind: "windows", Domain: "EXAMPLE", Realm: "EXAMPLE.ORG",
		},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc-rotate", FolderId: fid, TypeId: "type-windows-domain",
		TargetId: tgt.GetTarget().GetId(),
		Fields:   map[string]string{"domain": "SNEAKERS", "username": "svc-rotate", "password": "OldP@ss1"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	return s, ca, created.GetSecret().GetId()
}

func activePassword(t *testing.T, s *Server, secID string) string {
	t.Helper()
	rec, ok, err := s.vers.ActiveRecord(context.Background(), secID)
	if err != nil || !ok {
		t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
	}
	pw, err := s.crypt.Open(rec, "password")
	if err != nil {
		t.Fatalf("open active password: %v", err)
	}
	return pw
}

func TestEnqueueRotationSchedulesAndRejectsRetired(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatalf("EnqueueRotation: %v", err)
	}
	if ok, _ := s.rot.Exists(ctx, secID); !ok {
		t.Fatal("expected a schedule row after enqueue")
	}
	due, _ := s.rot.ClaimDue(ctx, 10, rotClaimTTL)
	if len(due) != 1 || due[0] != secID {
		t.Fatalf("expected secret due, got %v", due)
	}

	// Retired secret → FailedPrecondition.
	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: secID}); err != nil {
		t.Fatalf("RetireSecret: %v", err)
	}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); code(err) != codes.FailedPrecondition {
		t.Fatalf("EnqueueRotation on retired: want FailedPrecondition, got %v", err)
	}
}

func TestEnqueueRotationDeniedForNonManager(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	stranger := &vaultv1.ActorContext{UserId: "user-nobody"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: stranger, SecretId: secID, Reason: "manual"}); code(err) != codes.PermissionDenied {
		t.Fatalf("EnqueueRotation by non-manager: want PermissionDenied, got %v", err)
	}
	// The secret was auto-scheduled on creation (rotation-capable, policy has an
	// interval — see CreateSecret) — but a denied enqueue must not pull it
	// forward to due now.
	if due, _ := s.rot.ClaimDue(ctx, 10, rotClaimTTL); len(due) != 0 {
		t.Fatalf("denied enqueue should not make the secret due: %v", due)
	}
}

// TestEnqueueRotationAllowedForRoot proves system-triggered/admin rotations
// aren't wrongly denied: the authz package only auto-grants root/site-admin Read
// (never Author), so without an explicit allowance here a root actor with no
// folder rights would be denied. Root/site-admin must bypass canManage for
// EnqueueRotation specifically (rotation is triggered by system callers, not
// just folder authors).
func TestEnqueueRotationAllowedForRoot(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	root := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: root, SecretId: secID, Reason: "system"}); err != nil {
		t.Fatalf("EnqueueRotation as root: %v", err)
	}
	if ok, _ := s.rot.Exists(ctx, secID); !ok {
		t.Fatal("expected a schedule row after root enqueue")
	}
}

// TestEnqueueRotationAllowedForSiteAdmin mirrors the root case for site-admin.
func TestEnqueueRotationAllowedForSiteAdmin(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: admin, SecretId: secID, Reason: "system"}); err != nil {
		t.Fatalf("EnqueueRotation as site-admin: %v", err)
	}
	if ok, _ := s.rot.Exists(ctx, secID); !ok {
		t.Fatal("expected a schedule row after site-admin enqueue")
	}
}

// TestCreateSecretSchedulesRotationWhenPolicyHasInterval proves that a
// rotation-capable secret gets a rotation_schedule row at creation time when
// its policy carries a rotation interval, so scheduled (system-triggered)
// rotation works from the moment a secret exists — not only after a manual
// EnqueueRotation. The seeded "pwpolicy-privileged" policy (RotationDays=30)
// is bound to the test type's password field.
func TestCreateSecretSchedulesRotationWhenPolicyHasInterval(t *testing.T) {
	ctx := context.Background()
	pool := rotTestPool(t)
	s := newServer(t)
	s.rot = newRotationStore(pool.Querier())
	carol := &vaultv1.ActorContext{UserId: "user-carol"}

	typ, err := s.CreateSecretType(ctx, &vaultv1.CreateSecretTypeRequest{
		Actor: carol, Type: &vaultv1.SecretType{
			Name: "Rotatable Test Type", Heartbeat: true, Rotation: true,
			Fields: []*vaultv1.SecretFieldDef{
				{Key: "username", Label: "Username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
				{Key: "password", Label: "Password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Required: true, Sensitive: true, Rotates: true, PolicyId: "pwpolicy-privileged"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateSecretType: %v", err)
	}

	fid := newSharedFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "svc-scheduled", FolderId: fid, TypeId: typ.GetType().GetId(), TargetId: tgt,
		Fields: map[string]string{"username": "svc", "password": "Init1alP@ss"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secID := created.GetSecret().GetId()

	ok, err := s.rot.Exists(ctx, secID)
	if err != nil || !ok {
		t.Fatalf("expected a rotation_schedule row after create: ok=%v err=%v", ok, err)
	}

	var next time.Time
	if err := s.rot.db.QueryRow(ctx, `SELECT next_rotation_at FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&next); err != nil {
		t.Fatalf("query next_rotation_at: %v", err)
	}
	if days := time.Until(next).Hours() / 24; days < 29 || days > 31 {
		t.Fatalf("next_rotation_at ~%.1f days out, want ~30", days)
	}

	// Scheduled for the future, not immediately due.
	due, err := s.rot.ClaimDue(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range due {
		if id == secID {
			t.Fatal("secret scheduled ~30 days out should not be immediately due")
		}
	}
}

// TestCreateSecretNoRotationScheduleForNonRotationCapableType proves a plain
// (non-heartbeat) secret type never gets a rotation_schedule row on create.
func TestCreateSecretNoRotationScheduleForNonRotationCapableType(t *testing.T) {
	ctx := context.Background()
	pool := rotTestPool(t)
	s := newServer(t)
	s.rot = newRotationStore(pool.Querier())
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)

	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "plain", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	ok, err := s.rot.Exists(ctx, created.GetSecret().GetId())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("non-rotation-capable secret should not get a rotation_schedule row")
	}
}

func TestClaimDueRotationsBadTokenAuditsDenied(t *testing.T) {
	s, ca, _ := newRotationServer(t)
	s.wid = rejectVerifier{}
	if _, err := s.ClaimDueRotations(context.Background(), &vaultv1.ClaimDueRotationsRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "bad"}, Limit: 10,
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if ca.find("rotate.denied") == nil {
		t.Fatal("expected a rotate.denied audit event")
	}
}

func TestClaimDueRotationsUnavailableWithoutVerifier(t *testing.T) {
	s, _, _ := newRotationServer(t)
	s.wid = nil
	if _, err := s.ClaimDueRotations(context.Background(), &vaultv1.ClaimDueRotationsRequest{Limit: 10}); code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable with no verifier, got %v", err)
	}
}

func TestClaimDueRotationsReturnsJobSkipsRetired(t *testing.T) {
	s, _, secID := newRotationServer(t)
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
	if job.GetSecretId() != secID || job.GetUsername() != "svc-rotate" {
		t.Fatalf("job mismatch: %+v", job)
	}
	if job.GetConnection().GetProtocol() != "ldap" || job.GetTarget().GetRealm() != "EXAMPLE.ORG" {
		t.Fatalf("job conn/target missing: %+v", job)
	}

	// Retired secret is skipped even when its schedule row is due.
	if _, err := s.RetireSecret(ctx, &vaultv1.RetireSecretRequest{Actor: carol, Id: secID}); err != nil {
		t.Fatal(err)
	}
	// make it due again (claim above stamped claimed_until)
	_ = s.rot.Reschedule(ctx, secID, time.Now(), 0)
	resp2, err := s.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp2.GetJobs()) != 0 {
		t.Fatalf("retired secret should yield no jobs, got %d", len(resp2.GetJobs()))
	}
}

func TestRevealForRotationStagesAndAudits(t *testing.T) {
	s, ca, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)
	resp, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("RevealForRotation: %v", err)
	}
	if resp.GetUsername() != "svc-rotate" || resp.GetCurrentPassword() != "OldP@ss1" {
		t.Fatalf("reveal current mismatch: %+v", resp)
	}
	np := resp.GetNewPassword()
	if len([]rune(np)) < 12 || !hasClass(np, unicode.IsUpper) || !hasClass(np, unicode.IsLower) || !hasClass(np, unicode.IsDigit) {
		t.Fatalf("new password does not satisfy default policy: %q", np)
	}
	if np == "OldP@ss1" {
		t.Fatal("new password must differ from current")
	}
	// A staged version now exists.
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); !ok {
		t.Fatal("expected a staged version after reveal")
	}
	// Sensitive rotate.reveal audit under connector:<worker>.
	ev := ca.find("rotate.reveal")
	if ev == nil {
		t.Fatal("expected rotate.reveal audit")
	}
	if !ev.Sensitive || ev.ActorUserID != "connector:worker-1" || ev.Subject != secID {
		t.Fatalf("rotate.reveal audit wrong: %+v", ev)
	}
}

func TestRevealForRotationRejectsUnscheduled(t *testing.T) {
	s, _, secID := newRotationServer(t)
	// Creation auto-schedules rotation-capable secrets whose policy has an
	// interval (see CreateSecret) — remove that row to exercise the
	// not-scheduled guard on its own terms.
	if err := s.rot.Remove(context.Background(), secID); err != nil {
		t.Fatal(err)
	}
	// No enqueue, no schedule row → not scheduled.
	if _, err := s.RevealForRotation(context.Background(), &vaultv1.RevealForRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
	}); code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for unscheduled, got %v", err)
	}
}

// TestRevealForRotationRejectsUnclaimed proves the claim guard: a
// secret that is due (has an EnqueueRotation-scheduled row) but has never been
// picked up via ClaimDueRotations/ClaimDue must not be revealed/staged — only
// a live claim makes it a legitimate in-flight job.
func TestRevealForRotationRejectsUnclaimed(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for an unclaimed (due but unpicked-up) secret, got %v", err)
	}
}

// TestRevealForRotationTwiceLeavesOneStagedRow proves the atomic
// replace: a retried reveal on an already-claimed secret must replace the
// staged version, never accumulate a second one.
func TestRevealForRotationTwiceLeavesOneStagedRow(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)

	if _, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
	}); err != nil {
		t.Fatalf("first reveal: %v", err)
	}
	resp2, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
	})
	if err != nil {
		t.Fatalf("second reveal: %v", err)
	}

	var stagedCount int
	if err := s.vers.db.Querier().QueryRow(ctx,
		`SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND staged`, secID).Scan(&stagedCount); err != nil {
		t.Fatal(err)
	}
	if stagedCount != 1 {
		t.Fatalf("staged rows = %d, want 1 (second reveal must replace, not accumulate)", stagedCount)
	}
	vno, ok, err := s.vers.StagedVersion(ctx, secID)
	if err != nil || !ok {
		t.Fatalf("StagedVersion: vno=%d ok=%v err=%v", vno, ok, err)
	}
	if resp2.GetNewPassword() == "" {
		t.Fatal("expected a new password from the second reveal")
	}
}

// claimSecret enqueues-then-claims secID via the real rotation queue path
// (mirrors ClaimDueRotations), putting it in the claimed state
// RevealForRotation requires.
func claimSecret(t *testing.T, s *Server, secID string) {
	t.Helper()
	ctx := context.Background()
	due, err := s.rot.ClaimDue(ctx, 10, rotClaimTTL)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	for _, id := range due {
		if id == secID {
			return
		}
	}
	t.Fatalf("expected %s to be claimed, got %v", secID, due)
}

// revealNew enqueues, claims, reveals, and returns the generated new password.
func revealNew(t *testing.T, s *Server, secID string) string {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)
	resp, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("RevealForRotation: %v", err)
	}
	return resp.GetNewPassword()
}

// revealNewVer enqueues, claims, reveals, and returns both the generated new
// password and the staged version_no the reveal bound it to.
func revealNewVer(t *testing.T, s *Server, secID string) (string, int32) {
	t.Helper()
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)
	resp, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("RevealForRotation: %v", err)
	}
	return resp.GetNewPassword(), resp.GetVersion()
}

func versionCounts(t *testing.T, s *Server, secID string) (total, active int) {
	t.Helper()
	if err := s.vers.db.Querier().QueryRow(context.Background(),
		`SELECT count(*), count(*) FILTER (WHERE active) FROM secret_versions WHERE secret_id=$1`,
		secID).Scan(&total, &active); err != nil {
		t.Fatal(err)
	}
	return total, active
}

// TestRevealForRotationReturnsVersion proves the reveal echoes back the exact
// staged version_no, and two reveals in a row return strictly increasing
// versions while leaving exactly one staged row (the unique-staged invariant).
func TestRevealForRotationReturnsVersion(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)

	r1, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("first reveal: %v", err)
	}
	if r1.GetVersion() == 0 {
		t.Fatal("reveal must return a non-zero staged version")
	}
	r2, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("second reveal: %v", err)
	}
	if r2.GetVersion() <= r1.GetVersion() {
		t.Fatalf("second reveal version %d must exceed first %d", r2.GetVersion(), r1.GetVersion())
	}
	var stagedCount int
	if err := s.vers.db.Querier().QueryRow(ctx,
		`SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND staged`, secID).Scan(&stagedCount); err != nil {
		t.Fatal(err)
	}
	if stagedCount != 1 {
		t.Fatalf("staged rows = %d, want exactly 1", stagedCount)
	}
}

// TestReportRotationIdempotentCommit proves a repeated OK report on the same
// version commits exactly once: the second call (version now active) is a no-op
// idempotent retry — no second commit, no new version, old version retained.
func TestReportRotationIdempotentCommit(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	np, v := revealNewVer(t, s, secID)

	report := func() error {
		_, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
			Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
			Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
			Version: v,
		})
		return err
	}
	if err := report(); err != nil {
		t.Fatalf("first report: %v", err)
	}
	if got := activePassword(t, s, secID); got != np {
		t.Fatalf("active password = %q, want new %q", got, np)
	}
	total1, active1 := versionCounts(t, s, secID)
	if total1 != 2 || active1 != 1 {
		t.Fatalf("after first report versions total=%d active=%d, want 2/1", total1, active1)
	}

	if err := report(); err != nil {
		t.Fatalf("second (idempotent) report: %v", err)
	}
	total2, active2 := versionCounts(t, s, secID)
	if total2 != total1 || active2 != active1 {
		t.Fatalf("second report changed versions: total %d->%d active %d->%d", total1, total2, active1, active2)
	}
	if got := activePassword(t, s, secID); got != np {
		t.Fatalf("active password after retry = %q, want %q", got, np)
	}
}

// TestReportRotationStaleOKRejected proves the version binding: after a second
// reveal supersedes the first staged version, an OK report bound to the OLD
// version is rejected (FailedPrecondition) and never commits — the newer staged
// version survives and the active credential is untouched.
func TestReportRotationStaleOKRejected(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	claimSecret(t, s, secID)

	r1, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("first reveal: %v", err)
	}
	r2, err := s.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID})
	if err != nil {
		t.Fatalf("second reveal: %v", err)
	}

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
		Version: r1.GetVersion(),
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("stale OK report: want FailedPrecondition, got %v", err)
	}
	// v1 not committed — original active credential stands.
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1 (stale report must not commit)", got)
	}
	// v2 still staged.
	vno, ok, err := s.vers.StagedVersion(ctx, secID)
	if err != nil || !ok {
		t.Fatalf("StagedVersion: vno=%d ok=%v err=%v", vno, ok, err)
	}
	if vno != int(r2.GetVersion()) {
		t.Fatalf("staged version = %d, want v2=%d", vno, r2.GetVersion())
	}
}

// TestReportRotationIdempotentFailed proves a repeated FAILED report on the same
// version discards the staged version exactly once and does not double-bump the
// consecutive-failure counter (the second call sees the version already gone and
// returns ok without re-bumping or re-notifying).
func TestReportRotationIdempotentFailed(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_, v := revealNewVer(t, s, secID)

	report := func() error {
		_, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
			Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
			Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected",
			Version: v,
		})
		return err
	}
	if err := report(); err != nil {
		t.Fatalf("first FAILED report: %v", err)
	}
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); ok {
		t.Fatal("staged version should be discarded on FAILED")
	}
	failsAfter := func() int {
		var n int
		if err := s.rot.db.QueryRow(ctx, `SELECT consecutive_failures FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := failsAfter(); got != 1 {
		t.Fatalf("consecutive_failures = %d after first FAILED, want 1", got)
	}

	if err := report(); err != nil {
		t.Fatalf("second (idempotent) FAILED report: %v", err)
	}
	if got := failsAfter(); got != 1 {
		t.Fatalf("consecutive_failures = %d after idempotent retry, want 1 (no double-bump)", got)
	}
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1 (FAILED keeps old)", got)
	}
}

// TestReportRotationSkippedDiscardsStaging proves change=SKIPPED bound to a
// staged version cleans up the revealed-but-unused staging while leaving the
// prior LastRotationResult untouched.
func TestReportRotationSkippedDiscardsStaging(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()

	// Establish a prior OK result, then stage a fresh version to skip.
	_, v1 := revealNewVer(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
		Version: v1,
	}); err != nil {
		t.Fatalf("setup OK report: %v", err)
	}
	np1 := activePassword(t, s, secID)
	if s.findSecret(secID).GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("setup: LastRotationResult = %v, want OK", s.findSecret(secID).GetLastRotationResult())
	}

	_, v2 := revealNewVer(t, s, secID)
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); !ok {
		t.Fatal("expected a staged version before SKIPPED")
	}

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, Validate: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED,
		Version: v2, Detail: "no adapter for protocol",
	}); err != nil {
		t.Fatalf("SKIPPED report: %v", err)
	}
	// Staged row cleaned up.
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); ok {
		t.Fatal("SKIPPED must discard the revealed-but-unused staged version")
	}
	// LastRotationResult unchanged; active credential unchanged.
	if got := s.findSecret(secID).GetLastRotationResult(); got != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("LastRotationResult = %v after SKIPPED, want unchanged OK", got)
	}
	if got := activePassword(t, s, secID); got != np1 {
		t.Fatalf("active password = %q after SKIPPED, want unchanged %q", got, np1)
	}
}

func TestReportRotationCommitOnValidateOK(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	np := revealNew(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	// Staged committed active; hot path + ledger now the new password.
	if got := activePassword(t, s, secID); got != np {
		t.Fatalf("active password = %q, want new %q", got, np)
	}
	hot, err := s.crypt.Open(s.records[secID], "password")
	if err != nil || hot != np {
		t.Fatalf("hot-path password = %q err=%v, want new", hot, err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("LastRotationResult = %v, want OK", sec.GetLastRotationResult())
	}
	if sec.GetRotatedAt() == "" {
		t.Fatal("RotatedAt should be set on OK")
	}
	if sec.GetNextRotationAt() == "" {
		t.Fatal("NextRotationAt should be set when interval>0")
	}
	// Prior version retained inactive (2 versions, 1 active).
	var total, active int
	if err := s.vers.db.Querier().QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE active) FROM secret_versions WHERE secret_id=$1`, secID).Scan(&total, &active); err != nil {
		t.Fatal(err)
	}
	if total != 2 || active != 1 {
		t.Fatalf("versions total=%d active=%d, want 2/1", total, active)
	}
	// Claim cleared.
	var claimNull bool
	if err := s.rot.db.QueryRow(ctx, `SELECT claimed_until IS NULL FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&claimNull); err != nil {
		t.Fatal(err)
	}
	if !claimNull {
		t.Fatal("claim should be cleared after report")
	}
}

func TestReportRotationChangeFailedKeepsOld(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_ = revealNew(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected",
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	// Old password still active; staged discarded.
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1 (unchanged)", got)
	}
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); ok {
		t.Fatal("staged version should be discarded on change=FAILED")
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_FAILED {
		t.Fatalf("LastRotationResult = %v, want FAILED", sec.GetLastRotationResult())
	}
	var fails int
	if err := s.rot.db.QueryRow(ctx, `SELECT consecutive_failures FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("consecutive_failures = %d, want 1", fails)
	}
}

func TestReportRotationValidateFailedDegraded(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	np := revealNew(t, s, secID)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_FAILED,
		Detail: "kerberos validate timed out",
	}); err != nil {
		t.Fatalf("ReportRotation: %v", err)
	}
	// Committed anyway (target has the new password).
	if got := activePassword(t, s, secID); got != np {
		t.Fatalf("active password = %q, want new %q (committed on degraded)", got, np)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_DEGRADED {
		t.Fatalf("LastRotationResult = %v, want DEGRADED", sec.GetLastRotationResult())
	}
}

// TestReportRotationNotifiesOnFailure asserts the Informed fan-out fires for a
// failed rotation.
func TestReportRotationNotifiesOnFailure(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	rn := &recNotifier{}
	s.SetNotifier(rn)
	// Grant an Informed subject so notifyInformed has someone to fan out to.
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	sec := s.findSecret(secID)
	if _, err := s.SetSecretRuleset(ctx, &vaultv1.SetSecretRulesetRequest{
		Actor: carol, SecretId: secID, Rules: []*vaultv1.RaciRule{{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-turing",
			Grants: map[string]string{"I": "allow"},
		}},
	}); err != nil {
		t.Fatalf("SetSecretRuleset: %v", err)
	}
	_ = sec
	_ = revealNew(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "boom",
	}); err != nil {
		t.Fatal(err)
	}
	if rn.last == nil {
		t.Fatal("expected a notification on failed rotation")
	}
}

// TestReportRotationStagedVersionErrorReturnsInternal proves that
// a StagedVersion read that fails with a real DB error (not merely "no staged
// row") must not be swallowed into a false OK — the target may already be
// rotated, so vault must tell the connector to retry rather than silently
// keeping the OLD version active while reporting success.
//
// The DB error is a genuine one: a second pool to the same test database,
// closed before use, so every query against it returns a closed-pool error —
// while s.rot (a separate store on the original, live pool) still resolves
// normally, so this exercises exactly the StagedVersion branch and not the
// unrelated "not scheduled" guard.
func TestReportRotationStagedVersionErrorReturnsInternal(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_ = revealNew(t, s, secID)

	dsn := os.Getenv("TEST_DATABASE_DSN")
	brokenPool, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	brokenPool.Close()
	s.vers = newVersionStore(brokenPool)

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); code(err) != codes.Internal {
		t.Fatalf("want Internal on a staged-version DB error, got %v", err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() == vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatal("must not report OK when the staged version could not be read")
	}
}

// TestReportRotationHotPathRefreshErrorReturnsInternal proves the post-commit
// half of the same guard: once Commit has succeeded, a hot-path refresh (ActiveRecord) that
// fails must still return Internal rather than reporting OK with a stale hot
// path. The staged row's record is corrupted (a syntactically valid JSONB
// value whose WrappedDEK is not valid base64) so Commit — which only flips
// boolean flags by version_no and never parses the record — succeeds, while
// the subsequent ActiveRecord unmarshal of that same row fails.
func TestReportRotationHotPathRefreshErrorReturnsInternal(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_ = revealNew(t, s, secID)

	if _, err := s.vers.db.Querier().Exec(ctx,
		`UPDATE secret_versions SET record = jsonb_set(record, '{WrappedDEK}', '"not-valid-base64!!!"')
		 WHERE secret_id=$1 AND staged AND NOT active`, secID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); code(err) != codes.Internal {
		t.Fatalf("want Internal on a hot-path refresh error, got %v", err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() == vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatal("must not report OK when the post-commit hot-path refresh failed")
	}
}

// TestReportRotationCapsRetriesAndGoesDormant proves the retry cap:
// past rotMaxFailures consecutive FAILED reports, the schedule stops
// auto-retrying (next_rotation_at goes NULL) instead of backing off forever.
func TestReportRotationCapsRetriesAndGoesDormant(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < rotMaxFailures; i++ {
		if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
			Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
			Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected",
		}); err != nil {
			t.Fatalf("ReportRotation #%d: %v", i+1, err)
		}
	}

	var dormant bool
	if err := s.rot.db.QueryRow(ctx,
		`SELECT next_rotation_at IS NULL FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&dormant); err != nil {
		t.Fatal(err)
	}
	if !dormant {
		t.Fatalf("expected next_rotation_at NULL (dormant) after %d consecutive failures", rotMaxFailures)
	}
	due, err := s.rot.ClaimDue(ctx, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range due {
		if id == secID {
			t.Fatal("a dormant rotation must not be claimable as due")
		}
	}

	// A manual EnqueueRotation re-arms it.
	if _, err := s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: secID, Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	due2, err := s.rot.ClaimDue(ctx, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range due2 {
		if id == secID {
			found = true
		}
	}
	if !found {
		t.Fatal("manual EnqueueRotation should re-arm a dormant rotation")
	}
}

// TestReportRotationSkippedDoesNotOverwriteLastResult proves that
// change=SKIPPED must leave a prior LastRotationResult (e.g. OK) untouched
// rather than clobbering it with UNSPECIFIED.
func TestReportRotationSkippedDoesNotOverwriteLastResult(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_ = revealNew(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); err != nil {
		t.Fatal(err)
	}
	sec := s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("setup: LastRotationResult = %v, want OK", sec.GetLastRotationResult())
	}

	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, Validate: vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED,
		Detail: "no adapter for protocol",
	}); err != nil {
		t.Fatal(err)
	}
	sec = s.findSecret(secID)
	if sec.GetLastRotationResult() != vaultv1.RotationState_ROTATION_STATE_OK {
		t.Fatalf("LastRotationResult = %v after SKIPPED, want unchanged OK", sec.GetLastRotationResult())
	}
}

// TestReportRotationAuditsOutcomeWithoutCredential proves the
// "rotate" audit event carries the outcome as an attribute, and no attribute,
// subject or actor ever contains the generated credential value.
func TestReportRotationAuditsOutcomeWithoutCredential(t *testing.T) {
	s, ca, secID := newRotationServer(t)
	ctx := context.Background()
	np := revealNew(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK,
	}); err != nil {
		t.Fatal(err)
	}
	ev := ca.find("rotate")
	if ev == nil {
		t.Fatal("expected a rotate audit event")
	}
	want := vaultv1.RotationState_ROTATION_STATE_OK.String()
	if ev.Attributes["result"] != want {
		t.Fatalf("rotate audit result attribute = %q, want %q", ev.Attributes["result"], want)
	}
	if strings.Contains(ev.Subject, np) || strings.Contains(ev.ActorUserID, np) {
		t.Fatal("rotate audit leaked the credential value via subject/actor")
	}
	for k, v := range ev.Attributes {
		if strings.Contains(v, np) {
			t.Fatalf("rotate audit attribute %q leaked the credential value", k)
		}
	}
}

// TestReportRotationDiscardThenRevealNeverReusesVersion proves the
// soft-discard invariant: after a FAILED report discards a revealed version, the
// next reveal must hand out a strictly-higher version_no (never the freed
// number), so a stale OK bound to the discarded version can never match the new
// row — it is rejected and the newer staged version survives untouched.
func TestReportRotationDiscardThenRevealNeverReusesVersion(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()

	_, va := revealNewVer(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected", Version: va,
	}); err != nil {
		t.Fatalf("FAILED report: %v", err)
	}

	// Second reveal must yield a strictly-higher version, never the freed number.
	_, vb := revealNewVer(t, s, secID)
	if vb <= va {
		t.Fatalf("second reveal version %d must exceed discarded %d (never reused)", vb, va)
	}

	// A stale OK bound to the discarded v(a) is rejected and never commits.
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: va,
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("stale OK on discarded version: want FailedPrecondition, got %v", err)
	}

	// v(b) still staged; the original active credential is untouched.
	vno, ok, err := s.vers.StagedVersion(ctx, secID)
	if err != nil || !ok || vno != int(vb) {
		t.Fatalf("StagedVersion: vno=%d ok=%v err=%v, want %d", vno, ok, err, vb)
	}
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1 (stale report must not commit)", got)
	}
}

// TestReportRotationSoftDiscardLeavesInertRow proves a FAILED discard leaves a
// physically-retained, inert row (exists=true, staged=false, active=false) that
// VersionStatus reports as neither staged nor active, and that an OK report bound
// to that discarded version is rejected exactly like a truly-absent one (never a
// wrong commit).
func TestReportRotationSoftDiscardLeavesInertRow(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()

	_, va := revealNewVer(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected", Version: va,
	}); err != nil {
		t.Fatalf("FAILED report: %v", err)
	}

	active, staged, exists, err := s.vers.VersionStatus(ctx, secID, int(va))
	if err != nil {
		t.Fatalf("VersionStatus: %v", err)
	}
	if !exists || staged || active {
		t.Fatalf("discarded version status: exists=%v staged=%v active=%v, want true/false/false", exists, staged, active)
	}
	// The row is retained (soft-discarded), not deleted.
	var cnt int
	if err := s.vers.db.Querier().QueryRow(ctx,
		`SELECT count(*) FROM secret_versions WHERE secret_id=$1 AND version_no=$2`, secID, va).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("discarded row should be retained, got count=%d", cnt)
	}

	// OK bound to the inert version behaves identically to absent: rejected.
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: va,
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("OK on discarded version: want FailedPrecondition, got %v", err)
	}
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1 (discarded OK must not commit)", got)
	}
}

// TestReportRotationOKActiveHealsHotPath proves that after a version has been
// committed, a duplicate OK report bound to the now-active version re-reads the
// active record and repairs a hot path a prior post-commit refresh may have left
// stale — without re-committing or rewriting the schedule.
func TestReportRotationOKActiveHealsHotPath(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()

	np, v := revealNewVer(t, s, secID)
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: v,
	}); err != nil {
		t.Fatalf("first OK report: %v", err)
	}
	rotatedAt := s.findSecret(secID).GetRotatedAt()

	// Simulate a half-applied commit: the row is active, but the hot path is
	// stale/missing (as if the earlier post-commit refresh had failed).
	s.mu.Lock()
	delete(s.records, secID)
	s.mu.Unlock()

	// A duplicate OK on the now-active version self-heals s.records.
	if _, err := s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
		Change: vaultv1.RotationPhase_ROTATION_PHASE_OK, Validate: vaultv1.RotationPhase_ROTATION_PHASE_OK, Version: v,
	}); err != nil {
		t.Fatalf("idempotent OK retry: %v", err)
	}
	s.mu.RLock()
	rec, ok := s.records[secID]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("hot path was not healed on the OK×active retry")
	}
	pw, err := s.crypt.Open(rec, "password")
	if err != nil || pw != np {
		t.Fatalf("healed hot-path password = %q err=%v, want new %q", pw, err, np)
	}
	// The idempotent retry must not rewrite the commit timestamp.
	if got := s.findSecret(secID).GetRotatedAt(); got != rotatedAt {
		t.Fatalf("RotatedAt rewritten on idempotent retry: %q -> %q", rotatedAt, got)
	}
	// No re-commit: still exactly two versions, one active.
	total, active := versionCounts(t, s, secID)
	if total != 2 || active != 1 {
		t.Fatalf("versions total=%d active=%d after heal, want 2/1", total, active)
	}
}

// TestReportRotationConcurrentFailedSingleBump proves that two concurrent
// FAILED reports for the same staged version both succeed, but the
// consecutive-failure counter is bumped exactly once — only the report whose
// soft-discard cleared the staged flag bumps; the racing loser observes zero
// rows-affected and returns an idempotent ok.
func TestReportRotationConcurrentFailedSingleBump(t *testing.T) {
	s, _, secID := newRotationServer(t)
	ctx := context.Background()
	_, v := revealNewVer(t, s, secID)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.ReportRotation(ctx, &vaultv1.ReportRotationRequest{
				Identity: &vaultv1.WorkerIdentity{Token: "ok"}, SecretId: secID,
				Change: vaultv1.RotationPhase_ROTATION_PHASE_FAILED, Detail: "bind rejected", Version: v,
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent FAILED report #%d: %v", i, err)
		}
	}

	var fails int
	if err := s.rot.db.QueryRow(ctx,
		`SELECT consecutive_failures FROM rotation_schedule WHERE secret_id=$1`, secID).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails != 1 {
		t.Fatalf("consecutive_failures = %d after two concurrent FAILED reports, want exactly 1", fails)
	}
	// Old credential kept; staged version discarded.
	if got := activePassword(t, s, secID); got != "OldP@ss1" {
		t.Fatalf("active password = %q, want OldP@ss1", got)
	}
	if _, ok, _ := s.vers.StagedVersion(ctx, secID); ok {
		t.Fatal("staged version should be discarded after FAILED")
	}
}
