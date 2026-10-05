// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Connector rotation pull-API + state-aware compensation. Vault owns the
// rotation state machine: it queues due rotations, hands the connector the
// current credential plus a freshly generated replacement (staged as a pending
// version), and — on the connector's two-phase report — commits or compensates
// so vault and target never desync and a blind rollback never happens.
package grpcsvc

import (
	"context"
	"math"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// rotClaimTTL is longer than the heartbeat claim: a rotation does a write +
	// validate round-trip, so a claimed job needs more headroom before it's
	// considered abandoned and reclaimable.
	rotClaimTTL   = 5 * time.Minute
	rotMaxBackoff = 1 * time.Hour

	// rotMaxFailures caps how many consecutive FAILED reports a schedule retries
	// before it's parked dormant (next_rotation_at = NULL) rather than backing
	// off forever and re-notifying on every poll. A manual EnqueueRotation
	// re-arms it.
	rotMaxFailures = 5
)

// rotState is a readability alias converting the RotationState enum to the int
// stored in rotation_schedule.state.
func rotState(s vaultv1.RotationState) int { return int(s) }

// rotBackoff grows the retry delay with consecutive failures (2^n minutes,
// capped) so a persistently failing rotation doesn't hammer the target.
func rotBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures < 1 {
		consecutiveFailures = 1
	}
	d := time.Duration(math.Pow(2, float64(consecutiveFailures))) * time.Minute
	if d > rotMaxBackoff {
		d = rotMaxBackoff
	}
	return d
}

// typeHasRotation reports whether a secret is rotation-capable: its type must
// declare the "allowed rotation" capability AND the secret must not carry a
// per-secret rotation opt-out, nor be the domain's built-in Administrator
// (see builtinAdministratorReason). Rotation is now an explicit type capability (SSH
// keys, cards, notes, etc. are never rotated, even though key material is a
// SENSITIVE field) rather than being inferred from heartbeat + a password field.
// Caller holds at least s.mu.RLock.
func (s *Server) typeHasRotation(sec *vaultv1.Secret) bool {
	if sec.GetRotationOptOut() || sec.GetBuiltinAdministrator() {
		return false
	}
	t := s.findType(sec.GetTypeId())
	return t != nil && t.GetRotation() && rotatesFieldKey(t) != ""
}

// rotatesFieldKey returns the key of the field a rotation replaces: the first
// field flagged Rotates. Empty means the type declares no rotatable field (and
// so is not rotatable).
func rotatesFieldKey(t *vaultv1.SecretType) string {
	for _, f := range t.GetFields() {
		if f.GetRotates() {
			return f.GetKey()
		}
	}
	return ""
}

// policyForSecret resolves the password policy that governs a secret's generated
// replacement: the policy bound to the type's password field, else the instance
// default policy, else nil (GeneratePassword then applies its own defaults).
// Caller holds at least s.mu.RLock.
func (s *Server) policyForSecret(sec *vaultv1.Secret) *vaultv1.PasswordPolicy {
	var fieldPolicyID string
	if t := s.findType(sec.GetTypeId()); t != nil {
		for _, f := range t.GetFields() {
			if f.GetKind() == vaultv1.FieldKind_FIELD_KIND_PASSWORD && f.GetPolicyId() != "" {
				fieldPolicyID = f.GetPolicyId()
				break
			}
		}
	}
	return s.resolvePolicy(fieldPolicyID)
}

// resolvePolicy resolves a preferred policy id (a type's password-field
// binding, or an explicit override) to a PasswordPolicy: the preferred id if
// it names a known policy, else the instance default policy, else nil
// (GeneratePassword then applies its own defaults). Extracted from
// policyForSecret so GenerateSecretForPrincipal's passwordPolicyForField
// (secrets_principal.go) reuses the exact same resolution
// instead of reinventing it. Equivalent to policyForSecret's prior inline
// loop for the single-password-field types in use today; for a hypothetical
// multi-password-field type where an earlier field carries a dangling
// (non-empty but unknown) policy_id and a later field carries a valid one,
// the old loop kept scanning past the dangling id to find the later field's
// policy, whereas this split (policyForSecret picks the first non-empty
// policy_id and breaks, then resolvePolicy looks it up) resolves to the
// instance default instead of scanning further fields. Not a behavior change
// for any type today (all have a single password field); left as-is rather
// than reintroducing the scan-past-dangling-ids logic since the rotation
// path is well tested and changing it carries risk.
// Caller holds at least s.mu.RLock.
func (s *Server) resolvePolicy(preferredID string) *vaultv1.PasswordPolicy {
	if preferredID != "" {
		if p := findByID(s.policies, preferredID); p != nil {
			return p
		}
	}
	if s.settings != nil {
		if p := findByID(s.policies, s.settings.GetDefaultPasswordPolicyId()); p != nil {
			return p
		}
	}
	return nil
}

// policyRotationDays returns a policy's rotation interval in days (0 = none).
func policyRotationDays(p *vaultv1.PasswordPolicy) int {
	if p != nil && p.RotationDays != nil {
		return int(p.GetRotationDays())
	}
	return 0
}

// rotationScheduled reports whether secretID currently has a rotation_schedule
// row — a legitimate, scheduled rotation target. Fails closed on a nil store or
// lookup error, so Reveal/Report deny rather than treat an unscheduled secret as
// in-scope (mirrors heartbeatScheduled).
func (s *Server) rotationScheduled(ctx context.Context, secretID string) bool {
	if s.rot == nil {
		return false
	}
	ok, err := s.rot.Exists(ctx, secretID)
	return err == nil && ok
}

// connectionForSecret resolves the full Connection behind a secret's target (for
// the rotate-the-rotator guard, which needs the privileged-secret linkage).
// Caller holds at least s.mu.RLock.
func (s *Server) connectionForSecret(sec *vaultv1.Secret) *vaultv1.Connection {
	tgt := findByID(s.targets, sec.GetTargetId())
	if tgt == nil {
		return nil
	}
	return findByID(s.connections, tgt.GetConnectionId())
}

// rotationReachable reports whether a secret has a target whose connection
// exists, the minimum the connector needs to attempt a rotation. Caller holds
// at least s.mu.RLock.
func (s *Server) rotationReachable(sec *vaultv1.Secret) bool {
	return s.connectionForSecret(sec) != nil
}

// rotationEligible reports whether a secret can actually be rotated now: it is
// rotation-capable and the connector can reach it. Caller holds s.mu.RLock.
func (s *Server) rotationEligible(sec *vaultv1.Secret) bool {
	return s.typeHasRotation(sec) && s.rotationReachable(sec)
}

// dropUnreachableRotation removes the schedule row of a claimed secret the
// connector cannot reach.
func (s *Server) dropUnreachableRotation(ctx context.Context, sec *vaultv1.Secret) {
	l := s.lg(ctx)
	if err := s.rot.Remove(ctx, sec.GetId()); err != nil {
		l.Error(err, "remove unreachable rotation schedule failed", log.F("secret_id", sec.GetId()))
		return
	}
	l.Warn("rotation schedule removed: secret has no target with a connection", log.F("secret_id", sec.GetId()), log.F("target_id", sec.GetTargetId()))
}

// unclaimableReason reports why a claimed rotation row can never become a
// job, or "" if it can. Caller holds s.mu.RLock.
func unclaimableReason(s *Server, sec *vaultv1.Secret) string {
	switch {
	case sec == nil:
		return "secret deleted"
	case sec.GetRetired():
		return "secret retired"
	case sec.GetBuiltinAdministrator():
		return builtinAdministratorReason
	case !s.typeHasRotation(sec):
		return "secret no longer rotation-capable"
	}
	return ""
}

// dropClaimedRotation removes the schedule row of a claimed secret that will
// never be rotated, logging why.
func (s *Server) dropClaimedRotation(ctx context.Context, secretID, why string) {
	l := s.lg(ctx)
	if err := s.rot.Remove(ctx, secretID); err != nil {
		l.Error(err, "remove claimed rotation schedule failed", log.F("secret_id", secretID), log.F("reason", why))
		return
	}
	l.Warn("rotation schedule removed at claim", log.F("secret_id", secretID), log.F("reason", why))
}

// errNoRotationTarget is returned when a rotation is requested for a secret
// the connector cannot reach.
var errNoRotationTarget = status.Error(codes.FailedPrecondition,
	"secret has no target with a connection: attach a target before rotating")

// managedPeersOnConnection lists the other secret ids whose target binds to the
// same connection as sec (i.e. the accounts a connection's privileged credential
// manages). Caller holds at least s.mu.RLock.
func (s *Server) managedPeersOnConnection(connID, exceptSecretID string) []string {
	var out []string
	for _, sec := range s.secrets {
		if sec.GetId() == exceptSecretID {
			continue
		}
		tgt := findByID(s.targets, sec.GetTargetId())
		if tgt != nil && tgt.GetConnectionId() == connID {
			out = append(out, sec.GetId())
		}
	}
	return out
}

// EnqueueRotation makes a secret due for rotation now (all trigger paths route
// here). The actor must be permitted to manage (rotate = RACI author) the
// secret's folder, and the secret must not be retired. The built-in
// Administrator is never enqueued: a check-in or break-glass rotation is
// skipped (OK, audited rotate.skip) and any other request is refused with
// FailedPrecondition (audited rotate.refused). Root/site-admin are
// also permitted even without folder Author rights: the authz package's
// root/site-admin auto-allow covers only Read, not Author, so without this
// explicit bypass a system-triggered or admin-initiated rotation would be
// wrongly denied.
func (s *Server) EnqueueRotation(ctx context.Context, req *vaultv1.EnqueueRotationRequest) (*vaultv1.EnqueueRotationResponse, error) {
	s.mu.RLock()
	sec := findByID(s.secrets, req.GetSecretId())
	var retired, permitted, reachable, builtinAdmin, optedOut, rotates bool
	var intervalDays int
	var targetID string
	if sec != nil {
		retired = sec.GetRetired()
		builtinAdmin = sec.GetBuiltinAdministrator()
		permitted = s.canManage(req.GetActor(), sec.GetFolderId()) || isHumanAdmin(req.GetActor())
		reachable = s.rotationReachable(sec)
		optedOut = sec.GetRotationOptOut()
		rotates = s.typeHasRotation(sec)
		intervalDays = policyRotationDays(s.policyForSecret(sec))
		targetID = sec.GetTargetId()
	}
	s.mu.RUnlock()
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if retired {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !permitted {
		return nil, status.Error(codes.PermissionDenied, "not permitted to rotate this secret")
	}
	if builtinAdmin {
		return s.refuseBuiltinAdministratorEnqueue(ctx, req)
	}
	if err := s.checkRotatable(ctx, req, optedOut, rotates); err != nil {
		return nil, err
	}
	if !reachable {
		l := s.lg(ctx)
		l.Warn("rotation refused: secret has no target with a connection", log.F("secret_id", req.GetSecretId()), log.F("target_id", targetID))
		return nil, errNoRotationTarget
	}
	if s.rot == nil {
		return nil, status.Error(codes.Unavailable, "rotation queue not configured")
	}
	if err := s.rot.Enqueue(ctx, req.GetSecretId(), req.GetReason(), intervalDays); err != nil {
		return nil, status.Errorf(codes.Internal, "enqueue: %v", err)
	}
	s.emit(ctx, req.GetActor().GetUserId(), "rotate.enqueue", req.GetSecretId(), false)
	return &vaultv1.EnqueueRotationResponse{Ok: true}, nil
}

// ClaimDueRotations hands the connector a batch of due rotation jobs. No secret
// values travel here — only enough context (username, connection/target) to
// attempt the swap; RevealForRotation is the separate, audited credential call.
func (s *Server) ClaimDueRotations(ctx context.Context, req *vaultv1.ClaimDueRotationsRequest) (*vaultv1.ClaimDueRotationsResponse, error) {
	if _, err := s.verifyWorkerAudited(ctx, req.GetIdentity(), "rotate.denied"); err != nil {
		return nil, err
	}
	if s.rot == nil {
		return nil, status.Error(codes.Unavailable, "rotation queue not configured")
	}
	if s.maint.On() {
		s.lg(ctx).Debug("rotation claim answered empty: read-only maintenance")
		return &vaultv1.ClaimDueRotationsResponse{}, nil
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	ids, err := s.rot.ClaimDue(ctx, limit, rotClaimTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "claim: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := make([]*vaultv1.RotationJob, 0, len(ids))
	for _, id := range ids {
		sec := findByID(s.secrets, id)
		if why := unclaimableReason(s, sec); why != "" {
			// Never handed out, so leaving the row would re-claim it forever.
			s.dropClaimedRotation(ctx, id, why)
			continue
		}
		conn, tgt := s.connTargetFor(sec)
		if conn == nil {
			// Nothing to rotate against. Dropping the row stops it being
			// re-claimed and shown as rotating forever; attaching a target
			// schedules it again.
			s.dropUnreachableRotation(ctx, sec)
			continue
		}
		// Rotate-the-rotator: don't rotate a connection's privileged credential
		// while any account it manages is mid-rotation. Release the claim so it
		// retries once the managed rotations settle.
		if c := s.connectionForSecret(sec); c != nil && c.GetPrivilegedSecretId() == id {
			peers := s.managedPeersOnConnection(c.GetId(), id)
			if inflight, ierr := s.rot.InFlightOnConnection(ctx, peers); ierr == nil && inflight {
				_ = s.rot.Reschedule(ctx, id, time.Now(), rotState(vaultv1.RotationState_ROTATION_STATE_UNSPECIFIED))
				continue
			}
		}
		jobs = append(jobs, &vaultv1.RotationJob{
			SecretId: id, SecretName: sec.GetName(),
			Username:   s.nonSensitiveField(id, "username"),
			Connection: conn, Target: tgt,
		})
	}
	return &vaultv1.ClaimDueRotationsResponse{Jobs: jobs}, nil
}

// RevealForRotation generates a policy-compliant replacement password, stages it
// as a pending version, and returns {username, current, new} to a verified
// worker. The connector never generates passwords itself. Audited as a SENSITIVE
// rotate.reveal under the worker principal; subject is the secret id only — no
// credential value is ever logged or audited.
//
//nolint:gocyclo // pre-existing complexity
func (s *Server) RevealForRotation(ctx context.Context, req *vaultv1.RevealForRotationRequest) (*vaultv1.RevealForRotationResponse, error) {
	principal, err := s.verifyWorkerAudited(ctx, req.GetIdentity(), "rotate.denied")
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	sec := findByID(s.secrets, req.GetSecretId())
	var retired, rotationCapable bool
	var policy *vaultv1.PasswordPolicy
	var rotField string
	if sec != nil {
		retired = sec.GetRetired()
		rotationCapable = s.typeHasRotation(sec)
		policy = s.policyForSecret(sec)
		if t := s.findType(sec.GetTypeId()); t != nil {
			rotField = rotatesFieldKey(t)
		}
	}
	rec, ok := s.records[req.GetSecretId()]
	s.mu.RUnlock()

	if sec == nil {
		return nil, errNotFound("secret")
	}
	if retired {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !rotationCapable {
		return nil, status.Error(codes.PermissionDenied, "not a rotation-capable secret")
	}
	if !s.rotationScheduled(ctx, req.GetSecretId()) {
		return nil, status.Error(codes.PermissionDenied, "secret not scheduled for rotation")
	}
	if s.rot == nil {
		return nil, status.Error(codes.Unavailable, "rotation queue not configured")
	}
	claimed, err := s.rot.Claimed(ctx, req.GetSecretId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check rotation claim: %v", err)
	}
	if !claimed {
		// A due-but-unclaimed schedule row is not yet a live job: generating and
		// staging a replacement here would race ClaimDueRotations and could stage
		// a credential no worker is actually about to swap. Only a claimed job
		// (via ClaimDueRotations) may reveal/stage.
		return nil, status.Error(codes.FailedPrecondition, "rotation not claimed")
	}
	if s.vers == nil {
		return nil, status.Error(codes.Unavailable, "version store not configured")
	}
	if !ok {
		return nil, errNotFound("secret value")
	}
	fields, err := s.crypt.OpenAll(rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	newpw, err := GeneratePassword(policy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate password: %v", err)
	}
	// Seal a copy of the fields with only the rotatable field replaced (the field
	// the type flags Rotates — "password" for account types, but not hard-coded).
	staged := make(map[string]string, len(fields))
	for k, v := range fields {
		staged[k] = v
	}
	staged[rotField] = newpw
	stagedRec, err := s.crypt.Seal(staged)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal staged: %v", err)
	}
	// Replace any prior staged version and stage the new one atomically (retry
	// safety): a retried reveal must never leave two staged rows, nor a window
	// with none.
	stagedVersionNo, err := s.vers.ReplaceStaged(ctx, req.GetSecretId(), stagedRec, "connector:"+principal.WorkerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stage version: %v", err)
	}
	s.emit(ctx, "connector:"+principal.WorkerID, "rotate.reveal", req.GetSecretId(), true)
	// Return the exact staged version_no so the connector echoes it back in
	// ReportRotation: the report is bound to the version this reveal staged, even
	// if a later reveal replaces the staged row before the worker reports.
	return &vaultv1.RevealForRotationResponse{
		Username: fields["username"], CurrentPassword: fields[rotField], NewPassword: newpw,
		Version: safeconv.Int32(stagedVersionNo),
	}, nil
}

// ReportRotation records the connector's two-phase outcome and applies the
// state-aware compensation: never blind-rollback, never desync.
//
// The report is bound to req.Version — the exact version_no RevealForRotation
// staged for this worker — so a second reveal that replaces the staged row
// between apply and report can never make a report commit (or discard) the wrong
// version. Discards are soft (staged=false, row retained) so version_no is
// strictly monotonic and never reused; a discarded version is therefore inert
// and every branch keys off the (staged, active) pair only, treating a
// soft-discarded version (staged=false, active=false, exists=true) exactly like
// a truly-absent one:
//   - change=OK
//   - version active           → already committed (idempotent retry): no re-commit; re-read the active record to self-heal a stale hot path; result OK/DEGRADED; schedule/timestamps left untouched (no cosmetic drift).
//   - version staged           → commit staged→active (prior retained), refresh hot path, OK/DEGRADED, reschedule, ClearFailure on OK.
//   - neither (absent/discarded)→ stale/superseded: FailedPrecondition, never commit.
//   - change=FAILED
//   - version staged           → soft-discard that version; only the caller whose discard cleared the flag (rows-affected==1) keeps OLD active, sets FAILED, bumps failure + backoff (dormant past rotMaxFailures) and notifies; a racing loser (0) returns idempotent ok.
//   - neither (absent/discarded)→ already discarded on a prior report: idempotent ok, no re-bump, no re-notify.
//   - version active           → contradictory/stale: defensive no-op ok, never un-commit.
//   - change=SKIPPED
//   - version staged           → soft-discard the revealed-but-unused staging; reschedule on interval; LastRotationResult left as-is.
//   - neither/active           → no-op ok.
//   - change=SKIPPED with builtin_administrator → the connector refused the
//     built-in Administrator: see refuseBuiltinAdministratorReport.
//
// version==0 (an un-upgraded caller) falls back to the pre-binding,
// StagedVersion-based behavior so nothing breaks; the shipped connector always sends it.
//
// A version-status/StagedVersion read error or a post-commit hot-path refresh
// failure is never swallowed into a false OK: both return Internal so the
// connector retries (Commit is idempotent by version_no; the refresh re-runs).
//
//nolint:gocognit,gocyclo // pre-existing complexity
func (s *Server) ReportRotation(ctx context.Context, req *vaultv1.ReportRotationRequest) (*vaultv1.ReportRotationResponse, error) {
	if _, err := s.verifyWorkerAudited(ctx, req.GetIdentity(), "rotate.denied"); err != nil {
		return nil, err
	}
	secID := req.GetSecretId()
	s.mu.RLock()
	sec := findByID(s.secrets, secID)
	var rotationCapable, flagged bool
	var intervalDays int
	if sec != nil {
		rotationCapable = s.typeHasRotation(sec)
		flagged = sec.GetBuiltinAdministrator()
		intervalDays = policyRotationDays(s.policyForSecret(sec))
	}
	s.mu.RUnlock()
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if req.GetBuiltinAdministrator() && req.GetChange() == vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		return s.refuseBuiltinAdministratorReport(ctx, req, flagged)
	}
	if !rotationCapable {
		return nil, status.Error(codes.PermissionDenied, "not a rotation-capable secret")
	}
	if !s.rotationScheduled(ctx, secID) {
		return nil, status.Error(codes.PermissionDenied, "secret not scheduled for rotation")
	}
	if s.rot == nil || s.vers == nil {
		return nil, status.Error(codes.Unavailable, "rotation stores not configured")
	}

	change, validate := req.GetChange(), req.GetValidate()
	now := time.Now().UTC()

	// v is the exact version the reporting worker revealed (0 = un-upgraded
	// caller → pre-binding StagedVersion fallback). versioned drives every branch
	// off VersionStatus(secID, v) so a later reveal that replaced the staged row
	// can never make this report act on the wrong version.
	v := int(req.GetVersion())
	versioned := v != 0

	var result vaultv1.RotationState
	var next time.Time
	var newRecord crypto.Record
	refreshRecord := false // we hold a fresh active record to install in the hot path.
	alreadyActive := false // OK×active idempotent retry: skip schedule/timestamp rewrites.
	skipResult := false    // change=SKIPPED: leave Secret.LastRotationResult as-is.

	switch change {
	case vaultv1.RotationPhase_ROTATION_PHASE_FAILED:
		// Target unchanged: throw away the revealed version, keep the old active
		// credential (still decrypts, heartbeat unaffected), back off — or, past
		// rotMaxFailures consecutive failures, stop auto-retrying altogether
		// (next stays the zero value below, which Reschedule stores as NULL:
		// dormant until a manual EnqueueRotation re-arms it). Retries naturally
		// stop notifying once dormant, since there's nothing left to poll.
		result = vaultv1.RotationState_ROTATION_STATE_FAILED
		if !versioned {
			_ = s.vers.DiscardStaged(ctx, secID)
			fails, _ := s.rot.BumpFailure(ctx, secID)
			if fails < rotMaxFailures {
				next = now.Add(rotBackoff(fails))
			}
			break
		}
		active, staged, _, err := s.vers.VersionStatus(ctx, secID, v)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "version status: %v", err)
		}
		switch {
		case staged:
			// Soft-discard, then bump only if this call actually won the discard
			// (rows-affected==1). Two concurrent FAILED reports both see staged,
			// but only one clears the flag — the loser observes 0 and must not
			// double-bump the failure counter or re-notify.
			n, derr := s.vers.DiscardVersion(ctx, secID, v)
			if derr != nil {
				return nil, status.Errorf(codes.Internal, "discard version: %v", derr)
			}
			if n != 1 {
				return &vaultv1.ReportRotationResponse{Ok: true}, nil
			}
			fails, _ := s.rot.BumpFailure(ctx, secID)
			if fails < rotMaxFailures {
				next = now.Add(rotBackoff(fails))
			}
		case active:
			// Contradictory/stale: this version was already committed but the
			// connector now reports the change failed. Defensive no-op — never
			// un-commit a live credential.
			return &vaultv1.ReportRotationResponse{Ok: true}, nil
		default:
			// Neither staged nor active: absent or already soft-discarded on a
			// prior FAILED report. Idempotent — don't re-bump the failure counter
			// or re-notify, and leave the schedule as the earlier report left it.
			return &vaultv1.ReportRotationResponse{Ok: true}, nil
		}

	case vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED:
		// No-op on the target: no active version change; reschedule on the
		// interval. The prior LastRotationResult (OK/FAILED/DEGRADED) is left
		// untouched — a skip isn't itself a result worth recording over it.
		result = vaultv1.RotationState_ROTATION_STATE_UNSPECIFIED
		skipResult = true
		if !versioned {
			// Defensive: a hypothetical un-upgraded caller that revealed then
			// skipped would otherwise orphan its staged row. Soft-discard any
			// staging before rescheduling.
			_ = s.vers.DiscardStaged(ctx, secID)
			if intervalDays > 0 {
				next = now.AddDate(0, 0, intervalDays)
			}
			break
		}
		_, staged, _, err := s.vers.VersionStatus(ctx, secID, v)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "version status: %v", err)
		}
		if !staged {
			// absent, discarded, or active: nothing revealed-but-unused to clean
			// up. No-op.
			return &vaultv1.ReportRotationResponse{Ok: true}, nil
		}
		// Clean up the revealed-but-unapplied staging, then reschedule.
		if _, derr := s.vers.DiscardVersion(ctx, secID, v); derr != nil {
			return nil, status.Errorf(codes.Internal, "discard version: %v", derr)
		}
		if intervalDays > 0 {
			next = now.AddDate(0, 0, intervalDays)
		}

	default:
		// change=OK (target now has the new credential): commit the revealed
		// version regardless of validate — never leave the target ahead of vault.
		doCommit := false
		commitVno := v
		if !versioned {
			// Pre-binding fallback: commit whatever is currently staged.
			vno, staged, err := s.vers.StagedVersion(ctx, secID)
			if err != nil {
				// Don't swallow this into a false OK: the target is already
				// rotated but which version to commit is now unknown. Report
				// nothing; the connector retries and Commit is idempotent.
				return nil, status.Errorf(codes.Internal, "staged version: %v", err)
			}
			doCommit = staged
			commitVno = vno
		} else {
			active, staged, _, err := s.vers.VersionStatus(ctx, secID, v)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "version status: %v", err)
			}
			switch {
			case active:
				// Idempotent retry: this version is already committed. Do NOT
				// re-commit, but still re-read the active record below to
				// self-heal a hot path a prior refresh may have left stale.
				alreadyActive = true
			case staged:
				doCommit = true
			default:
				// Neither staged nor active (superseded, never staged, or
				// soft-discarded): never commit a stale version — that would
				// desync vault ahead of the target.
				return nil, status.Error(codes.FailedPrecondition, "unknown or superseded rotation version")
			}
		}
		if doCommit {
			if err := s.vers.Commit(ctx, secID, commitVno); err != nil {
				return nil, status.Errorf(codes.Internal, "commit version: %v", err)
			}
			rec, ok, rerr := s.vers.ActiveRecord(ctx, secID)
			if rerr != nil || !ok {
				// Commit landed but the hot-path re-read failed or found
				// nothing: never report OK while the hot path is stale (the
				// rest of vault — reveal, heartbeat — would keep serving the
				// OLD credential). The connector retries; Commit is idempotent
				// and this refresh simply re-runs.
				return nil, status.Errorf(codes.Internal, "refresh hot path: ok=%v err=%v", ok, rerr)
			}
			newRecord = rec
			refreshRecord = true
		} else if alreadyActive {
			// Self-heal a half-applied commit: Commit already happened on an
			// earlier attempt, but its post-commit hot-path refresh may have
			// failed. Re-read the active record so this retry heals a stale hot
			// path. An error/!ok while active returns Internal (consistent with
			// the staged-commit path) so the connector retries.
			rec, ok, rerr := s.vers.ActiveRecord(ctx, secID)
			if rerr != nil || !ok {
				return nil, status.Errorf(codes.Internal, "refresh hot path: ok=%v err=%v", ok, rerr)
			}
			newRecord = rec
			refreshRecord = true
		}
		if validate == vaultv1.RotationPhase_ROTATION_PHASE_OK {
			result = vaultv1.RotationState_ROTATION_STATE_OK
			_ = s.rot.ClearFailure(ctx, secID)
		} else {
			// Target has the new password but proof failed (e.g. replication lag):
			// commit stands, flag DEGRADED for operator attention.
			result = vaultv1.RotationState_ROTATION_STATE_DEGRADED
		}
		if intervalDays > 0 {
			next = now.AddDate(0, 0, intervalDays)
		}
	}

	// An OK×active idempotent retry must not rewrite the schedule to the retry
	// time (the rotation already committed on an earlier attempt): skip the
	// reschedule and the RotatedAt/NextRotationAt rewrites to avoid cosmetic drift
	// on late duplicates.
	if !alreadyActive {
		_ = s.rot.Reschedule(ctx, secID, next, rotState(result))
	}

	// Apply to the in-memory hot path + Secret rotation fields, and snapshot the
	// notify inputs, all under the write lock.
	s.mu.Lock()
	sec = findByID(s.secrets, secID)
	if sec == nil {
		s.mu.Unlock()
		return nil, errNotFound("secret")
	}
	if refreshRecord {
		// Point the secret_records hot path at the newly-active version so the
		// rest of vault (reveal, heartbeat) reads the rotated credential. The
		// PersistUnary interceptor snapshots this after the RPC returns. Set both
		// on a fresh commit and on an OK×active self-heal.
		s.records[secID] = newRecord
		s.resumeHeartbeatOnValueChange(ctx, sec, "connector", map[string]string{"reason": "credential_rotated"})
	}
	if !skipResult {
		sec.LastRotationResult = result
	}
	if result == vaultv1.RotationState_ROTATION_STATE_OK && !alreadyActive {
		sec.RotatedAt = now.Format(time.RFC3339)
	}
	sec.RotationIntervalDays = int32(intervalDays)
	if !next.IsZero() && !alreadyActive {
		sec.NextRotationAt = next.Format(time.RFC3339)
	}
	secName := sec.GetName()
	chain := s.secretChain(sec)
	s.mu.Unlock()

	// The outcome is recorded as an attribute (never a credential value: only
	// the RotationState name, e.g. "ROTATION_STATE_OK").
	s.emitAttrs(ctx, "connector", "rotate", secID, false, map[string]string{"result": result.String()})
	if result == vaultv1.RotationState_ROTATION_STATE_FAILED || result == vaultv1.RotationState_ROTATION_STATE_DEGRADED {
		s.notifyRotation(ctx, secID, secName, chain, result, req.GetDetail())
	}
	return &vaultv1.ReportRotationResponse{Ok: true}, nil
}

// notifyRotation is a best-effort Informed-notification for a failed or degraded
// rotation. Inputs are snapshotted by the caller under s.mu, so no shared state
// is touched here (race-free against concurrent mutations, like notifyHeartbeat).
func (s *Server) notifyRotation(ctx context.Context, secID, secName string, chain []authz.CategoryRuleset, result vaultv1.RotationState, detail string) {
	action := "secret.rotation.degraded"
	if result == vaultv1.RotationState_ROTATION_STATE_FAILED {
		action = "secret.rotation.failed"
	}
	label := secName
	if detail != "" {
		label = label + " — " + detail
	}
	s.notifyInformed(ctx, "connector", action, "secret", secID, label, chain)
}

// Rotation refusal reasons.
const (
	// ReasonRotationNotSupported: the secret's type has no rotation.
	ReasonRotationNotSupported = "ROTATION_NOT_SUPPORTED"
	// ReasonRotationOptedOut: the secret is opted out of rotation.
	ReasonRotationOptedOut = "ROTATION_OPTED_OUT"
)

// checkRotatable refuses a rotation the secret can't do, so nothing is queued
// for a job that would never finish. Audited as rotate.refused.
func (s *Server) checkRotatable(ctx context.Context, req *vaultv1.EnqueueRotationRequest, optedOut, rotates bool) error {
	reason, msg := "", ""
	switch {
	case optedOut:
		reason, msg = ReasonRotationOptedOut, "this secret is opted out of rotation"
	case !rotates:
		reason, msg = ReasonRotationNotSupported, "this secret's type can't be rotated"
	default:
		return nil
	}
	s.lg(ctx).Info("rotation refused", log.F("secret_id", req.GetSecretId()), log.F("reason", reason), log.F("trigger", req.GetReason()))
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "rotate.refused", req.GetSecretId(), false, map[string]string{
		"reason": reason, "trigger": req.GetReason(),
	})
	return refuseCode(codes.FailedPrecondition, reason, msg)
}
