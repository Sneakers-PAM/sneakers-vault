// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Connector pull-API: the heartbeat worker never holds long-lived vault
// credentials — it authenticates per-call via WorkerIdentity, claims due
// validation jobs, reveals just the one credential it needs to bind with, and
// reports the result back so the schedule advances (or backs off).
package grpcsvc

import (
	"context"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	hbClaimTTL    = 2 * time.Minute
	hbAlertAfterN = 3
	hbMaxBackoff  = 30 * time.Minute
)

// HB_VALID / HB_UNREACHABLE are readability aliases for the two
// HeartbeatResult values nextDue's backoff logic branches on.
const (
	HB_VALID       = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK
	HB_UNREACHABLE = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE
)

// hostKeyRefused reports an SSH heartbeat the connector didn't run because
// the target's host key couldn't be verified (no pins, or a key not pinned).
func hostKeyRefused(r vaultv1.HeartbeatResult) bool {
	return r == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED ||
		r == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH
}

// heartbeatFailed reports a failed check: a wrong credential, or a host the
// connector refused to trust.
func heartbeatFailed(r vaultv1.HeartbeatResult) bool {
	return r == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED || hostKeyRefused(r)
}

// nextDue computes the next scheduled time: interval on valid/invalid;
// exponential backoff (capped) on unreachable, keyed by consecutive count.
func nextDue(from time.Time, intervalSeconds int, result vaultv1.HeartbeatResult, consecutiveUnreachable int) time.Time {
	if result == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE {
		backoff := time.Duration(math.Pow(2, float64(consecutiveUnreachable))) * time.Second * 15
		if backoff > hbMaxBackoff {
			backoff = hbMaxBackoff
		}
		return from.Add(backoff)
	}
	if intervalSeconds <= 0 {
		intervalSeconds = 300
	}
	return from.Add(time.Duration(intervalSeconds) * time.Second)
}

// verifyWorker gates every connector RPC on the shared worker-identity
// verifier (the dev token seam, or the OIDC verifier for projected
// ServiceAccount tokens — same interface), and
// returns the verified Principal so callers can attribute audited actions
// (e.g. a credential reveal) to the specific worker, not just "connector".
// A rejected or absent identity is itself audited (heartbeat.denied) before
// the error is returned, so forged/rejected worker attempts leave a trace
// even though they never reach an authenticated actor.
func (s *Server) verifyWorker(ctx context.Context, id *vaultv1.WorkerIdentity) (workloadid.Principal, error) {
	return s.verifyWorkerAudited(ctx, id, "heartbeat.denied")
}

// verifyWorkerAudited is verifyWorker with a caller-supplied denial audit action
// so each connector pull-API family attributes its rejections distinctly
// (heartbeat.denied vs rotate.denied) while sharing the identity gate.
func (s *Server) verifyWorkerAudited(ctx context.Context, id *vaultv1.WorkerIdentity, deniedAction string) (workloadid.Principal, error) {
	if s.wid == nil {
		s.emit(ctx, "connector", deniedAction, "", false)
		return workloadid.Principal{}, status.Error(codes.Unavailable, "worker identity not configured")
	}
	principal, err := s.wid.Verify(id.GetToken())
	if errors.Is(err, workloadid.ErrUnavailable) {
		s.emit(ctx, "connector", deniedAction, "", false)
		return workloadid.Principal{}, status.Error(codes.Unavailable, "worker identity unavailable")
	}
	if err != nil {
		s.emit(ctx, "connector", deniedAction, "", false)
		return workloadid.Principal{}, status.Error(codes.PermissionDenied, "worker identity rejected")
	}
	s.recordConnectorContact(ctx, principal.WorkerID)
	return principal, nil
}

// heartbeatScheduled reports whether secretID currently has an active
// heartbeat_schedule row — i.e. is a legitimate, currently-scheduled
// heartbeat target, not just any secret of a heartbeat-capable type. Fails
// closed: a nil heartbeat store or a lookup error is treated as "not
// scheduled" so RevealForHeartbeat/ReportHeartbeat deny rather than risk
// treating an unscheduled secret as in-scope.
func (s *Server) heartbeatScheduled(ctx context.Context, secretID string) bool {
	if s.hb == nil {
		return false
	}
	ok, err := s.hb.Exists(ctx, secretID)
	return err == nil && ok
}

// ClaimDueHeartbeats hands the connector a batch of due validation jobs. No
// secret values travel here — only enough non-sensitive context (username,
// connection/target) for the worker to attempt a bind; RevealForHeartbeat is
// the separate, audited call for the credential itself.
func (s *Server) ClaimDueHeartbeats(ctx context.Context, req *vaultv1.ClaimDueHeartbeatsRequest) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	if _, err := s.verifyWorker(ctx, req.GetIdentity()); err != nil {
		return nil, err
	}
	if s.maint.On() {
		s.lg(ctx).Debug("heartbeat claim answered empty: read-only maintenance")
		return &vaultv1.ClaimDueHeartbeatsResponse{}, nil
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	ids, err := s.hb.ClaimDue(ctx, limit, hbClaimTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "claim: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := make([]*vaultv1.HeartbeatJob, 0, len(ids))
	for _, id := range ids {
		sec := findByID(s.secrets, id)
		if sec == nil || sec.GetRetired() {
			continue
		}
		if !s.heartbeatReachable(sec) {
			// The connector can only report UNREACHABLE (or, for SSH, refuse
			// the host key) here, which alerts. Dropping the row stops the
			// re-claim; attaching a target or pinning a host key schedules it
			// again.
			s.dropUnreachableHeartbeat(ctx, sec)
			continue
		}
		conn, tgt := s.connTargetFor(sec)
		jobs = append(jobs, &vaultv1.HeartbeatJob{
			SecretId: id, SecretName: sec.GetName(),
			Username:   s.nonSensitiveField(id, "username"),
			Connection: conn, Target: tgt,
			Logon: s.jobLogonFormat(id),
		})
	}
	return &vaultv1.ClaimDueHeartbeatsResponse{Jobs: jobs}, nil
}

// dropUnreachableHeartbeat removes the schedule row of a claimed secret the
// connector cannot reach.
func (s *Server) dropUnreachableHeartbeat(ctx context.Context, sec *vaultv1.Secret) {
	l := s.lg(ctx)
	if err := s.hb.Remove(ctx, sec.GetId()); err != nil {
		l.Error(err, "remove unreachable heartbeat schedule failed", log.F("secret_id", sec.GetId()))
		return
	}
	l.Warn("heartbeat schedule removed: secret has no target with a connection", log.F("secret_id", sec.GetId()), log.F("target_id", sec.GetTargetId()))
}

// RevealForHeartbeat releases the managed account's current credential to a
// verified worker for exactly one bind attempt. The fetch itself is not
// audited on its own: it is always followed by a ReportHeartbeat call, which
// folds the fetch-plus-report pair into the secret's daily rollup when the
// check is routine (#161), or audits them together when it is not. A fetch
// the connector never reports back for (a crash, a dropped report) leaves no
// trace here, which is the one case this folding cannot see; that is outside
// this fix's scope.
func (s *Server) RevealForHeartbeat(ctx context.Context, req *vaultv1.RevealForHeartbeatRequest) (*vaultv1.RevealForHeartbeatResponse, error) {
	principal, err := s.verifyWorker(ctx, req.GetIdentity())
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	sec := findByID(s.secrets, req.GetSecretId())
	var retired, heartbeatCapable bool
	if sec != nil {
		retired = sec.GetRetired()
		heartbeatCapable = s.secretHeartbeatEnabled(sec)
	}
	rec, ok := s.records[req.GetSecretId()]
	s.mu.RUnlock()
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if retired {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	// This scopes the reveal to a secret the connector is legitimately
	// validating (heartbeat-capable type + actually scheduled), closing the
	// "any secret id" exfil oracle the pull-API used to be. It does NOT yet
	// bind the reveal to which connection/target this specific worker
	// principal is authorized to validate — that needs per-connector-principal
	// -> allowed-connection authz, which requires multi-principal worker
	// identity (today every worker verifies to the same dev principal).
	// @todo: add that once multi-principal identity lands.
	if !heartbeatCapable {
		return nil, status.Error(codes.PermissionDenied, "not a heartbeat-capable secret")
	}
	if !s.heartbeatScheduled(ctx, req.GetSecretId()) {
		return nil, status.Error(codes.PermissionDenied, "secret not scheduled for heartbeat")
	}
	if !ok {
		return nil, errNotFound("secret value")
	}
	fields, err := s.crypt.OpenAll(rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	s.lg(ctx).Debug("heartbeat credential fetched", log.F("secret_id", req.GetSecretId()), log.F("worker_id", principal.WorkerID))
	// Key-based types (ssh) carry key material and no password; password
	// types carry the password and no key material.
	if sec.GetTypeId() == "type-ssh-key" {
		return &vaultv1.RevealForHeartbeatResponse{
			Username:   fields["username"],
			PrivateKey: fields["privateKey"],
			Passphrase: fields["passphrase"],
		}, nil
	}
	return &vaultv1.RevealForHeartbeatResponse{Username: fields["username"], Password: fields["password"]}, nil
}

// ReportHeartbeat records the worker's validation outcome, reschedules the
// next attempt (interval, backoff on unreachable, paused on failed), and — for drift or
// sustained unreachability — fans out an Informed notification.
func (s *Server) ReportHeartbeat(ctx context.Context, req *vaultv1.ReportHeartbeatRequest) (*vaultv1.ReportHeartbeatResponse, error) {
	principal, err := s.verifyWorker(ctx, req.GetIdentity())
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	sec := findByID(s.secrets, req.GetSecretId())
	var heartbeatCapable bool
	if sec != nil {
		heartbeatCapable = s.secretHeartbeatEnabled(sec)
	}
	s.mu.RUnlock()
	if sec == nil {
		return nil, errNotFound("secret")
	}
	// Same scope check as RevealForHeartbeat: the reported result must be for
	// a secret that's actually a scheduled heartbeat target. This does not
	// verify THIS worker/claim owns the row — full per-worker claim-ownership
	// needs multi-principal identity tracking (see RevealForHeartbeat's
	// @todo); the scheduled+capable check is the current scope.
	if !heartbeatCapable {
		return nil, status.Error(codes.PermissionDenied, "not a heartbeat-capable secret")
	}
	if !s.heartbeatScheduled(ctx, req.GetSecretId()) {
		return nil, status.Error(codes.PermissionDenied, "secret not scheduled for heartbeat")
	}

	s.mu.Lock()
	sec = findByID(s.secrets, req.GetSecretId())
	if sec == nil {
		s.mu.Unlock()
		return nil, errNotFound("secret")
	}
	now := time.Now().UTC()
	prevResult := sec.GetLastHeartbeatResult() // captured before overwrite, for the drift transition check
	sec.LastHeartbeatResult = req.GetResult()
	sec.VerifiedAt = now.Format(time.RFC3339)
	// A FAILED bind means the stored credential is wrong; retrying it every
	// interval can lock the account out, so the schedule pauses instead.
	failed := req.GetResult() == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED
	sec.LastHeartbeatDetail = truncate(req.GetDetail(), maxHeartbeatDetail)
	if failed {
		sec.LastHeartbeatDetail = withPausedNote(req.GetDetail())
	}
	interval := int(sec.GetHeartbeatIntervalSeconds())
	secID, secName := sec.GetId(), sec.GetName()
	// Snapshot everything notifyHeartbeat/secretChain need (the secret's own
	// ruleset plus its folder/ancestor rulesets, and id/name for the label)
	// now, while s.mu is still held. secretChain reads sec and the shared
	// s.folders/s.raciRules, which other handlers mutate under s.mu.Lock(), so
	// this must happen before we unlock — otherwise the notify path below
	// races with those mutations.
	chain := s.secretChain(sec)
	flagAttrs := s.applyAccountFlags(ctx, sec, req)
	s.mu.Unlock()
	if flagAttrs != nil {
		s.emitAttrs(ctx, "connector", "secret.account_flags", secID, false, flagAttrs)
	}

	consec := 0
	if req.GetResult() == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE {
		consec = s.bumpUnreachable(ctx, req.GetSecretId())
	} else {
		_ = s.clearUnreachable(ctx, req.GetSecretId())
	}
	if failed {
		s.pauseHeartbeat(ctx, req.GetSecretId())
	} else {
		_ = s.hb.Reschedule(ctx, req.GetSecretId(), nextDue(now, interval, req.GetResult(), consec))
	}

	s.auditHeartbeatCheck(ctx, secID, principal.WorkerID, req.GetResult(), req.GetDetail())
	// Notify only on the TRANSITION into a bad state, never on every poll — a
	// target that stays down/drifted must not flood the inbox each interval.
	//   drift: fire when the result first becomes FAILED (prev wasn't FAILED).
	//   unreachable: fire on the poll that reaches N consecutive (transient
	//     blips below N stay quiet); clearUnreachable() re-arms on recovery.
	driftAlert := heartbeatFailed(req.GetResult()) && prevResult != req.GetResult()
	unreachableAlert := req.GetResult() == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE &&
		consec == hbAlertAfterN
	if driftAlert || unreachableAlert {
		s.notifyHeartbeat(ctx, secID, secName, chain, req.GetResult(), req.GetDetail())
	}
	return &vaultv1.ReportHeartbeatResponse{Ok: true}, nil
}

// auditHostKeyRefusal logs and audits a heartbeat the connector refused
// because the target's host key couldn't be verified. Other results are a
// no-op.
func (s *Server) auditHostKeyRefusal(ctx context.Context, secID string, result vaultv1.HeartbeatResult, detail string) {
	if !hostKeyRefused(result) {
		return
	}
	s.lg(ctx).Warn("SSH heartbeat refused: the target's host key could not be verified",
		log.F("secret_id", secID), log.F("result", result.String()))
	s.emitAttrs(ctx, "connector", "secret.heartbeat.host_key", secID, false,
		map[string]string{"result": result.String(), "detail": truncate(detail, maxHeartbeatDetail)})
}

// auditHeartbeatCheck records one heartbeat check (#161). A routine, OK check
// that matches the day and result of a rollup already open for this secret
// just extends it — no audit event for this check. Everything else flushes
// any pending rollup as its own summary record and is itself audited
// individually: a non-OK result (always, never folded — auditHostKeyRefusal
// adds its own record for a host-key refusal on top of the generic one, same
// as before this fix), or the first OK check that follows a different
// result (a recovery). A plain day rollover with the result staying OK is
// not a transition, so it opens the next day's rollup silently.
func (s *Server) auditHeartbeatCheck(ctx context.Context, secID, workerID string, result vaultv1.HeartbeatResult, detail string) {
	actor := "connector:" + workerID
	if result != HB_VALID {
		s.flushHeartbeatSummary(ctx, secID)
		s.emit(ctx, "connector", "heartbeat.report", secID, false)
		s.auditHostKeyRefusal(ctx, secID, result, detail)
		return
	}
	if s.hbSummary == nil {
		// No rollup store wired (e.g. a mem-only server): fall back to the
		// pre-fold behavior rather than silently dropping the audit record.
		s.emit(ctx, "connector", "heartbeat.report", secID, false)
		return
	}
	l := s.lg(ctx)
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	pending, open, err := s.hbSummary.Get(ctx, secID)
	if err != nil {
		l.Error(err, "read pending heartbeat rollup failed", log.F("secret_id", secID))
		s.emit(ctx, "connector", "heartbeat.report", secID, false)
		return
	}
	if open && pending.Result == HB_VALID.String() && pending.Day.Equal(today) {
		if err := s.hbSummary.Bump(ctx, secID, now, detail); err != nil {
			l.Error(err, "extend heartbeat rollup failed", log.F("secret_id", secID))
		}
		return
	}
	recovering := open && pending.Result != HB_VALID.String()
	s.flushHeartbeatSummary(ctx, secID)
	if recovering {
		s.emit(ctx, "connector", "heartbeat.report", secID, false)
	}
	if err := s.hbSummary.Start(ctx, secID, today, now, HB_VALID.String(), detail, actor); err != nil {
		l.Error(err, "start heartbeat rollup failed", log.F("secret_id", secID))
	}
}

// flushHeartbeatSummary emits the secret's pending rollup (if any) as one
// audit record carrying how many checks it covers and the window they span,
// then clears it. A no-op when there is nothing pending.
func (s *Server) flushHeartbeatSummary(ctx context.Context, secID string) {
	if s.hbSummary == nil {
		return
	}
	pending, open, err := s.hbSummary.Get(ctx, secID)
	if err != nil {
		s.lg(ctx).Error(err, "read pending heartbeat rollup failed", log.F("secret_id", secID))
		return
	}
	if !open {
		return
	}
	s.emitAttrs(ctx, pending.Actor, "heartbeat.summary", secID, false, map[string]string{
		"result": pending.Result,
		"checks": strconv.Itoa(pending.Checks),
		"first":  pending.StartedAt.Format(time.RFC3339),
		"last":   pending.LastAt.Format(time.RFC3339),
		"detail": truncate(pending.Detail, maxHeartbeatDetail),
	})
	if err := s.hbSummary.Clear(ctx, secID); err != nil {
		s.lg(ctx).Error(err, "clear heartbeat rollup failed", log.F("secret_id", secID))
	}
}

// connTargetFor resolves a secret's target and the target's connection into
// the connector-facing (protocol/host/port) shapes. Nil-safe: an unset or
// dangling target/connection yields nil fields rather than an error — the
// job just carries less connection detail. Caller must hold at least s.mu.RLock.
func (s *Server) connTargetFor(sec *vaultv1.Secret) (*vaultv1.HeartbeatConn, *vaultv1.HeartbeatTarget) {
	tgt := findByID(s.targets, sec.GetTargetId())
	if tgt == nil {
		return nil, nil
	}
	target := &vaultv1.HeartbeatTarget{
		Kind: tgt.GetKind(), Domain: tgt.GetDomain(), Realm: tgt.GetRealm(), Hostname: tgt.GetHostname(),
		SshHostKeys: slices.Clone(tgt.GetSshHostKeys()),
	}
	conn := findByID(s.connections, tgt.GetConnectionId())
	if conn == nil {
		return nil, target
	}
	return &vaultv1.HeartbeatConn{
		Protocol: conn.GetProtocol(), Host: tgt.GetHostname(), Port: conn.GetPort(), UseTls: conn.GetUseTls(),
	}, target
}

// typeNeedsHostKeyPin reports whether a secret's type binds over SSH, so its
// target's host identity must be pinned before the broker will send a
// credential to it. Only SSH Key secrets need this; an AD or local Windows
// account's heartbeat binds over LDAP/SMB, which this vault doesn't pin a
// host key for.
func typeNeedsHostKeyPin(typeID string) bool { return typeID == "type-ssh-key" }

// heartbeatReachable reports whether a secret has everything its heartbeat
// needs to actually run: a target whose connection exists (rotationReachable
// covers both), and — for an SSH Key secret only — at least one pinned host
// key on that target, since the broker refuses to send a credential to an
// unpinned host. Caller holds at least s.mu.RLock.
func (s *Server) heartbeatReachable(sec *vaultv1.Secret) bool {
	if !s.rotationReachable(sec) {
		return false
	}
	if !typeNeedsHostKeyPin(sec.GetTypeId()) {
		return true
	}
	tgt := findByID(s.targets, sec.GetTargetId())
	return tgt != nil && len(tgt.GetSshHostKeys()) > 0
}

// heartbeatUnreadyReason names what's missing for sec's heartbeat to run, for
// a heartbeat-capable secret that isn't heartbeatReachable — "" if it is (or
// the type isn't heartbeat-capable at all). Caller holds at least
// s.mu.RLock.
func (s *Server) heartbeatUnreadyReason(sec *vaultv1.Secret) string {
	if !s.typeHasHeartbeat(sec.GetTypeId()) {
		return ""
	}
	tgt := findByID(s.targets, sec.GetTargetId())
	switch {
	case sec.GetTargetId() == "" || tgt == nil:
		return "no target"
	case findByID(s.connections, tgt.GetConnectionId()) == nil:
		return "no connection"
	case typeNeedsHostKeyPin(sec.GetTypeId()) && len(tgt.GetSshHostKeys()) == 0:
		return "no pinned host key"
	default:
		return ""
	}
}

// nonSensitiveField reads one non-sensitive field's plaintext value for a
// secret, reusing the same decrypt-then-filter logic as GetSecretFields.
// Returns "" on any miss (no secret/record, decrypt error, or the field is
// sensitive) — the connector job only ever wants a bind-as username here,
// never a credential. Caller must hold at least s.mu.RLock.
func (s *Server) nonSensitiveField(secretID, key string) string {
	sec := findByID(s.secrets, secretID)
	rec, ok := s.records[secretID]
	if sec == nil || !ok {
		return ""
	}
	if s.isSensitiveField(s.findType(sec.GetTypeId()), key) {
		return ""
	}
	all, err := s.crypt.OpenAll(rec)
	if err != nil {
		return ""
	}
	return all[key]
}

// jobLogonFormat returns the secret's logon format fields for a connector
// job, or nil when it sets none. Caller holds s.mu.
func (s *Server) jobLogonFormat(secretID string) *vaultv1.LogonFormat {
	lf := &vaultv1.LogonFormat{
		Format:    s.nonSensitiveField(secretID, "logonFormat"),
		Netbios:   s.nonSensitiveField(secretID, "netbios"),
		UpnSuffix: s.nonSensitiveField(secretID, "upnSuffix"),
	}
	if lf.GetFormat() == "" && lf.GetNetbios() == "" && lf.GetUpnSuffix() == "" {
		return nil
	}
	return lf
}

// bumpUnreachable increments the schedule's consecutive-unreachable counter
// and returns the new count (used to gate the "alert after N" threshold).
// Best-effort: a nil heartbeat store or DB error yields 0 rather than failing
// the RPC — reporting still succeeds, just without escalation this round.
func (s *Server) bumpUnreachable(ctx context.Context, secretID string) int {
	if s.hb == nil {
		return 0
	}
	var n int
	err := s.hb.db.QueryRow(ctx,
		`UPDATE heartbeat_schedule SET consecutive_unreachable = consecutive_unreachable + 1
		 WHERE secret_id = $1 RETURNING consecutive_unreachable`, secretID).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// clearUnreachable resets the counter after a non-unreachable result.
func (s *Server) clearUnreachable(ctx context.Context, secretID string) error {
	if s.hb == nil {
		return nil
	}
	_, err := s.hb.db.Exec(ctx,
		`UPDATE heartbeat_schedule SET consecutive_unreachable = 0 WHERE secret_id = $1`, secretID)
	return err
}

// notifyHeartbeat is a best-effort Informed-notification for heartbeat drift
// (FAILED) or sustained unreachability. The caller (ReportHeartbeat) snapshots
// secID/secName and the RACI chain under s.mu before calling this, so no
// further access to the shared secrets/folders/raciRules state happens here —
// that keeps this notify path race-free against concurrent mutations.
func (s *Server) notifyHeartbeat(ctx context.Context, secID, secName string, chain []authz.CategoryRuleset, result vaultv1.HeartbeatResult, detail string) {
	action := "secret.heartbeat.unreachable"
	if heartbeatFailed(result) {
		action = "secret.heartbeat.drift"
	}
	label := secName
	if detail != "" {
		label = label + " — " + detail
	}
	s.notifyInformed(ctx, "connector", action, "secret", secID, label, chain)
}

// heartbeatPausedNote ends last_heartbeat_detail while a FAILED heartbeat
// holds the schedule, so the status says why no further check is coming.
const heartbeatPausedNote = "heartbeat paused after a failed check: update the credential or request a check to resume"

func withPausedNote(detail string) string {
	if detail == "" {
		return heartbeatPausedNote
	}
	return truncate(detail, maxHeartbeatDetail-len(heartbeatPausedNote)-1) + " " + heartbeatPausedNote
}

func withoutPausedNote(detail string) string {
	if detail == heartbeatPausedNote {
		return ""
	}
	return strings.TrimSuffix(detail, " "+heartbeatPausedNote)
}

// pauseHeartbeat holds a secret's heartbeat after a FAILED check until its
// credential changes or a check is requested.
func (s *Server) pauseHeartbeat(ctx context.Context, secretID string) {
	l := s.lg(ctx)
	if err := s.hb.Pause(ctx, secretID); err != nil {
		l.Error(err, "pause heartbeat after a failed check failed", log.F("secret_id", secretID))
		return
	}
	l.Warn("heartbeat paused after a failed check: no automatic retry until the credential is updated or a check is requested", log.F("secret_id", secretID))
	s.emit(ctx, "connector", "secret.heartbeat.pause", secretID, false)
}

// resumeHeartbeatOnValueChange lifts a pause once the stored credential has
// changed, making the check due now. A heartbeat that is not paused is left
// alone. attrs must carry a "reason". Caller holds s.mu (write lock).
func (s *Server) resumeHeartbeatOnValueChange(ctx context.Context, sec *vaultv1.Secret, actorID string, attrs map[string]string) {
	if s.hb == nil {
		return
	}
	resumed, err := s.hb.Resume(ctx, sec.GetId())
	if err != nil {
		l := s.lg(ctx)
		l.Error(err, "resume paused heartbeat failed", log.F("secret_id", sec.GetId()))
		return
	}
	if resumed {
		s.markHeartbeatResumed(ctx, sec, actorID, attrs)
	}
}

// markHeartbeatResumed clears the pause from the status and audits the
// resume. Caller holds s.mu (write lock) and has already made the row due.
func (s *Server) markHeartbeatResumed(ctx context.Context, sec *vaultv1.Secret, actorID string, attrs map[string]string) {
	sec.LastHeartbeatDetail = withoutPausedNote(sec.LastHeartbeatDetail)
	l := s.lg(ctx)
	l.Info("paused heartbeat resumed", log.F("secret_id", sec.GetId()), log.F("reason", attrs["reason"]))
	s.emitAttrs(ctx, actorID, "secret.heartbeat.resume", sec.GetId(), false, attrs)
}
