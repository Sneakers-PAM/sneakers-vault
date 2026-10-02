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
		conn, tgt := s.connTargetFor(sec)
		if conn == nil {
			// The connector can only report UNREACHABLE here, which alerts.
			// Dropping the row stops the re-claim; attaching a target
			// schedules it again.
			s.dropUnreachableHeartbeat(ctx, sec)
			continue
		}
		jobs = append(jobs, &vaultv1.HeartbeatJob{
			SecretId: id, SecretName: sec.GetName(),
			Username:   s.nonSensitiveField(id, "username"),
			Connection: conn, Target: tgt,
		})
	}
	return &vaultv1.ClaimDueHeartbeatsResponse{Jobs: jobs}, nil
}

// dropUnreachableHeartbeat removes the schedule row of a claimed secret the
// connector cannot reach.
func (s *Server) dropUnreachableHeartbeat(ctx context.Context, sec *vaultv1.Secret) {
	l := log.Ctx(ctx)
	if err := s.hb.Remove(ctx, sec.GetId()); err != nil {
		l.Error().Err(err).Str("secret_id", sec.GetId()).Msg("remove unreachable heartbeat schedule failed")
		return
	}
	l.Warn().Str("secret_id", sec.GetId()).Str("target_id", sec.GetTargetId()).
		Msg("heartbeat schedule removed: secret has no target with a connection")
}

// RevealForHeartbeat releases the managed account's current credential to a
// verified worker for exactly one bind attempt. Audited like any reveal.
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
	s.emit(ctx, "connector:"+principal.WorkerID, "heartbeat", req.GetSecretId(), true)
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
	if _, err := s.verifyWorker(ctx, req.GetIdentity()); err != nil {
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

	s.emit(ctx, "connector", "heartbeat.report", req.GetSecretId(), false)
	// Notify only on the TRANSITION into a bad state, never on every poll — a
	// target that stays down/drifted must not flood the inbox each interval.
	//   drift: fire when the result first becomes FAILED (prev wasn't FAILED).
	//   unreachable: fire on the poll that reaches N consecutive (transient
	//     blips below N stay quiet); clearUnreachable() re-arms on recovery.
	driftAlert := req.GetResult() == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED &&
		prevResult != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED
	unreachableAlert := req.GetResult() == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE &&
		consec == hbAlertAfterN
	if driftAlert || unreachableAlert {
		s.notifyHeartbeat(ctx, secID, secName, chain, req.GetResult(), req.GetDetail())
	}
	return &vaultv1.ReportHeartbeatResponse{Ok: true}, nil
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
	}
	conn := findByID(s.connections, tgt.GetConnectionId())
	if conn == nil {
		return nil, target
	}
	return &vaultv1.HeartbeatConn{
		Protocol: conn.GetProtocol(), Host: tgt.GetHostname(), Port: conn.GetPort(), UseTls: conn.GetUseTls(),
	}, target
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
	if result == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED {
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
	l := log.Ctx(ctx)
	if err := s.hb.Pause(ctx, secretID); err != nil {
		l.Error().Err(err).Str("secret_id", secretID).Msg("pause heartbeat after a failed check failed")
		return
	}
	l.Warn().Str("secret_id", secretID).
		Msg("heartbeat paused after a failed check: no automatic retry until the credential is updated or a check is requested")
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
		l := log.Ctx(ctx)
		l.Error().Err(err).Str("secret_id", sec.GetId()).Msg("resume paused heartbeat failed")
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
	l := log.Ctx(ctx)
	l.Info().Str("secret_id", sec.GetId()).Str("reason", attrs["reason"]).Msg("paused heartbeat resumed")
	s.emitAttrs(ctx, actorID, "secret.heartbeat.resume", sec.GetId(), false, attrs)
}
