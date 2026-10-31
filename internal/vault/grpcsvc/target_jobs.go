// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Per-target connector jobs and outcome aggregation (#168): a secret
// attached to several targets hands the connector one TargetJob per target
// (primary first, kept as the legacy singular connection/target fields too)
// and, on report, aggregates per-target outcomes into the existing
// scalar last_rotation_result/last_heartbeat_result (OK only once every
// target succeeds) while keeping the per-target breakdown for display.
package grpcsvc

import (
	"context"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// targetUsable reports whether targetID resolves to a known target with a
// known connection and, for a type needing a pinned host key (SSH), at
// least one pin. Caller holds at least s.mu.RLock.
func (s *Server) targetUsable(targetID, typeID string) bool {
	tgt := findByID(s.targets, targetID)
	if tgt == nil || findByID(s.connections, tgt.GetConnectionId()) == nil {
		return false
	}
	if typeNeedsHostKeyPin(typeID) && len(tgt.GetSshHostKeys()) == 0 {
		return false
	}
	return true
}

// anyTargetUsable reports whether at least one of sec's attached targets is
// fully usable. Permissive by design: a secret with several targets, only
// some connected or pinned, is still claimed; the connector finds out (and
// reports, target_results) which succeed, rather than the whole job being
// withheld for one bad target. Caller holds at least s.mu.RLock.
func (s *Server) anyTargetUsable(sec *vaultv1.Secret) bool {
	for _, id := range secretTargetIDs(sec) {
		if s.targetUsable(id, sec.GetTypeId()) {
			return true
		}
	}
	return false
}

// targetJobFor builds one TargetJob for targetID. Nil-safe like the former
// connTargetFor: a dangling id, or one with no connection, yields a job
// with a nil Connection (and/or Target) rather than an error — the
// connector just has less to act on for that one target. Caller holds at
// least s.mu.RLock.
func (s *Server) targetJobFor(targetID string) *vaultv1.TargetJob {
	job := &vaultv1.TargetJob{TargetId: targetID}
	tgt := findByID(s.targets, targetID)
	if tgt == nil {
		return job
	}
	job.Target = &vaultv1.HeartbeatTarget{
		Kind: tgt.GetKind(), Domain: tgt.GetDomain(), Realm: tgt.GetRealm(), Hostname: tgt.GetHostname(),
		SshHostKeys: slices.Clone(tgt.GetSshHostKeys()),
	}
	if conn := findByID(s.connections, tgt.GetConnectionId()); conn != nil {
		job.Connection = &vaultv1.HeartbeatConn{
			Protocol: conn.GetProtocol(), Host: tgt.GetHostname(), Port: conn.GetPort(), UseTls: conn.GetUseTls(), KdcPort: conn.GetKdcPort(),
		}
	}
	return job
}

// targetJobsFor builds one TargetJob per attached target, primary (first)
// included. Caller holds at least s.mu.RLock.
func (s *Server) targetJobsFor(sec *vaultv1.Secret) []*vaultv1.TargetJob {
	ids := secretTargetIDs(sec)
	out := make([]*vaultv1.TargetJob, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.targetJobFor(id))
	}
	return out
}

// aggregateTargetOutcomes reports whether every entry in results is ok (true
// for an empty/nil list — a connector that hasn't moved to multi-target
// reporting carries no per-target signal to contradict the caller's own
// aggregate result), plus the outcomes themselves with "at" stamped now.
func aggregateTargetOutcomes(results []*vaultv1.TargetOutcome, now time.Time) (allOK bool, outcomes []*vaultv1.TargetOutcome) {
	if len(results) == 0 {
		return true, nil
	}
	allOK = true
	outcomes = make([]*vaultv1.TargetOutcome, 0, len(results))
	at := now.UTC().Format(time.RFC3339)
	for _, r := range results {
		if !r.GetOk() {
			allOK = false
		}
		outcomes = append(outcomes, &vaultv1.TargetOutcome{TargetId: r.GetTargetId(), Ok: r.GetOk(), Detail: r.GetDetail(), At: at})
	}
	return allOK, outcomes
}

// resolveHeartbeatResult folds a connector's per-target heartbeat outcomes
// (#168) into the secret's one aggregate result: reported stands unless it
// claims OK while some attached target isn't confirmed working, in which
// case the aggregate is downgraded to FAILED. targetResults empty means the
// connector hasn't moved to multi-target reporting, so reported is trusted
// exactly as before (outcomes is then nil — nothing to record).
func resolveHeartbeatResult(reported vaultv1.HeartbeatResult, targetResults []*vaultv1.TargetOutcome, now time.Time) (result vaultv1.HeartbeatResult, outcomes []*vaultv1.TargetOutcome) {
	allOK, outcomes := aggregateTargetOutcomes(targetResults, now)
	result = reported
	if result == vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK && !allOK {
		result = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED
	}
	return result, outcomes
}

// markTargetsUncheckedAfterPrincipalWrite marks sec's heartbeat unchecked and
// requests one now, for a principal rotate/restore that changed the vault's
// own copy without pushing or confirming it on any target (#169/#168):
// mirrors RestoreSecretVersion's human-path treatment. Caller holds s.mu
// (write lock).
func (s *Server) markTargetsUncheckedAfterPrincipalWrite(ctx context.Context, sec *vaultv1.Secret, verb string) {
	if primaryTargetID(sec) == "" {
		return
	}
	sec.LastHeartbeatResult = vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN
	sec.LastHeartbeatDetail = verb + " by a principal; not yet checked against the target"
	if s.hb != nil {
		if _, _, err := s.hb.RequestNow(ctx, sec.GetId(), 0); err != nil {
			s.lg(ctx).Error(err, "queue heartbeat after principal write failed", log.F("secret_id", sec.GetId()), log.F("verb", verb))
		}
	}
}
