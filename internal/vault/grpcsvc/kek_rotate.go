// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// kekRefPattern matches the "kek-vN" refs minted by rotateOnce (never the
// legacy/dev-static refs, which keep their own naming and are never rotated
// into or retired).
var kekRefPattern = regexp.MustCompile(`^kek-v(\d+)$`)

// nextKekRef derives the next working-KEK generation's ref from the highest
// "kek-vN" ref seen across every persisted row (active or retired) — so a
// retired generation's version number is never reused.
func nextKekRef(rows []keyringRow) string {
	max := 0
	for _, r := range rows {
		m := kekRefPattern.FindStringSubmatch(r.Ref)
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > max {
			max = n
		}
	}
	return fmt.Sprintf("kek-v%d", max+1)
}

// rotationResult is the outcome of one rotateOnce: the active ref after it,
// and how many sealed records it moved onto that ref in each table.
type rotationResult struct {
	ActiveRef string
	Records   int
	Versions  int
}

// Total is every re-wrapped row (secret_records + secret_versions).
func (r rotationResult) Total() int { return r.Records + r.Versions }

// rotateOnce mints a new working-KEK generation, makes it active, and eagerly
// re-wraps every sealed row still on an older generation (including data
// sealed with the static dev key, dev-static-v1), in this order:
//
//  1. insert the new generation (durable before anything is sealed under it);
//     2-3. re-wrap secret_records (sweepRewrap) and persist them, as one writeTx
//     so the sweep runs on fresh state — errRotationPersist on failure;
//  4. re-wrap secret_versions in the database, batched (sweepVersions) —
//     errVersionSweep on failure;
//  5. stamp retired_at on generations nothing references any more.
//
// Every failure leaves each row on a ref the keyring still holds (no
// generation is ever deleted), so reads keep working, and every step is
// idempotent: re-running RotateKek finishes whatever a failed run left.
// Shared by the RotateKek RPC and the scheduler. s.rotating guards against
// two rotations running concurrently (a second caller gets a benign no-op
// reporting the current active ref).
func (s *Server) rotateOnce(ctx context.Context) (rotationResult, error) {
	if !s.rotating.CompareAndSwap(false, true) {
		return rotationResult{ActiveRef: s.keyring.ActiveRef()}, nil
	}
	defer s.rotating.Store(false)

	rows, err := s.keyringStore.Load(ctx)
	if err != nil {
		return rotationResult{}, fmt.Errorf("load keyring: %w", err)
	}
	newRef := nextKekRef(rows)

	raw, err := crypto.RandKey()
	if err != nil {
		return rotationResult{}, fmt.Errorf("generate working KEK: %w", err)
	}
	wrapped, _, err := s.root.WrapDEK(raw)
	if err != nil {
		return rotationResult{}, fmt.Errorf("wrap working KEK under root: %w", err)
	}
	if err := s.keyringStore.InsertActive(ctx, newRef, wrapped, s.rootRef); err != nil {
		return rotationResult{}, fmt.Errorf("insert active keyring generation: %w", err)
	}
	s.keyring.Add(crypto.WorkingKey{Ref: newRef, Key: raw}, true)

	res := rotationResult{ActiveRef: newRef}
	// The sweep and its persist are one writeTx: re-wrapping a stale
	// snapshot and persisting it would delete every secret a peer wrote since.
	err = s.writeTx(ctx, func(ctx context.Context) error {
		var serr error
		res.Records, serr = s.sweepRewrap(ctx)
		return serr
	})
	switch {
	case errors.Is(err, errStatePersist):
		return res, fmt.Errorf("%w: %w", errRotationPersist, err)
	case err != nil:
		return res, fmt.Errorf("sweep re-wrap: %w", err)
	}
	if s.store != nil {
		s.publishInvalidate(ctx, "RotateKek", "")
	}
	res.Versions, err = s.sweepVersions(ctx)
	if err != nil {
		return res, fmt.Errorf("%w: %w", errVersionSweep, err)
	}
	if err := s.retireUnreferenced(ctx); err != nil {
		// Bookkeeping only (retired_at); every row is already durable on the
		// new ref, so report it without failing the rotation.
		l := s.lg(ctx)
		l.Warn("rotate KEK: retire unreferenced generations failed", log.F("error", err.Error()), log.F("active_ref", newRef))
	}
	return res, nil
}

// sweepRewrap re-wraps (in memory) every secret_record not already on the
// keyring's active ref; rotateOnce persists the result. It snapshots the
// candidate id list under a brief lock (mirroring CreateSecret/UpdateSecret's
// locking) and then rewraps one record at a time, re-acquiring the lock per
// id, so a single slow/failing record never holds s.mu for the whole sweep. Fail-safe: on the first RewrapDEK
// error it returns immediately, leaving that record (and everything after it)
// on its current KEK — safe, and resumable by simply calling sweepRewrap
// again (only records not yet on the active ref are touched, so a partial or
// repeat run is a no-op past what already succeeded).
func (s *Server) sweepRewrap(ctx context.Context) (int, error) {
	s.mu.Lock()
	active := s.keyring.ActiveRef()
	ids := make([]string, 0, len(s.records))
	for id, rec := range s.records {
		if rec.KeyRef != active {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()

	count := 0
	for _, id := range ids {
		s.mu.Lock()
		rec, ok := s.records[id]
		if !ok || rec.KeyRef == s.keyring.ActiveRef() {
			s.mu.Unlock()
			continue
		}
		rr, rewrapErr := s.crypt.RewrapDEK(rec)
		if rewrapErr != nil {
			s.mu.Unlock()
			return count, fmt.Errorf("rewrap record %s: %w", id, rewrapErr)
		}
		s.records[id] = rr
		s.mu.Unlock()
		count++
	}
	return count, nil
}

// retireUnreferenced stamps retired_at on every non-active keyring generation
// that neither an in-memory record nor a stored secret_versions row
// references any more. Best-effort bookkeeping only — it never touches a
// record, and retired generations stay in the keyring (decrypt-only).
func (s *Server) retireUnreferenced(ctx context.Context) error {
	s.mu.RLock()
	referenced := make(map[string]bool, len(s.records))
	for _, rec := range s.records {
		referenced[rec.KeyRef] = true
	}
	s.mu.RUnlock()
	if s.vers != nil {
		vrefs, err := s.vers.versionRefs(ctx)
		if err != nil {
			return fmt.Errorf("load version refs for retirement: %w", err)
		}
		for ref := range vrefs {
			referenced[ref] = true
		}
	}

	rows, err := s.keyringStore.Load(ctx)
	if err != nil {
		return fmt.Errorf("load keyring for retirement: %w", err)
	}
	for _, row := range rows {
		if row.Active || referenced[row.Ref] {
			continue
		}
		if err := s.keyringStore.Retire(ctx, row.Ref); err != nil {
			return fmt.Errorf("retire %s: %w", row.Ref, err)
		}
	}
	return nil
}

// RotateKek mints a new working-KEK generation, makes it active, and eagerly
// re-wraps every secret_records and secret_versions row onto it. This is
// how operators move data sealed with the static dev key (dev-static-v1) onto
// a working key before dropping it from the keyring. Two callers
// are allowed:
//
//   - a human site-admin/root (isHumanAdmin; admin authority is human-only);
//   - an allowlisted SYSTEM principal: PrincipalKind WORKLOAD with a user_id
//     exactly in VAULT_KEK_ROTATION_PRINCIPALS (isKekRotationPrincipal). This
//     lets rotation run under a system account that is not tied to a person's
//     identity. It grants RotateKek only, and SERVICE_ACCOUNT is never accepted.
//
// It persists its own outcome synchronously and is NOT in mutatingMethods:
// PersistUnary only logs a persist failure, which would report a re-wrap that
// never reached the database as a success. Rewrapped in the response is
// records + versions. The kek.rotate audit event records the caller id, the
// principal_kind/rotated_by/trigger of the rotation, the active ref, per-table
// counts and the outcome. It never records key material.
func (s *Server) RotateKek(ctx context.Context, req *vaultv1.RotateKekRequest) (*vaultv1.RotateKekResponse, error) {
	actor := req.GetActor()
	var principalKind, rotatedBy string
	switch {
	case isHumanAdmin(actor):
		principalKind, rotatedBy = "human", "human"
	case s.isKekRotationPrincipal(actor):
		principalKind, rotatedBy = "workload", "system"
	default:
		return nil, status.Error(codes.PermissionDenied, "rotate KEK requires site-admin or an allowlisted system principal")
	}

	res, err := s.rotateOnce(ctx)
	attrs := rotationAttrs(res, err, principalKind, rotatedBy, "rpc")
	if err != nil {
		l := s.lg(ctx)
		l.Error(err, "rotate KEK failed; every row remains readable under the generation it is on — retry RotateKek to finish", log.F("active_ref", res.ActiveRef), log.F("outcome", attrs["outcome"]), log.F("actor", actor.GetUserId()), log.F("rotated_by", rotatedBy), log.F("rewrapped_records", res.Records), log.F("rewrapped_versions", res.Versions))
		if res.ActiveRef != "" {
			s.emitAttrs(ctx, actor.GetUserId(), "kek.rotate", "", false, attrs)
		}
		return nil, status.Errorf(codes.Internal,
			"rotate KEK (%s, active %s, %d records + %d versions re-wrapped): every row remains readable under its current generation; retry RotateKek: %v",
			attrs["outcome"], res.ActiveRef, res.Records, res.Versions, err)
	}

	s.emitAttrs(ctx, actor.GetUserId(), "kek.rotate", "", false, attrs)
	return &vaultv1.RotateKekResponse{ActiveRef: res.ActiveRef, Rewrapped: safeconv.Int32(res.Total())}, nil
}

// rotationAttrs builds the kek.rotate audit attributes shared by the RPC and
// the scheduler: refs, counts, outcome, and who rotated and how. principalKind
// is "human" or "workload", rotatedBy is "human" or "system", and trigger is
// "rpc" or "scheduler". Never key material.
func rotationAttrs(res rotationResult, err error, principalKind, rotatedBy, trigger string) map[string]string {
	return map[string]string{
		"active_ref":         res.ActiveRef,
		"rewrapped":          strconv.Itoa(res.Total()),
		"rewrapped_records":  strconv.Itoa(res.Records),
		"rewrapped_versions": strconv.Itoa(res.Versions),
		"outcome":            rotationOutcome(err),
		"principal_kind":     principalKind,
		"rotated_by":         rotatedBy,
		"trigger":            trigger,
	}
}

// rotationOutcome classifies a rotateOnce error for the audit trail.
func rotationOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, errRotationPersist):
		return "persist_failed"
	case errors.Is(err, errVersionSweep):
		return "version_sweep_failed"
	default:
		return "failed"
	}
}
