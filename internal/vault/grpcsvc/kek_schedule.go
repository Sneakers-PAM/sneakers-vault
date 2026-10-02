// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
)

// kekRotationDue reports whether the active KEK generation (created
// activeCreatedAt) has aged past rotationDays as of now. Pure so it can be
// table-tested without a server/store. rotationDays<=0 means auto-rotation is
// off — always false, regardless of age.
func kekRotationDue(activeCreatedAt time.Time, rotationDays int32, now time.Time) bool {
	if rotationDays <= 0 {
		return false
	}
	return now.Sub(activeCreatedAt) >= time.Duration(rotationDays)*24*time.Hour
}

// RunKekScheduler runs vault's automatic KEK-rotation check on a
// time.Ticker(checkEvery) loop until ctx is cancelled (mirrors
// RunInvalidationSubscriber's ctx.Done()-honoring shape). Each tick delegates
// to kekSchedulerTick, which does the actual read-settings/read-active/rotate
// work and its own logging; a tick error is already logged there, so this
// loop just keeps ticking. Intended to be launched in its own goroutine (see
// cmd/vault/main.go).
func (s *Server) RunKekScheduler(ctx context.Context, checkEvery time.Duration) {
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.kekSchedulerTick(ctx)
		}
	}
}

// kekSchedulerTick is one evaluation of the auto-rotation check, factored out
// of RunKekScheduler so it can be unit-tested directly without a real ticker
// loop. It reads the effective kek_rotation_days (settings guarded by s.mu,
// same locking as GetSecuritySettings) and the active keyring generation's
// age, and — when due — calls the same rotateOnce RotateKek's RPC handler
// uses (whose own s.rotating guard makes an overlapping tick a safe no-op).
// Like the RPC path, a successful rotation is persisted inside rotateOnce
// and a persist failure is returned (and logged at error), never swallowed.
// Every log line carries refs/counts only, never key material.
func (s *Server) kekSchedulerTick(ctx context.Context) error {
	l := log.Ctx(ctx)

	s.mu.RLock()
	days := s.settings.GetKekRotationDays()
	s.mu.RUnlock()
	if days <= 0 {
		return nil // auto-rotation off
	}

	row, ok, err := s.keyringStore.Active(ctx)
	if err != nil {
		l.Warn().Err(err).Msg("kek scheduler: read active keyring generation failed")
		return err
	}
	if !ok {
		l.Warn().Msg("kek scheduler: no active keyring generation found")
		return nil
	}

	if !kekRotationDue(row.CreatedAt, days, time.Now()) {
		return nil
	}

	// rotateOnce persists the re-wraps itself (as a writeTx, then it
	// publishes the invalidation peers need) and sweeps secret_versions; any
	// failure is returned and logged at error, never swallowed.
	res, err := s.rotateOnce(ctx)
	// Automatic rotations are audited too, as the reserved SYSTEM principal
	// kekSchedulerPrincipal (same kek.rotate action and attrs as the RPC,
	// trigger=scheduler). Like the RPC, a failure before any generation was
	// minted (empty ActiveRef) is only logged.
	if res.ActiveRef != "" {
		s.emitAttrs(ctx, kekSchedulerPrincipal, "kek.rotate", "", false,
			rotationAttrs(res, err, "workload", "system", "scheduler"))
	}
	if err != nil {
		l.Error().Err(err).Str("active_ref", res.ActiveRef).Str("outcome", rotationOutcome(err)).
			Msg("kek scheduler: rotation failed; every row remains readable under the generation it is on")
		return err
	}

	l.Info().Str("active_ref", res.ActiveRef).Int32("rewrapped_records", safeconv.Int32(res.Records)).
		Int32("rewrapped_versions", safeconv.Int32(res.Versions)).Msg("kek scheduler: rotated")
	return nil
}
