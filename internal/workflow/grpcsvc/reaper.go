// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/google/uuid"
)

// RunReaper ticks every interval, sweeping leases whose expiry has passed
// without an explicit check-in. Each due lease with a saga run is signaled
// "checkin" — driving the existing checkout saga through rotate-on-checkin
// and close_lease, so an expired-but-never-returned lease still rotates the
// credential and closes cleanly. Blocks until ctx is done.
func (s *Server) RunReaper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reapOnce(ctx)
		}
	}
}

// reapOnce performs one sweep and returns the number of leases signaled.
func (s *Server) reapOnce(ctx context.Context) int {
	l := s.lg(ctx)
	if s.maint.On() {
		l.Debug("reaper: paused for read-only maintenance")
		return 0
	}
	due, err := s.store.DueLeases(ctx, nowRFC3339())
	if err != nil {
		l.Warn("reaper: list due leases", log.F("error", err.Error()))
		return 0
	}
	n := 0
	for _, d := range due {
		if d.RunID == "" {
			continue // lease predates run tracking or was never saga-owned; nothing to signal
		}
		runID, err := uuid.Parse(d.RunID)
		if err != nil {
			l.Warn("reaper: bad run id", log.F("error", err.Error()), log.F("lease_id", d.ID), log.F("run_id", d.RunID))
			continue
		}
		lease, _ := s.store.LeaseByRun(ctx, d.RunID)
		if err := s.saga.Signal(ctx, runID, "checkin", nil); err != nil {
			l.Warn("reaper: signal checkin", log.F("error", err.Error()), log.F("lease_id", d.ID))
			continue
		}
		if lease != nil {
			s.emit(ctx, "system:workflow", "lease.expire", lease.GetSecretId(), map[string]string{
				"lease_id": lease.GetId(), "user_id": lease.GetUserId(), "expires_at": lease.GetExpiresAt(),
			})
		}
		n++
	}
	if n > 0 {
		l.Info("reaper: reaped expired leases", log.F("count", n))
	}
	return n
}
