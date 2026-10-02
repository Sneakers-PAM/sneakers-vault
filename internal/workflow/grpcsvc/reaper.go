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
	l := log.Ctx(ctx)
	due, err := s.store.DueLeases(ctx, nowRFC3339())
	if err != nil {
		l.Warn().Err(err).Msg("reaper: list due leases")
		return 0
	}
	n := 0
	for _, d := range due {
		if d.RunID == "" {
			continue // lease predates run tracking or was never saga-owned; nothing to signal
		}
		runID, err := uuid.Parse(d.RunID)
		if err != nil {
			l.Warn().Err(err).Str("lease_id", d.ID).Str("run_id", d.RunID).Msg("reaper: bad run id")
			continue
		}
		if err := s.saga.Signal(ctx, runID, "checkin", nil); err != nil {
			l.Warn().Err(err).Str("lease_id", d.ID).Msg("reaper: signal checkin")
			continue
		}
		n++
	}
	if n > 0 {
		l.Info().Int("count", n).Msg("reaper: reaped expired leases")
	}
	return n
}
