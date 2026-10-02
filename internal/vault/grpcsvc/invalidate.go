// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	log "github.com/Bugs5382/go-log"
	bredis "github.com/Bugs5382/go-redis"
)

// DefaultInvalidateChannel is the Redis pub/sub channel vault uses to broadcast
// cache invalidations to its replicas.
const DefaultInvalidateChannel = "vault:invalidate"

const (
	// defaultInvDebounce coalesces a burst of peer writes into a single reload.
	defaultInvDebounce = 200 * time.Millisecond
	// defaultInvBackoff is the pause before the subscriber re-subscribes after a
	// connection error (the common Redis/RabbitMQ "no-reconnect" footgun is
	// avoided by always looping back through Subscribe here, never dying on a
	// single receive error).
	defaultInvBackoff = 2 * time.Second
)

// invalidation is the small JSON payload published on every durable mutation.
// The subscriber reloads the FULL state regardless of the fields; Kind/ID/Origin
// are carried only for observability (logs/tracing).
type invalidation struct {
	Origin string `json:"origin"`         // publishing instance id
	Kind   string `json:"kind,omitempty"` // RPC/entity that mutated
	ID     string `json:"id,omitempty"`   // affected entity id, when known
	TS     int64  `json:"ts"`             // publish time (unix nanos)
}

// SetInvalidation wires the Redis pub/sub cache-invalidation transport. A nil
// client (empty REDIS_URL, or an unreachable Redis at boot) is tolerated: the
// publisher and subscriber become no-ops and vault keeps serving with the legacy
// single-replica behaviour. Called from cmd/vault after Redis is dialled.
func (s *Server) SetInvalidation(rc *bredis.Client, channel string) {
	if channel == "" {
		channel = DefaultInvalidateChannel
	}
	s.redis = rc
	s.invChannel = channel
	s.instanceID = instanceID()
	if s.invDebounceD == 0 {
		s.invDebounceD = defaultInvDebounce
	}
	if s.invBackoffD == 0 {
		s.invBackoffD = defaultInvBackoff
	}
}

// instanceID identifies this replica in invalidation payloads (host + pid). It
// is best-effort/observability-only, so a hostname lookup failure is ignored.
func instanceID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "vault"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// publishInvalidate broadcasts a cache-invalidation to all replicas. It MUST be
// called with s.mu NOT held (it performs a network round-trip). A publish error
// is logged, not returned: the mutation is already durable, and peers reconverge
// on the next invalidation or a restart. No-op when Redis is not wired.
func (s *Server) publishInvalidate(ctx context.Context, kind, id string) {
	if s.redis == nil || s.invChannel == "" {
		return
	}
	payload, err := json.Marshal(invalidation{
		Origin: s.instanceID, Kind: kind, ID: id, TS: time.Now().UnixNano(),
	})
	if err != nil { // unreachable for these fields, but never panic on the write path
		return
	}
	if perr := s.redis.Redis().Publish(ctx, s.invChannel, payload).Err(); perr != nil {
		l := log.Ctx(ctx)
		l.Warn().Err(perr).Str("channel", s.invChannel).Msg("vault invalidate publish failed")
	}
}

// reload re-reads the full persisted state from the store and swaps it into the
// in-memory slices under the write lock, so a replica converges on the latest
// durable state after a peer's mutation. It reuses the existing store.Load +
// hydrate path (one load code path for boot and reload). A load error leaves the
// current in-memory state untouched (prefer stale-but-serving over dropping the
// dataset); an empty store is a no-op.
//
// After hydrating records, it also reconciles the in-memory KEK keyring: hydrate alone swaps in records a peer's RotateKek rewrapped
// onto a new working-KEK generation, but never refreshes s.keyring itself, so
// without this every reveal on this replica would fail against a ref it
// never learned about. A reconcile error is logged, not returned — it never
// crashes the invalidation subscriber, and a subsequent reveal still fails
// closed against any generation this replica couldn't unwrap, which is the
// correct, safe behaviour.
//
// It takes writeMu so a reload never interleaves with a write on this replica:
// a reload that loaded before a write's commit must not hydrate over it.
func (s *Server) reload(ctx context.Context) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.refresh(ctx, s.store)
}

// refresh loads st and hydrates it, then reconciles the keyring (see reload).
// writeTx calls it with the lock-holding transaction's Store before every
// write, so each write starts from the latest committed state.
func (s *Server) refresh(ctx context.Context, st Store) error {
	loaded, empty, err := st.Load(ctx)
	if err != nil {
		return err
	}
	if empty {
		return nil
	}
	s.mu.Lock()
	s.hydrate(loaded)
	s.mu.Unlock()
	if rerr := s.reconcileKeyring(ctx); rerr != nil {
		l := log.Ctx(ctx)
		l.Warn().Err(rerr).Msg("vault reconcile keyring after reload failed")
	}
	return nil
}

// RunInvalidationSubscriber runs the replica's background cache-invalidation
// subscriber until ctx is cancelled. It is resilient by design: a receive error
// (Redis restart, network blip) never kills the subscriber — it re-subscribes
// after a short backoff. Reloads are handled by a dedicated worker fed through a
// size-1 trigger channel, so a burst of peer writes coalesces into a single
// store reload (debounced) and the network read never blocks on reload work.
// No-op (returns immediately) when Redis is not wired. Intended to be launched
// in its own goroutine.
func (s *Server) RunInvalidationSubscriber(ctx context.Context) {
	l := log.Ctx(ctx)
	if s.redis == nil || s.invChannel == "" {
		l.Warn().Msg("vault invalidate subscriber disabled: no Redis (single-replica reads only)")
		return
	}
	trigger := make(chan struct{}, 1)
	go s.reloadWorker(ctx, trigger)
	for ctx.Err() == nil {
		err := s.subscribeLoop(ctx, trigger)
		if ctx.Err() != nil {
			return
		}
		l.Warn().Err(err).Msg("vault invalidate subscription lost; reconnecting")
		if !sleepCtx(ctx, s.invBackoffD) {
			return
		}
	}
}

// subscribeLoop subscribes and forwards every received message to the reload
// worker via a non-blocking send (a pending trigger already covers this write).
// It returns the receive error so RunInvalidationSubscriber can reconnect.
func (s *Server) subscribeLoop(ctx context.Context, trigger chan<- struct{}) error {
	sub := s.redis.Redis().Subscribe(ctx, s.invChannel)
	defer func() { _ = sub.Close() }()
	l := log.Ctx(ctx)
	l.Info().Str("channel", s.invChannel).Msg("vault invalidate subscriber connected")
	for {
		if _, err := sub.ReceiveMessage(ctx); err != nil {
			return err
		}
		select {
		case trigger <- struct{}{}:
		default: // a reload is already pending → coalesced
		}
	}
}

// reloadWorker debounces trigger signals and reloads the store once per burst.
func (s *Server) reloadWorker(ctx context.Context, trigger <-chan struct{}) {
	l := log.Ctx(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-trigger:
			if !sleepCtx(ctx, s.invDebounceD) {
				return
			}
			select { // drain a trigger that arrived during the debounce window
			case <-trigger:
			default:
			}
			if err := s.reload(ctx); err != nil {
				l.Warn().Err(err).Msg("vault reload after invalidate failed")
			}
		}
	}
}

// sleepCtx sleeps for d, returning false if ctx is cancelled first (or already).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
