// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Break-glass browse. A human site admin or root opens a short-lived session
// with a reason and a fresh MFA; while it is open they can list every folder
// and secret, other users' personal folders included, as metadata only. Each
// value they reveal goes through BreakGlassSecret with the session id, so the
// owner notification, forced rotation and per-reveal audit are unchanged. The
// session itself is audited as one break_glass.entered and one
// break_glass.left event, and the ledger rows carry the session id so the
// audit view can expand a session to every secret revealed in it. A session
// grants no edit or manage rights.
package grpcsvc

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// breakGlassSessionTTL is how long a browse session stays open.
	breakGlassSessionTTL = 15 * time.Minute
	// breakGlassReasonMax caps the reason, in characters.
	breakGlassReasonMax = 500
	// ReasonBreakGlassSessionClosed refuses a call naming a session that isn't
	// open, isn't the caller's, or is bound to another web session.
	ReasonBreakGlassSessionClosed = "BREAK_GLASS_SESSION_CLOSED"
)

// How a session ended.
const (
	btgEndExit     = "exit"
	btgEndExpired  = "expired"
	btgEndReplaced = "replaced"
)

func (s *Server) breakGlassStoreOrUnavailable() (*breakGlassStore, error) {
	if s.bg == nil {
		return nil, status.Error(codes.Unavailable, "break-glass browse needs the vault database")
	}
	return s.bg, nil
}

func errBreakGlassClosed() error {
	return refuseCode(codes.FailedPrecondition, ReasonBreakGlassSessionClosed, "the break-glass session is not open")
}

// ownsSession reports whether a may use sess: the same person, from the web
// session it was opened in.
func ownsSession(a *vaultv1.ActorContext, sess btgSession) bool {
	return sess.Actor == a.GetUserId() && a.GetSessionRef() != "" && sess.SessionRef == a.GetSessionRef()
}

// liveBreakGlassSession returns a's open, unexpired session id, or refuses.
func (s *Server) liveBreakGlassSession(ctx context.Context, a *vaultv1.ActorContext, id, method string) (btgSession, error) {
	bg, err := s.breakGlassStoreOrUnavailable()
	if err != nil {
		return btgSession{}, err
	}
	if err := s.requireSiteAdmin(ctx, a, method); err != nil {
		return btgSession{}, err
	}
	sess, ok, err := bg.GetSession(ctx, id)
	if err != nil {
		return btgSession{}, status.Errorf(codes.Internal, "load break-glass session: %v", err)
	}
	if !ok || !ownsSession(a, sess) || !sess.open() || !s.clock().Before(sess.ExpiresAt) {
		s.lg(ctx).Warn("break-glass session refused", log.F("method", method), log.F("session_id", id),
			log.F("user_id", a.GetUserId()), log.F("found", ok))
		return btgSession{}, errBreakGlassClosed()
	}
	return sess, nil
}

// endBreakGlassSession ends sess and, when this call is the one that ended
// it, records the single break_glass.left event.
func (s *Server) endBreakGlassSession(ctx context.Context, sess btgSession, how string, at time.Time) (btgSession, error) {
	l := s.lg(ctx)
	ended, err := s.bg.EndSession(ctx, sess.ID, how, at)
	if err != nil {
		l.Error(err, "break-glass: end session failed", log.F("session_id", sess.ID))
		return sess, status.Errorf(codes.Internal, "end break-glass session: %v", err)
	}
	if !ended {
		l.Debug("break-glass session already ended", log.F("session_id", sess.ID))
		cur, ok, err := s.bg.GetSession(ctx, sess.ID)
		if err == nil && ok {
			return cur, nil
		}
		return sess, nil
	}
	sess.EndedAt, sess.EndReason = at, how
	reveals, err := s.bg.RevealsIn(ctx, []string{sess.ID})
	if err != nil {
		l.Error(err, "break-glass: count session reveals failed", log.F("session_id", sess.ID))
	}
	if err := s.emitTierErr(ctx, audit.TierAudit, sess.Actor, "break_glass.left", sess.ID, true, map[string]string{
		"end_reason": how, "reason": sess.Reason, "reveals": strconv.Itoa(len(reveals)),
	}); err != nil {
		l.Error(err, "break-glass: record left event failed", log.F("session_id", sess.ID))
	}
	l.Info("break-glass session ended", log.F("session_id", sess.ID), log.F("user_id", sess.Actor),
		log.F("end_reason", how), log.F("reveals", len(reveals)))
	return sess, nil
}

// OpenBreakGlassSession opens a browse session for a human site admin or root
// with a reason, a web session reference and a fresh MFA. A session the
// caller still has open ends first, as replaced. The entered event is
// recorded fail-closed: without it no session is left open.
func (s *Server) OpenBreakGlassSession(ctx context.Context, req *vaultv1.OpenBreakGlassSessionRequest) (*vaultv1.OpenBreakGlassSessionResponse, error) {
	a := req.GetActor()
	l := s.lg(ctx)
	l.Debug("break-glass open requested", log.F("user_id", a.GetUserId()))
	bg, err := s.breakGlassStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	if err := s.requireSiteAdmin(ctx, a, "OpenBreakGlassSession"); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.GetReason())
	switch {
	case reason == "":
		return nil, status.Error(codes.InvalidArgument, "a reason is required to break glass")
	case utf8.RuneCountInString(reason) > breakGlassReasonMax:
		return nil, status.Errorf(codes.InvalidArgument, "the reason is longer than %d characters", breakGlassReasonMax)
	case a.GetSessionRef() == "":
		return nil, status.Error(codes.InvalidArgument, "break-glass needs a signed-in web session")
	}
	if !s.mfaFresh(a) {
		l.Warn("break-glass open refused", log.F("reason", ReasonStepUpRequired), log.F("user_id", a.GetUserId()))
		s.emitTier(ctx, audit.TierAudit, a.GetUserId(), "break_glass.denied", "vault", false, map[string]string{
			"method": "OpenBreakGlassSession", "reason": ReasonStepUpRequired,
		})
		return nil, refuse(ReasonStepUpRequired, "confirm your MFA again to break glass")
	}

	now := s.clock()
	prior, err := bg.OpenSessionsFor(ctx, a.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load break-glass sessions: %v", err)
	}
	for _, p := range prior {
		how, at := btgEndReplaced, now
		if !now.Before(p.ExpiresAt) {
			how, at = btgEndExpired, p.ExpiresAt
		}
		if _, err := s.endBreakGlassSession(ctx, p, how, at); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	id := s.nextID("break-glass-session")
	s.mu.Unlock()
	sess := btgSession{
		ID: id, Actor: a.GetUserId(), SessionRef: a.GetSessionRef(), Reason: reason,
		OpenedAt: now, ExpiresAt: now.Add(breakGlassSessionTTL),
	}
	if err := bg.OpenSession(ctx, sess); err != nil {
		return nil, status.Errorf(codes.Internal, "record break-glass session: %v", err)
	}
	if err := s.emitTierErr(ctx, audit.TierAudit, sess.Actor, "break_glass.entered", id, true, map[string]string{
		"reason": reason, "expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		if derr := bg.DeleteSession(context.WithoutCancel(ctx), id); derr != nil {
			l.Error(derr, "break-glass: drop unaudited session failed", log.F("session_id", id))
		}
		return nil, status.Errorf(codes.Internal, "record break-glass audit: %v", err)
	}
	l.Info("break-glass session opened", log.F("session_id", id), log.F("user_id", sess.Actor),
		log.F("expires_at", sess.ExpiresAt.UTC().Format(time.RFC3339)))
	return &vaultv1.OpenBreakGlassSessionResponse{Session: btgSessionProto(sess, nil)}, nil
}

// GetBreakGlassSession returns the caller's open session bound to their web
// session, or none. A session past its expiry reads as closed.
func (s *Server) GetBreakGlassSession(ctx context.Context, req *vaultv1.GetBreakGlassSessionRequest) (*vaultv1.GetBreakGlassSessionResponse, error) {
	a := req.GetActor()
	bg, err := s.breakGlassStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	if err := s.requireSiteAdmin(ctx, a, "GetBreakGlassSession"); err != nil {
		return nil, err
	}
	open, err := bg.OpenSessionsFor(ctx, a.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load break-glass sessions: %v", err)
	}
	now := s.clock()
	for _, sess := range open {
		if ownsSession(a, sess) && now.Before(sess.ExpiresAt) {
			return &vaultv1.GetBreakGlassSessionResponse{Session: btgSessionProto(sess, nil)}, nil
		}
	}
	return &vaultv1.GetBreakGlassSessionResponse{}, nil
}

// ListBreakGlassItems lists every folder and every live secret, metadata
// only, while the caller's session is open. Folders never come back
// manageable: break-glass grants no edit or manage rights.
func (s *Server) ListBreakGlassItems(ctx context.Context, req *vaultv1.ListBreakGlassItemsRequest) (*vaultv1.ListBreakGlassItemsResponse, error) {
	a := req.GetActor()
	if _, err := s.liveBreakGlassSession(ctx, a, req.GetSessionId(), "ListBreakGlassItems"); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	folders := make([]*vaultv1.Folder, 0, len(s.folders))
	for _, f := range s.folders {
		cp := proto.Clone(f).(*vaultv1.Folder)
		cp.SubtreeSecretCount = s.activeSubtreeSecretCount(f.GetId())
		cp.CanManage = false
		folders = append(folders, cp)
	}
	var secrets []*vaultv1.Secret
	for _, sec := range s.secrets {
		if sec.GetRetired() || (req.GetFolderId() != "" && sec.GetFolderId() != req.GetFolderId()) {
			continue
		}
		secrets = append(secrets, withCanRead(sec, s.resolveSecret(a, sec).Read.Allowed))
	}
	s.lg(ctx).Debug("break-glass items listed", log.F("session_id", req.GetSessionId()),
		log.F("folders", len(folders)), log.F("secrets", len(secrets)))
	return &vaultv1.ListBreakGlassItemsResponse{Folders: folders, Secrets: secrets}, nil
}

// CloseBreakGlassSession ends the caller's session. Closing a session that
// already ended returns it unchanged, with no second left event.
func (s *Server) CloseBreakGlassSession(ctx context.Context, req *vaultv1.CloseBreakGlassSessionRequest) (*vaultv1.CloseBreakGlassSessionResponse, error) {
	a := req.GetActor()
	bg, err := s.breakGlassStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	if err := s.requireSiteAdmin(ctx, a, "CloseBreakGlassSession"); err != nil {
		return nil, err
	}
	sess, ok, err := bg.GetSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load break-glass session: %v", err)
	}
	if !ok || !ownsSession(a, sess) {
		s.lg(ctx).Warn("break-glass close refused", log.F("session_id", req.GetSessionId()), log.F("user_id", a.GetUserId()))
		return nil, errBreakGlassClosed()
	}
	if sess.open() {
		how, at := btgEndExit, s.clock()
		if !at.Before(sess.ExpiresAt) {
			how, at = btgEndExpired, sess.ExpiresAt
		}
		if sess, err = s.endBreakGlassSession(ctx, sess, how, at); err != nil {
			return nil, err
		}
	}
	return &vaultv1.CloseBreakGlassSessionResponse{Session: btgSessionProto(sess, nil)}, nil
}

// ListBreakGlassSessions lists sessions newest first, each with the reveals
// made in it, for the admin audit view.
func (s *Server) ListBreakGlassSessions(ctx context.Context, req *vaultv1.ListBreakGlassSessionsRequest) (*vaultv1.ListBreakGlassSessionsResponse, error) {
	bg, err := s.breakGlassStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	if err := s.requireSiteAdmin(ctx, req.GetActor(), "ListBreakGlassSessions"); err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	switch {
	case limit <= 0:
		limit = 50
	case limit > 200:
		limit = 200
	}
	sessions, err := bg.ListSessions(ctx, limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list break-glass sessions: %v", err)
	}
	ids := make([]string, len(sessions))
	for i, sess := range sessions {
		ids[i] = sess.ID
	}
	rows, err := bg.RevealsIn(ctx, ids)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list break-glass reveals: %v", err)
	}
	bySession := map[string][]*vaultv1.BreakGlassReveal{}
	s.mu.RLock()
	for _, r := range rows {
		name := ""
		if sec := s.findSecret(r.SecretID); sec != nil {
			name = sec.GetName()
		}
		bySession[r.SessionID] = append(bySession[r.SessionID], &vaultv1.BreakGlassReveal{
			EventId: r.EventID, SecretId: r.SecretID, SecretName: name, RevealedAtUnix: r.OccurredAt.Unix(),
			PostRotationScheduled: r.PostRotationScheduled, OwnerNotified: r.Notified,
		})
	}
	s.mu.RUnlock()
	out := make([]*vaultv1.BreakGlassSession, len(sessions))
	for i, sess := range sessions {
		out[i] = btgSessionProto(sess, bySession[sess.ID])
	}
	return &vaultv1.ListBreakGlassSessionsResponse{Sessions: out}, nil
}

// ExpireBreakGlassSessions ends every session past its expiry, recording its
// left event. Safe to run on every replica at once.
func (s *Server) ExpireBreakGlassSessions(ctx context.Context) error {
	if s.bg == nil {
		return nil
	}
	expired, err := s.bg.ExpiredSessions(ctx, s.clock())
	if err != nil {
		return err
	}
	for _, sess := range expired {
		if _, err := s.endBreakGlassSession(ctx, sess, btgEndExpired, sess.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

// RunBreakGlassExpiry runs ExpireBreakGlassSessions every checkEvery until ctx
// is cancelled.
func (s *Server) RunBreakGlassExpiry(ctx context.Context, checkEvery time.Duration) {
	ticker := time.NewTicker(checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ExpireBreakGlassSessions(ctx); err != nil {
				s.lg(ctx).Error(err, "break-glass: expiry sweep failed")
			}
		}
	}
}

func btgSessionProto(sess btgSession, reveals []*vaultv1.BreakGlassReveal) *vaultv1.BreakGlassSession {
	out := &vaultv1.BreakGlassSession{
		Id: sess.ID, ActorUserId: sess.Actor, Reason: sess.Reason,
		OpenedAtUnix: sess.OpenedAt.Unix(), ExpiresAtUnix: sess.ExpiresAt.Unix(),
		EndReason: sess.EndReason, Reveals: reveals,
	}
	if !sess.EndedAt.IsZero() {
		out.EndedAtUnix = sess.EndedAt.Unix()
	}
	return out
}
