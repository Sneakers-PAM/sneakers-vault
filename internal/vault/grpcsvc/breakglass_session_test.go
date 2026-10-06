// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// btgFixture is a Postgres-backed server with a fixed clock, a shared-folder
// secret (from newBreakGlassServer) and a secret in user-turing's personal
// folder that no site admin can see through ListFolders.
type btgFixture struct {
	s           *Server
	ca          *capAudit
	rn          *recNotifier
	sharedSecID string
	personalID  string
	personalSec string
	now         time.Time
}

func newBTGFixture(t *testing.T) *btgFixture {
	t.Helper()
	s, ca, rn, secID := newBreakGlassServer(t)
	ctx := context.Background()
	if _, err := s.bg.db.Exec(ctx, "TRUNCATE break_glass_sessions"); err != nil {
		t.Fatal(err)
	}
	fx := &btgFixture{s: s, ca: ca, rn: rn, sharedSecID: secID, now: time.Unix(1_800_000_000, 0)}
	s.now = func() time.Time { return fx.now }
	seedPersonalFolder(s, "user-turing")
	fx.personalID = "folder-personal-turing"
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-turing"}, Name: "turing-laptop", FolderId: fx.personalID,
		TypeId: "type-password", Fields: map[string]string{"username": "alan", "password": "Enigma#42", "notes": ""},
	})
	if err != nil {
		t.Fatalf("CreateSecret (personal): %v", err)
	}
	fx.personalSec = created.GetSecret().GetId()
	return fx
}

// btgAdmin is a human site admin with a fresh MFA, signed in to web session "web-1".
func (fx *btgFixture) btgAdmin() *vaultv1.ActorContext {
	return &vaultv1.ActorContext{
		UserId: "user-admin", IsSiteAdmin: true, SessionRef: "web-1",
		MfaVerifiedAtUnix: fx.now.Unix(),
	}
}

func (fx *btgFixture) open(t *testing.T, a *vaultv1.ActorContext) *vaultv1.BreakGlassSession {
	t.Helper()
	resp, err := fx.s.OpenBreakGlassSession(context.Background(), &vaultv1.OpenBreakGlassSessionRequest{
		Actor: a, Reason: "owner unreachable, outage",
	})
	if err != nil {
		t.Fatalf("OpenBreakGlassSession: %v", err)
	}
	return resp.GetSession()
}

func (fx *btgFixture) count(action string) int {
	fx.ca.mu.Lock()
	defer fx.ca.mu.Unlock()
	n := 0
	for _, ev := range fx.ca.events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

func btgReason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}

func TestBreakGlassSessionOpenAuditsEnteredOnce(t *testing.T) {
	fx := newBTGFixture(t)
	sess := fx.open(t, fx.btgAdmin())
	if sess.GetId() == "" || sess.GetActorUserId() != "user-admin" || sess.GetReason() != "owner unreachable, outage" {
		t.Fatalf("session = %+v", sess)
	}
	if sess.GetOpenedAtUnix() != fx.now.Unix() || sess.GetExpiresAtUnix() != fx.now.Add(breakGlassSessionTTL).Unix() {
		t.Fatalf("opened/expires = %d/%d", sess.GetOpenedAtUnix(), sess.GetExpiresAtUnix())
	}
	ev := fx.ca.find("break_glass.entered")
	if ev == nil {
		t.Fatal("no break_glass.entered audit event")
	}
	if ev.Tier != audit.TierAudit || !ev.Sensitive || ev.ActorUserID != "user-admin" || ev.Subject != sess.GetId() {
		t.Fatalf("entered event = %+v", ev)
	}
	if ev.Attributes["reason"] != "owner unreachable, outage" {
		t.Fatalf("entered reason attr = %q", ev.Attributes["reason"])
	}
	if n := fx.count("break_glass.entered"); n != 1 {
		t.Fatalf("entered events = %d, want 1", n)
	}

	got, err := fx.s.GetBreakGlassSession(context.Background(), &vaultv1.GetBreakGlassSessionRequest{Actor: fx.btgAdmin()})
	if err != nil {
		t.Fatalf("GetBreakGlassSession: %v", err)
	}
	if got.GetSession().GetId() != sess.GetId() {
		t.Fatalf("GetBreakGlassSession = %+v, want %s", got.GetSession(), sess.GetId())
	}
	other := fx.btgAdmin()
	other.SessionRef = "web-2"
	got, err = fx.s.GetBreakGlassSession(context.Background(), &vaultv1.GetBreakGlassSessionRequest{Actor: other})
	if err != nil || got.GetSession() != nil {
		t.Fatalf("another web session must not see the session: %+v %v", got.GetSession(), err)
	}
}

func TestBreakGlassSessionRefusals(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	open := func(a *vaultv1.ActorContext, reason string) error {
		_, err := fx.s.OpenBreakGlassSession(ctx, &vaultv1.OpenBreakGlassSessionRequest{Actor: a, Reason: reason})
		return err
	}

	user := fx.btgAdmin()
	user.IsSiteAdmin = false
	if err := open(user, "why"); btgReason(err) != ReasonNotSiteAdmin {
		t.Fatalf("non-admin: %v", err)
	}
	for _, kind := range []vaultv1.PrincipalKind{
		vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN, vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
	} {
		a := fx.btgAdmin()
		a.PrincipalKind = kind
		a.PrincipalId = "p-1"
		if err := open(a, "why"); btgReason(err) != ReasonNotSiteAdmin {
			t.Fatalf("%v: %v", kind, err)
		}
	}
	stale := fx.btgAdmin()
	stale.MfaVerifiedAtUnix = fx.now.Add(-time.Hour).Unix()
	if err := open(stale, "why"); btgReason(err) != ReasonStepUpRequired {
		t.Fatalf("stale MFA: %v", err)
	}
	if err := open(fx.btgAdmin(), "   "); code(err) != codes.InvalidArgument {
		t.Fatalf("blank reason: %v", err)
	}
	noRef := fx.btgAdmin()
	noRef.SessionRef = ""
	if err := open(noRef, "why"); code(err) != codes.InvalidArgument {
		t.Fatalf("no session ref: %v", err)
	}
	if n := fx.count("break_glass.entered"); n != 0 {
		t.Fatalf("refused opens wrote %d entered events", n)
	}

	// Without a session nobody can list.
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: fx.btgAdmin(), SessionId: "bgs-none"}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("list without a session: %v", err)
	}
	// Audit view is admin only.
	if _, err := fx.s.ListBreakGlassSessions(ctx, &vaultv1.ListBreakGlassSessionsRequest{Actor: user}); btgReason(err) != ReasonNotSiteAdmin {
		t.Fatalf("non-admin audit view: %v", err)
	}
}

func TestBreakGlassListShowsEveryFolderAndSecret(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()

	// Outside break-glass, the admin can't see turing's personal folder.
	plain, err := fx.s.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: admin})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plain.GetFolders() {
		if f.GetId() == fx.personalID {
			t.Fatal("setup: ListFolders must not show another user's personal folder")
		}
	}

	sess := fx.open(t, admin)
	resp, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: admin, SessionId: sess.GetId()})
	if err != nil {
		t.Fatalf("ListBreakGlassItems: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range resp.GetFolders() {
		seen[f.GetId()] = true
		if f.GetCanManage() {
			t.Fatalf("folder %s: break-glass must never grant manage", f.GetId())
		}
	}
	if !seen[fx.personalID] {
		t.Fatal("break-glass list must include another user's personal folder")
	}
	secs := map[string]*vaultv1.Secret{}
	for _, sec := range resp.GetSecrets() {
		secs[sec.GetId()] = sec
	}
	if secs[fx.personalSec] == nil || secs[fx.sharedSecID] == nil {
		t.Fatalf("break-glass list must include every secret, got %d", len(secs))
	}

	// folder_id narrows the secrets, never the folders.
	resp, err = fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: admin, SessionId: sess.GetId(), FolderId: fx.personalID})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetSecrets()) != 1 || resp.GetSecrets()[0].GetId() != fx.personalSec {
		t.Fatalf("folder filter: %+v", resp.GetSecrets())
	}
	if len(resp.GetFolders()) < 2 {
		t.Fatal("folder filter must still list every folder")
	}

	// Another web session of the same admin, or another admin, can't use it.
	other := fx.btgAdmin()
	other.SessionRef = "web-2"
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: other, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("other web session: %v", err)
	}
	second := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true, SessionRef: "web-1", MfaVerifiedAtUnix: fx.now.Unix()}
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: second, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("another admin: %v", err)
	}
}

func TestBreakGlassSessionRevealIsGroupedUnderTheSession(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()
	sess := fx.open(t, admin)

	resp, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, SessionId: sess.GetId()})
	if err != nil {
		t.Fatalf("BreakGlassSecret in session: %v", err)
	}
	if resp.GetFields()["password"] != "Enigma#42" {
		t.Fatalf("password = %q", resp.GetFields()["password"])
	}
	// The owner is alerted as for any break-glass reveal.
	if fx.rn.last == nil || fx.rn.last.Action != "secret.break_glass" || fx.rn.last.Subjects[0].Name != "user-turing" {
		t.Fatalf("owner notification = %+v", fx.rn.last)
	}
	ev := fx.ca.find("break_glass")
	if ev == nil || ev.Attributes["session_id"] != sess.GetId() || ev.Attributes["reason"] != sess.GetReason() {
		t.Fatalf("reveal event = %+v", ev)
	}
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.sharedSecID, SessionId: sess.GetId(), Reason: "the DBA account too"}); err != nil {
		t.Fatal(err)
	}
	// A reveal outside any session isn't grouped.
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, Reason: "single"}); err != nil {
		t.Fatal(err)
	}

	list, err := fx.s.ListBreakGlassSessions(ctx, &vaultv1.ListBreakGlassSessionsRequest{Actor: admin})
	if err != nil {
		t.Fatalf("ListBreakGlassSessions: %v", err)
	}
	if len(list.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(list.GetSessions()))
	}
	revs := list.GetSessions()[0].GetReveals()
	if len(revs) != 2 || revs[0].GetSecretId() != fx.personalSec || revs[1].GetSecretId() != fx.sharedSecID {
		t.Fatalf("reveals = %+v", revs)
	}
	if revs[0].GetSecretName() != "turing-laptop" || !revs[0].GetOwnerNotified() || !revs[1].GetPostRotationScheduled() {
		t.Fatalf("reveal details = %+v", revs)
	}
	for k, v := range ev.Attributes {
		if v == "Enigma#42" {
			t.Fatalf("audit attr %q leaked the value", k)
		}
	}
}

func TestBreakGlassSessionRevealRefusedOutsideAnOpenSession(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()
	sess := fx.open(t, admin)
	other := fx.btgAdmin()
	other.SessionRef = "web-2"
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: other, SecretId: fx.personalSec, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("other web session: %v", err)
	}
	if _, err := fx.s.CloseBreakGlassSession(ctx, &vaultv1.CloseBreakGlassSessionRequest{Actor: admin, SessionId: sess.GetId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("closed session: %v", err)
	}
	if fx.ca.find("break_glass") != nil {
		t.Fatal("a refused session reveal must not be recorded as a reveal")
	}
}

func TestBreakGlassSessionExitAuditsLeftOnce(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()
	sess := fx.open(t, admin)
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, SessionId: sess.GetId()}); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(time.Minute)
	closed, err := fx.s.CloseBreakGlassSession(ctx, &vaultv1.CloseBreakGlassSessionRequest{Actor: admin, SessionId: sess.GetId()})
	if err != nil {
		t.Fatalf("CloseBreakGlassSession: %v", err)
	}
	if closed.GetSession().GetEndReason() != "exit" || closed.GetSession().GetEndedAtUnix() != fx.now.Unix() {
		t.Fatalf("closed = %+v", closed.GetSession())
	}
	ev := fx.ca.find("break_glass.left")
	if ev == nil || ev.Subject != sess.GetId() || ev.Attributes["end_reason"] != "exit" || ev.Attributes["reveals"] != "1" || ev.Tier != audit.TierAudit {
		t.Fatalf("left event = %+v", ev)
	}
	// Closing again is a no-op: still exactly one left event.
	if _, err := fx.s.CloseBreakGlassSession(ctx, &vaultv1.CloseBreakGlassSessionRequest{Actor: admin, SessionId: sess.GetId()}); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if n := fx.count("break_glass.left"); n != 1 {
		t.Fatalf("left events = %d, want 1", n)
	}
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: admin, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("list after exit: %v", err)
	}
	got, err := fx.s.GetBreakGlassSession(ctx, &vaultv1.GetBreakGlassSessionRequest{Actor: admin})
	if err != nil || got.GetSession() != nil {
		t.Fatalf("no session should be open: %+v %v", got.GetSession(), err)
	}
	// Someone else can't close the admin's session.
	sess2 := fx.open(t, admin)
	root := &vaultv1.ActorContext{UserId: "user-root", IsRoot: true, SessionRef: "web-1"}
	if _, err := fx.s.CloseBreakGlassSession(ctx, &vaultv1.CloseBreakGlassSessionRequest{Actor: root, SessionId: sess2.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("closing another admin's session: %v", err)
	}
}

func TestBreakGlassSessionExpiry(t *testing.T) {
	fx := newBTGFixture(t)
	ctx := context.Background()
	admin := fx.btgAdmin()
	sess := fx.open(t, admin)

	fx.now = fx.now.Add(breakGlassSessionTTL + time.Second)
	// An expired session reads as closed straight away.
	if _, err := fx.s.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{Actor: admin, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("list after expiry: %v", err)
	}
	got, err := fx.s.GetBreakGlassSession(ctx, &vaultv1.GetBreakGlassSessionRequest{Actor: admin})
	if err != nil || got.GetSession() != nil {
		t.Fatalf("expired session must not read as open: %+v %v", got.GetSession(), err)
	}
	if _, err := fx.s.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{Actor: admin, SecretId: fx.personalSec, SessionId: sess.GetId()}); btgReason(err) != ReasonBreakGlassSessionClosed {
		t.Fatalf("reveal after expiry: %v", err)
	}

	// The sweep writes the one left event, and only once.
	if err := fx.s.ExpireBreakGlassSessions(ctx); err != nil {
		t.Fatalf("ExpireBreakGlassSessions: %v", err)
	}
	if err := fx.s.ExpireBreakGlassSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if n := fx.count("break_glass.left"); n != 1 {
		t.Fatalf("left events = %d, want 1", n)
	}
	if ev := fx.ca.find("break_glass.left"); ev.Attributes["end_reason"] != "expired" {
		t.Fatalf("left event = %+v", ev)
	}
	list, err := fx.s.ListBreakGlassSessions(ctx, &vaultv1.ListBreakGlassSessionsRequest{Actor: admin})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetSessions()) != 1 || list.GetSessions()[0].GetEndReason() != "expired" {
		t.Fatalf("sessions = %+v", list.GetSessions())
	}
}

func TestBreakGlassSessionReopenReplacesTheOpenOne(t *testing.T) {
	fx := newBTGFixture(t)
	first := fx.open(t, fx.btgAdmin())
	other := fx.btgAdmin()
	other.SessionRef = "web-2"
	second := fx.open(t, other)
	if first.GetId() == second.GetId() {
		t.Fatal("a reopen must start a new session")
	}
	if n := fx.count("break_glass.left"); n != 1 {
		t.Fatalf("left events = %d, want 1 for the replaced session", n)
	}
	if ev := fx.ca.find("break_glass.left"); ev.Subject != first.GetId() || ev.Attributes["end_reason"] != "replaced" {
		t.Fatalf("left event = %+v", ev)
	}
}

func TestBreakGlassSessionOpenFailsClosedOnAudit(t *testing.T) {
	fx := newBTGFixture(t)
	fx.s.audit = failAudit{}
	_, err := fx.s.OpenBreakGlassSession(context.Background(), &vaultv1.OpenBreakGlassSessionRequest{Actor: fx.btgAdmin(), Reason: "why"})
	if code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	fx.s.audit = fx.ca
	got, err := fx.s.GetBreakGlassSession(context.Background(), &vaultv1.GetBreakGlassSessionRequest{Actor: fx.btgAdmin()})
	if err != nil || got.GetSession() != nil {
		t.Fatalf("an unaudited open must leave no session: %+v %v", got.GetSession(), err)
	}
}

func TestBreakGlassSessionUnavailableWithoutLedger(t *testing.T) {
	s := newServer(t)
	a := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true, SessionRef: "web-1", MfaVerifiedAtUnix: time.Now().Unix()}
	_, err := s.OpenBreakGlassSession(context.Background(), &vaultv1.OpenBreakGlassSessionRequest{Actor: a, Reason: "why"})
	if code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable without the ledger store, got %v", err)
	}
}
