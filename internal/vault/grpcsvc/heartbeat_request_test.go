// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newHeartbeatTestServer(t *testing.T) (*Server, *capAudit, string) {
	t.Helper()
	s, ca, secID := newRotationServer(t)
	s.hb = newHeartbeatStore(s.rot.db)
	if _, err := s.rot.db.Exec(context.Background(), "TRUNCATE heartbeat_schedule"); err != nil {
		t.Fatal(err)
	}
	if err := s.hb.Ensure(context.Background(), secID, 3600); err != nil {
		t.Fatal(err)
	}
	if err := s.hb.Reschedule(context.Background(), secID, s.clock().Add(3600e9)); err != nil {
		t.Fatal(err)
	}
	return s, ca, secID
}

var hbReader = tokenActor("user-carol", false)

func requestHB(s *Server, actor *vaultv1.ActorContext, id string) error {
	_, err := s.RequestHeartbeatForPrincipal(context.Background(), &vaultv1.RequestHeartbeatForPrincipalRequest{Actor: actor, SecretId: id})
	return err
}

func hbStatus(t *testing.T, s *Server, id string) *vaultv1.GetHeartbeatStatusForPrincipalResponse {
	t.Helper()
	r, err := s.GetHeartbeatStatusForPrincipal(context.Background(), &vaultv1.GetHeartbeatStatusForPrincipalRequest{Actor: hbReader, SecretId: id})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	return r
}

func TestRequestHeartbeatMakesItDueAndIsRateLimited(t *testing.T) {
	s, ca, id := newHeartbeatTestServer(t)
	if hbStatus(t, s, id).GetPending() {
		t.Fatal("precondition: nothing pending before the request")
	}
	if err := requestHB(s, hbReader, id); err != nil {
		t.Fatalf("request: %v", err)
	}
	if !hbStatus(t, s, id).GetPending() {
		t.Fatal("a requested heartbeat must be pending")
	}
	due, err := s.hb.ClaimDue(context.Background(), 10, 60e9)
	if err != nil || len(due) != 1 || due[0] != id {
		t.Fatalf("the connector's next claim = %v, %v; want the requested secret", due, err)
	}
	if ev := ca.find("heartbeat.request.principal"); ev == nil || ev.ActorUserID != "user-carol" {
		t.Fatalf("request audit = %+v", ev)
	}
	if err := requestHB(s, hbReader, id); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second request within a minute: want ResourceExhausted, got %v", err)
	}
	if _, err := s.rot.db.Exec(context.Background(), `UPDATE heartbeat_schedule SET last_manual_at = now() - interval '61 seconds', claimed_until = NULL`); err != nil {
		t.Fatal(err)
	}
	if err := requestHB(s, hbReader, id); err != nil {
		t.Fatalf("request after the minute: %v", err)
	}
}

func TestRequestHeartbeatRefusals(t *testing.T) {
	s, _, id := newHeartbeatTestServer(t)
	if err := requestHB(s, tokenActor("user-eve", false), id); status.Code(err) != codes.PermissionDenied {
		t.Errorf("no read: want PermissionDenied, got %v", err)
	}
	if err := requestHB(s, &vaultv1.ActorContext{UserId: "user-carol"}, id); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a person on the principal path: want PermissionDenied, got %v", err)
	}
	if err := s.hb.Remove(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := requestHB(s, hbReader, id); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("no scheduled heartbeat: want FailedPrecondition, got %v", err)
	}
}

func TestHeartbeatStatusCarriesTheResultAndReason(t *testing.T) {
	s, _, id := newHeartbeatTestServer(t)
	if err := requestHB(s, hbReader, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.hb.ClaimDue(context.Background(), 10, 60e9); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReportHeartbeat(context.Background(), &vaultv1.ReportHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "w"}, SecretId: id,
		Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, Detail: "LDAP bind: invalid credentials " + strings.Repeat("x", 2000),
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	st := hbStatus(t, s, id)
	if st.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED || st.GetPending() || st.GetCheckedAtUnix() == 0 ||
		!strings.HasPrefix(st.GetDetail(), "LDAP bind: invalid credentials") || len(st.GetDetail()) > 512 {
		t.Fatalf("status = result %v pending %v checked %d detail %d chars", st.GetResult(), st.GetPending(), st.GetCheckedAtUnix(), len(st.GetDetail()))
	}
	if _, err := s.GetHeartbeatStatusForPrincipal(context.Background(), &vaultv1.GetHeartbeatStatusForPrincipalRequest{Actor: tokenActor("user-eve", false), SecretId: id}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status without read: want PermissionDenied, got %v", err)
	}
}

type hbRow struct {
	next, lastManual, claimed any
}

func readHBRow(t *testing.T, s *Server, id string) hbRow {
	t.Helper()
	var r hbRow
	if err := s.rot.db.QueryRow(context.Background(),
		`SELECT next_heartbeat_at, last_manual_at, claimed_until FROM heartbeat_schedule WHERE secret_id = $1`, id,
	).Scan(&r.next, &r.lastManual, &r.claimed); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRequestHeartbeatWithoutVerifierFailsFastAndLeavesTheRow(t *testing.T) {
	s, ca, id := newHeartbeatTestServer(t)
	s.wid = nil
	before := readHBRow(t, s, id)
	err := requestHB(s, hbReader, id)
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.HasPrefix(status.Convert(err).Message(), "no connector is available in this environment") {
		t.Fatalf("no verifier: want FailedPrecondition \"no connector is available in this environment...\", got %v", err)
	}
	if after := readHBRow(t, s, id); after != before {
		t.Fatalf("heartbeat row changed with no verifier: before %+v after %+v", before, after)
	}
	if ca.find("heartbeat.request.principal") != nil {
		t.Fatal("a refused request must not be audited as a request")
	}
	if hbStatus(t, s, id).GetPending() {
		t.Fatal("status must not be pending when no connector can serve the check")
	}
}

func TestRequestHeartbeatWithoutVerifierStillChecksAccessFirst(t *testing.T) {
	s, _, id := newHeartbeatTestServer(t)
	s.wid = nil
	if err := requestHB(s, tokenActor("user-eve", false), id); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no read and no verifier: want PermissionDenied, got %v", err)
	}
}

func TestHeartbeatStatusWithoutVerifierIsNeverPendingAndKeepsTheResult(t *testing.T) {
	s, _, id := newHeartbeatTestServer(t)
	if _, err := s.ReportHeartbeat(context.Background(), &vaultv1.ReportHeartbeatRequest{
		Identity: &vaultv1.WorkerIdentity{Token: "w"}, SecretId: id,
		Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK, Detail: "bind ok",
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if _, err := s.rot.db.Exec(context.Background(), `UPDATE heartbeat_schedule SET next_heartbeat_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	if !hbStatus(t, s, id).GetPending() {
		t.Fatal("precondition: a due row is pending while a verifier is installed")
	}
	s.wid = nil
	st := hbStatus(t, s, id)
	if st.GetPending() {
		t.Fatal("a due row must not read as pending when no connector can serve it")
	}
	if st.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK || st.GetDetail() != "bind ok" || st.GetCheckedAtUnix() == 0 {
		t.Fatalf("stored result lost: result %v detail %q checked %d", st.GetResult(), st.GetDetail(), st.GetCheckedAtUnix())
	}
}
