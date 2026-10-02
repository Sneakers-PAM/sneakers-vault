// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// SSH heartbeat and rotation jobs carry the target's host-key pins, so the
// connector can refuse a host it can't verify.

func pinTarget(t *testing.T, s *Server, targetID string, keys ...string) {
	t.Helper()
	s.mu.RLock()
	cur := findByID(s.targets, targetID)
	s.mu.RUnlock()
	tgt := &vaultv1.Target{
		Id: cur.GetId(), Name: cur.GetName(), Hostname: cur.GetHostname(), ConnectionId: cur.GetConnectionId(),
		Kind: cur.GetKind(), Domain: cur.GetDomain(), Realm: cur.GetRealm(), SshHostKeys: keys,
	}
	if _, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{Actor: siteAdmin, Target: tgt}); err != nil {
		t.Fatalf("SaveTarget pins: %v", err)
	}
}

func claimedJob(t *testing.T, s *Server, id string) *vaultv1.HeartbeatJob {
	t.Helper()
	resp, err := s.ClaimDueHeartbeats(context.Background(), &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
	if err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	for _, j := range resp.GetJobs() {
		if j.GetSecretId() == id {
			return j
		}
	}
	t.Fatalf("secret %s not claimed", id)
	return nil
}

func claimedRotation(t *testing.T, s *Server, id string) *vaultv1.RotationJob {
	t.Helper()
	if _, err := s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{Actor: orgCarol, SecretId: id, Reason: "manual"}); err != nil {
		t.Fatalf("EnqueueRotation: %v", err)
	}
	resp, err := s.ClaimDueRotations(context.Background(), &vaultv1.ClaimDueRotationsRequest{Identity: &vaultv1.WorkerIdentity{Token: "ok"}})
	if err != nil {
		t.Fatalf("ClaimDueRotations: %v", err)
	}
	for _, j := range resp.GetJobs() {
		if j.GetSecretId() == id {
			return j
		}
	}
	t.Fatalf("secret %s not claimed for rotation", id)
	return nil
}

func TestJobsCarryTheTargetsHostKeyPins(t *testing.T) {
	fx := newNoTargetFixture(t)
	k1, _ := genHostKey(t)
	k2, _ := genECDSAHostKey(t)
	pinTarget(t, fx.s, fx.target, k1, k2)
	id := fx.createHuman(t, fx.target)

	if got := claimedJob(t, fx.s, id).GetTarget().GetSshHostKeys(); !slices.Equal(got, []string{k1, k2}) {
		t.Fatalf("heartbeat job pins = %q, want %q", got, []string{k1, k2})
	}
	if got := claimedRotation(t, fx.s, id).GetTarget().GetSshHostKeys(); !slices.Equal(got, []string{k1, k2}) {
		t.Fatalf("rotation job pins = %q, want %q", got, []string{k1, k2})
	}
}

func TestJobsForAnUnpinnedTargetCarryNoPins(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	if got := claimedJob(t, fx.s, id).GetTarget().GetSshHostKeys(); len(got) != 0 {
		t.Fatalf("unpinned target sent pins %q", got)
	}
}

func TestJobPinsAreACopy(t *testing.T) {
	s := newServer(t)
	k1, _ := genHostKey(t)
	s.targets = []*vaultv1.Target{{Id: "t1", Kind: "linux", Hostname: "host.example.org", SshHostKeys: []string{k1}}}
	_, tgt := s.connTargetFor(&vaultv1.Secret{TargetId: "t1"})
	tgt.SshHostKeys[0] = "changed"
	if s.targets[0].GetSshHostKeys()[0] != k1 {
		t.Fatal("changing a job's pins changed the stored target")
	}
}

func TestReportHeartbeat_HostKeyResultsAreFailures(t *testing.T) {
	for _, res := range []vaultv1.HeartbeatResult{
		vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED,
		vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH,
	} {
		t.Run(res.String(), func(t *testing.T) {
			fx := newNoTargetFixture(t)
			id := fx.createHuman(t, fx.target)
			claimsHB(t, fx.s, id)
			reportHB(t, fx.s, id, res, "host offered SHA256:abc")

			fx.s.mu.RLock()
			sec := fx.s.findSecret(id)
			got, detail := sec.GetLastHeartbeatResult(), sec.GetLastHeartbeatDetail()
			fx.s.mu.RUnlock()
			if got != res || !strings.Contains(detail, "SHA256:abc") {
				t.Fatalf("recorded %v %q", got, detail)
			}
			if !heartbeatFailed(got) {
				t.Fatalf("%v must count as a failed heartbeat", got)
			}
			if hbPausedRow(t, fx.s, id) {
				t.Fatal("a host-key refusal tried no credential, so it must not pause the schedule")
			}
			st, err := fx.s.GetSecretStats(context.Background(), &vaultv1.GetSecretStatsRequest{Actor: orgCarol})
			if err != nil {
				t.Fatal(err)
			}
			if st.GetStats().GetDrift() != 1 {
				t.Fatalf("drift = %d, want the host-key failure counted", st.GetStats().GetDrift())
			}
			if fx.ca.find("secret.heartbeat.host_key") == nil {
				t.Fatal("no secret.heartbeat.host_key audit")
			}
		})
	}
}
