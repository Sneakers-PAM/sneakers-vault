// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// An untrusted certificate is a trust failure, not a reachability one: the
// target answered, and no credential was tried, so it shows as a failed check
// with its reason and leaves the schedule running.
func TestReportHeartbeat_UntrustedCertificateIsAFailure(t *testing.T) {
	const reason = "untrusted certificate: the certificate for dc01.example.org is signed by Example CA, which isn't in the trusted CA list"
	res := vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNTRUSTED_CERTIFICATE
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, res, reason)

	fx.s.mu.RLock()
	sec := fx.s.findSecret(id)
	got, detail := sec.GetLastHeartbeatResult(), sec.GetLastHeartbeatDetail()
	fx.s.mu.RUnlock()
	if got != res || !strings.Contains(detail, reason) {
		t.Fatalf("recorded %v %q", got, detail)
	}
	if hbPausedRow(t, fx.s, id) {
		t.Fatal("no credential was tried, so the schedule must not pause")
	}
	st, err := fx.s.GetSecretStats(context.Background(), &vaultv1.GetSecretStatsRequest{Actor: orgCarol})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetStats().GetDrift() != 1 {
		t.Fatalf("drift = %d, want the certificate failure counted", st.GetStats().GetDrift())
	}
	rec := fx.ca.find("secret.heartbeat.tls_certificate")
	if rec == nil {
		t.Fatal("no secret.heartbeat.tls_certificate audit record")
	}
	if rec.Attributes["detail"] != reason {
		t.Fatalf("audit attributes = %v", rec.Attributes)
	}
	if fx.ca.find("secret.heartbeat.host_key") != nil {
		t.Fatal("a certificate failure isn't a host-key refusal")
	}
}
