// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TLS certificate pins (Sneakers-PAM/sneakers-connector#75): a target's
// SHA-256 certificate fingerprints, which the connector verifies LDAPS and
// other TLS targets against. They follow the SSH host key rule: a person
// only, the personal target's owner or a site admin.

var tlsPinDana = &vaultv1.ActorContext{UserId: "user-dana", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}

// genCertPin returns a random SHA-256 fingerprint as 64 lowercase hex digits.
func genCertPin(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// colonUpper writes a pin the way openssl prints it: "AB:CD:...".
func colonUpper(pin string) string {
	var parts []string
	for i := 0; i < len(pin); i += 2 {
		parts = append(parts, strings.ToUpper(pin[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func saveLdapTarget(t *testing.T, s *Server, actor *vaultv1.ActorContext, id string, pins []string) (*vaultv1.Target, error) {
	t.Helper()
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{Actor: actor, Target: &vaultv1.Target{
		Id: id, Name: "dc01", Hostname: "dc01.corp.example.org", ConnectionId: "conn-ldaps", TlsCertPins: pins,
	}})
	return resp.GetTarget(), err
}

func TestNormalizeTLSPinsAcceptsHexPrefixAndColons(t *testing.T) {
	a, b := genCertPin(t), genCertPin(t)
	got, err := normalizeTLSPins([]string{
		"  " + a + "  ",
		"sha256:" + colonUpper(b),
		"SHA256:" + strings.ToUpper(a), // a repeat of the first, differently written
	})
	if err != nil {
		t.Fatalf("normalizeTLSPins: %v", err)
	}
	if !slices.Equal(got, []string{a, b}) {
		t.Fatalf("pins = %q, want %q", got, []string{a, b})
	}
}

func TestNormalizeTLSPinsRejectsBadEntries(t *testing.T) {
	good := genCertPin(t)
	for name, entry := range map[string]string{
		"empty":         "  ",
		"too short":     good[:62],
		"too long":      good + "00",
		"not hex":       strings.Repeat("g", 64),
		"other prefix":  "sha1:" + good,
		"a PEM block":   "-----BEGIN CERTIFICATE-----",
		"base64 sha256": "SHA256:" + strings.Repeat("A", 43),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := normalizeTLSPins([]string{good, entry})
			if code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", code(err))
			}
			if !strings.Contains(err.Error(), "TLS certificate pin 2") {
				t.Fatalf("error must name the entry by position: %v", err)
			}
			if strings.TrimSpace(entry) != "" && strings.Contains(err.Error(), strings.TrimSpace(entry)) {
				t.Fatalf("error echoes the entry: %v", err)
			}
		})
	}
}

func TestNormalizeTLSPinsCapsTheCount(t *testing.T) {
	pins := make([]string, maxTLSPinsPerTarget+1)
	for i := range pins {
		pins[i] = genCertPin(t)
	}
	if _, err := normalizeTLSPins(pins[:maxTLSPinsPerTarget]); err != nil {
		t.Fatalf("%d pins: %v", maxTLSPinsPerTarget, err)
	}
	if _, err := normalizeTLSPins(pins); code(err) != codes.InvalidArgument {
		t.Fatalf("%d pins: code = %v, want InvalidArgument", len(pins), code(err))
	}
}

func TestSaveTargetTLSPinsRoundTripAndAudit(t *testing.T) {
	s, aud := newAuditedServer(t)
	a, b := genCertPin(t), genCertPin(t)
	created, err := saveLdapTarget(t, s, hostKeyAdmin, "", []string{"sha256:" + colonUpper(a), b})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	id := created.GetId()
	if got := listedTarget(t, s, hostKeyAdmin, id).GetTlsCertPins(); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("listed pins = %q", got)
	}
	ev := aud.find("target.tls_cert_pins.change")
	if ev == nil || ev.Subject != id || ev.ActorUserID != "user-admin" ||
		ev.Attributes["added"] != a+","+b || ev.Attributes["removed"] != "" {
		t.Fatalf("audit on create = %+v", ev)
	}

	aud.events = nil
	if _, err := saveLdapTarget(t, s, hostKeyAdmin, id, []string{b}); err != nil {
		t.Fatalf("SaveTarget (edit): %v", err)
	}
	ev = aud.find("target.tls_cert_pins.change")
	if ev == nil || ev.Attributes["added"] != "" || ev.Attributes["removed"] != a {
		t.Fatalf("audit on edit = %+v", ev)
	}

	aud.events = nil
	if _, err := saveLdapTarget(t, s, hostKeyAdmin, id, []string{colonUpper(b)}); err != nil {
		t.Fatalf("SaveTarget (same pin, other spelling): %v", err)
	}
	if aud.find("target.tls_cert_pins.change") != nil {
		t.Fatal("unchanged pins must not audit a pin change")
	}
}

func TestSaveTargetTLSPinsOwnerOfPersonalTargetPins(t *testing.T) {
	s := newServer(t)
	pin, pin2 := genCertPin(t), genCertPin(t)
	created, err := saveLdapTarget(t, s, tlsPinDana, "", []string{pin})
	if err != nil {
		t.Fatalf("owner pin on create: %v", err)
	}
	if created.GetOwnerUserId() != "user-dana" {
		t.Fatalf("owner = %q", created.GetOwnerUserId())
	}
	if _, err := saveLdapTarget(t, s, tlsPinDana, created.GetId(), []string{pin2}); err != nil {
		t.Fatalf("owner re-pin: %v", err)
	}
	if got := listedTarget(t, s, tlsPinDana, created.GetId()).GetTlsCertPins(); !slices.Equal(got, []string{pin2}) {
		t.Fatalf("pins after re-pin = %q", got)
	}
}

func TestSaveTargetTLSPinsNonOwnerRefused(t *testing.T) {
	s := newServer(t)
	eli := &vaultv1.ActorContext{UserId: "user-eli", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	pin := genCertPin(t)
	shared, err := saveLdapTarget(t, s, hostKeyAdmin, "", nil)
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if _, err := saveLdapTarget(t, s, eli, shared.GetId(), []string{pin}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin pin on a shared target: code = %v", code(err))
	}
	// The rule itself, apart from SaveTarget's edit gate.
	if _, _, err := applyTLSPins(eli, "user-dana", nil, []string{pin}); code(err) != codes.PermissionDenied {
		t.Fatalf("another person on a personal target: code = %v", code(err))
	}
	if _, _, err := applyTLSPins(eli, "", nil, []string{pin}); code(err) != codes.PermissionDenied {
		t.Fatalf("a non-admin on a shared target: code = %v", code(err))
	}
	if _, _, err := applyTLSPins(tlsPinDana, "user-dana", nil, []string{pin}); err != nil {
		t.Fatalf("the owner: %v", err)
	}
}

// No token may change pins, an admin's or the owner's own included; the
// refusal says a person has to do it, not that a role is missing.
func TestSaveTargetTLSPinsTokenRefused(t *testing.T) {
	s := newServer(t)
	pin := genCertPin(t)
	personal, err := saveLdapTarget(t, s, tlsPinDana, "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The owner's token edits the owner's target; a site admin's token, which
	// SaveTarget's edit gate already keeps off other people's targets, makes a
	// new one.
	for name, tc := range map[string]struct {
		tok *vaultv1.ActorContext
		id  string
	}{
		"the owner's token":  {tokenActor("user-dana", false), personal.GetId()},
		"a site admin token": {tokenActor("user-admin", true), ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := saveLdapTarget(t, s, tc.tok, tc.id, []string{pin})
			if code(err) != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied", code(err))
			}
			st, _ := status.FromError(err)
			var info *errdetails.ErrorInfo
			for _, d := range st.Details() {
				if i, ok := d.(*errdetails.ErrorInfo); ok {
					info = i
				}
			}
			if info == nil || info.GetReason() != ReasonTLSPinsPersonOnly {
				t.Fatalf("error info = %v, want %s", info, ReasonTLSPinsPersonOnly)
			}
		})
	}
	if got := listedTarget(t, s, tlsPinDana, personal.GetId()).GetTlsCertPins(); len(got) != 0 {
		t.Fatalf("pins after refused token saves = %q", got)
	}
	// A token may still save the target with the pins it already has.
	if _, err := saveLdapTarget(t, s, tokenActor("user-dana", false), personal.GetId(), nil); err != nil {
		t.Fatalf("token save with unchanged pins: %v", err)
	}
}

func TestSaveTargetTLSPinsAdminPinsSharedTarget(t *testing.T) {
	s := newServer(t)
	pin := genCertPin(t)
	shared, err := saveLdapTarget(t, s, hostKeyAdmin, "", nil)
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if _, err := saveLdapTarget(t, s, hostKeyAdmin, shared.GetId(), []string{pin}); err != nil {
		t.Fatalf("admin pin: %v", err)
	}
	if got := listedTarget(t, s, tlsPinDana, shared.GetId()).GetTlsCertPins(); !slices.Equal(got, []string{pin}) {
		t.Fatalf("pins = %q", got)
	}
}

func TestJobsCarryTheTargetsTLSPins(t *testing.T) {
	s := newServer(t)
	pin := genCertPin(t)
	s.targets = []*vaultv1.Target{{Id: "t1", Kind: "active-directory", Hostname: "dc01.corp.example.org", ConnectionId: "conn-ldaps", TlsCertPins: []string{pin}}}
	job := s.targetJobFor("t1")
	if got := job.GetTarget().GetTlsCertPins(); !slices.Equal(got, []string{pin}) {
		t.Fatalf("job pins = %q", got)
	}
	job.Target.TlsCertPins[0] = "changed"
	if s.targets[0].GetTlsCertPins()[0] != pin {
		t.Fatal("changing a job's pins changed the stored target")
	}
	_, tgt := s.connTargetFor(&vaultv1.Secret{TargetId: "t1"})
	if got := tgt.GetTlsCertPins(); !slices.Equal(got, []string{pin}) {
		t.Fatalf("primary job target pins = %q", got)
	}
}

func TestReportHeartbeat_CertificateMismatchIsAFailure(t *testing.T) {
	res := vaultv1.HeartbeatResult_HEARTBEAT_RESULT_CERTIFICATE_MISMATCH
	reason := fmt.Sprintf("certificate mismatch: dc01.example.org presented %s, which isn't pinned", genCertPin(t))
	fx := newNoTargetFixture(t)
	id := fx.createHuman(t, fx.target)
	claimsHB(t, fx.s, id)
	reportHB(t, fx.s, id, res, reason)

	fx.s.mu.RLock()
	got := fx.s.findSecret(id).GetLastHeartbeatResult()
	fx.s.mu.RUnlock()
	if got != res || !heartbeatFailed(got) {
		t.Fatalf("recorded %v, want a failed %v", got, res)
	}
	if hbPausedRow(t, fx.s, id) {
		t.Fatal("no credential was tried, so the schedule must not pause")
	}
	if rec := fx.ca.find("secret.heartbeat.tls_certificate"); rec == nil || rec.Attributes["detail"] != reason {
		t.Fatalf("audit = %+v", rec)
	}
}
