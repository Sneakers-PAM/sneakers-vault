// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"golang.org/x/crypto/ssh"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var hostKeyAdmin = &vaultv1.ActorContext{
	UserId: "user-admin", IsSiteAdmin: true, PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN,
}

// genHostKey returns a fresh ed25519 host public key in authorized_keys form
// (no trailing newline) and its SHA256 fingerprint. Generated per test run.
func genHostKey(t *testing.T) (line, fp string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), ssh.FingerprintSHA256(sp)
}

func genECDSAHostKey(t *testing.T) (line, fp string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), ssh.FingerprintSHA256(sp)
}

func newAuditedServer(t *testing.T) (*Server, *recordingAuditor) {
	t.Helper()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	aud := &recordingAuditor{}
	return New(crypto.New(kek), aud), aud
}

func listedTarget(t *testing.T, s *Server, actor *vaultv1.ActorContext, id string) *vaultv1.Target {
	t.Helper()
	resp, err := s.ListTargets(context.Background(), &vaultv1.ListTargetsRequest{Actor: actor})
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	for _, tg := range resp.GetTargets() {
		if tg.GetId() == id {
			return tg
		}
	}
	t.Fatalf("target %s not listed", id)
	return nil
}

func TestSaveTargetHostKeysRoundTrip(t *testing.T) {
	s, aud := newAuditedServer(t)
	ctx := context.Background()
	edKey, edFP := genHostKey(t)
	ecKey, ecFP := genECDSAHostKey(t)

	created, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "app01", Hostname: "app01.example.org", ConnectionId: "conn-ssh-default",
		SshHostKeys: []string{"  " + edKey + " app01 host key\n", ecKey},
	}})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	id := created.GetTarget().GetId()
	want := []string{edKey + " app01 host key", ecKey}
	got := listedTarget(t, s, hostKeyAdmin, id).GetSshHostKeys()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("listed host keys = %q, want %q", got, want)
	}
	ev := aud.find("target.host_keys.change")
	if ev == nil {
		t.Fatal("no target.host_keys.change audit event on create")
	}
	if ev.Subject != id || ev.ActorUserID != "user-admin" {
		t.Fatalf("audit subject/actor = %q/%q", ev.Subject, ev.ActorUserID)
	}
	if ev.Attributes["added"] != edFP+","+ecFP || ev.Attributes["removed"] != "" {
		t.Fatalf("audit attrs on create = %v", ev.Attributes)
	}

	// An edit replaces the list: drop the ed25519 key.
	aud.events = nil
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Id: id, Name: "app01", Hostname: "app01.example.org", ConnectionId: "conn-ssh-default",
		SshHostKeys: []string{ecKey},
	}}); err != nil {
		t.Fatalf("SaveTarget (edit): %v", err)
	}
	if got := listedTarget(t, s, hostKeyAdmin, id).GetSshHostKeys(); len(got) != 1 || got[0] != ecKey {
		t.Fatalf("host keys after edit = %q", got)
	}
	ev = aud.find("target.host_keys.change")
	if ev == nil || ev.Attributes["added"] != "" || ev.Attributes["removed"] != edFP {
		t.Fatalf("audit on edit = %+v", ev)
	}
	for _, v := range ev.Attributes {
		if strings.Contains(v, "AAAA") {
			t.Fatalf("audit attribute carries key material: %q", v)
		}
	}

	// A save that leaves the pins alone audits no pin change.
	aud.events = nil
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Id: id, Name: "app01-renamed", Hostname: "app01.example.org", ConnectionId: "conn-ssh-default",
		SshHostKeys: []string{ecKey},
	}}); err != nil {
		t.Fatalf("SaveTarget (rename): %v", err)
	}
	if aud.find("target.host_keys.change") != nil {
		t.Fatal("unchanged pins must not audit a pin change")
	}
}

func TestSaveTargetHostKeysDeduplicates(t *testing.T) {
	s := newServer(t)
	key, _ := genHostKey(t)
	resp, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "app02", Hostname: "app02.example.org", ConnectionId: "conn-ssh-default",
		SshHostKeys: []string{key, key + " same key, other comment"},
	}})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}
	if got := resp.GetTarget().GetSshHostKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("host keys = %q, want the one key once", got)
	}
}

func TestSaveTargetRejectsBadHostKeys(t *testing.T) {
	good, _ := genHostKey(t)
	other, _ := genHostKey(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := string(pem.EncodeToMemory(block))

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	hostPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSSH, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: hostSSH, CertType: ssh.HostCert, ValidPrincipals: []string{"app03.example.org"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	cases := map[string]string{
		"garbage":       "not a key",
		"empty entry":   "   ",
		"private key":   privatePEM,
		"options":       `no-pty,from="192.0.2.10" ` + good,
		"two keys":      good + "\n" + other,
		"certificate":   certLine,
		"truncated key": good[:len(good)-12],
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			s := newServer(t)
			before := len(s.targets)
			_, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
				Name: "app03", Hostname: "app03.example.org", ConnectionId: "conn-ssh-default",
				SshHostKeys: []string{good, entry},
			}})
			if code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v (%v), want InvalidArgument", code(err), err)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "AAAA") {
				t.Fatalf("error echoes the entry: %v", err)
			}
			if len(s.targets) != before {
				t.Fatal("a rejected save must not create the target")
			}
		})
	}
}

// #318: a person may pin their own personal target's host keys; a site admin
// pins a shared one. Anyone else, and every token, is refused.
func TestSaveTargetHostKeysOwnerOfPersonalTargetPins(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	owner := &vaultv1.ActorContext{UserId: "user-dana", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	key, _ := genHostKey(t)
	key2, _ := genECDSAHostKey(t)

	created, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: owner, Target: &vaultv1.Target{
		Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}})
	if err != nil {
		t.Fatalf("owner pin on create: %v", err)
	}
	id := created.GetTarget().GetId()
	if created.GetTarget().GetOwnerUserId() != "user-dana" {
		t.Fatalf("owner = %q, want the creator", created.GetTarget().GetOwnerUserId())
	}
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: owner, Target: &vaultv1.Target{
		Id: id, Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key2},
	}}); err != nil {
		t.Fatalf("owner re-pin: %v", err)
	}
	if got := listedTarget(t, s, owner, id).GetSshHostKeys(); len(got) != 1 || got[0] != key2 {
		t.Fatalf("pins after owner re-pin = %q", got)
	}
}

func TestSaveTargetHostKeysOwnersTokenRefused(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	owner := &vaultv1.ActorContext{UserId: "user-dana", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	key, _ := genHostKey(t)
	created, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: owner, Target: &vaultv1.Target{
		Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default",
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.GetTarget().GetId()
	_, err = s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: tokenActor("user-dana", false), Target: &vaultv1.Target{
		Id: id, Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("owner's token pin: code = %v, want PermissionDenied", code(err))
	}
	if got := listedTarget(t, s, owner, id).GetSshHostKeys(); len(got) != 0 {
		t.Fatalf("pins after refused token save = %q", got)
	}
}

func TestSaveTargetHostKeysNonOwnerRefused(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	owner := &vaultv1.ActorContext{UserId: "user-dana", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	other := &vaultv1.ActorContext{UserId: "user-eli", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	key, _ := genHostKey(t)

	// Another person's personal target.
	personal, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: owner, Target: &vaultv1.Target{
		Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default",
	}})
	if err != nil {
		t.Fatalf("create personal: %v", err)
	}
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: other, Target: &vaultv1.Target{
		Id: personal.GetTarget().GetId(), Name: "lab01", Hostname: "lab01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}}); code(err) != codes.PermissionDenied {
		t.Fatalf("other person's pin on a personal target: code = %v, want PermissionDenied", code(err))
	}

	// A shared target: only a site admin pins it.
	shared, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "db01", Hostname: "db01.example.org", ConnectionId: "conn-ssh-default",
	}})
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: other, Target: &vaultv1.Target{
		Id: shared.GetTarget().GetId(), Name: "db01", Hostname: "db01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}}); code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin pin on a shared target: code = %v, want PermissionDenied", code(err))
	}

	// The rule itself, apart from SaveTarget's edit gate: a person who isn't
	// the owner can't change a personal target's pins, nor anyone's a
	// shared target's.
	if _, _, err := applyHostKeys(other, "user-dana", nil, []string{key}); code(err) != codes.PermissionDenied {
		t.Fatalf("applyHostKeys non-owner: code = %v, want PermissionDenied", code(err))
	}
	if _, _, err := applyHostKeys(other, "", nil, []string{key}); code(err) != codes.PermissionDenied {
		t.Fatalf("applyHostKeys non-admin on shared: code = %v, want PermissionDenied", code(err))
	}
	if _, _, err := applyHostKeys(owner, "user-dana", nil, []string{key}); err != nil {
		t.Fatalf("applyHostKeys owner: %v", err)
	}
}

func TestSaveTargetHostKeysAdminPinsSharedTarget(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	owner := &vaultv1.ActorContext{UserId: "user-dana", PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN}
	key, _ := genHostKey(t)
	created, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "db01", Hostname: "db01.example.org", ConnectionId: "conn-ssh-default",
	}})
	if err != nil {
		t.Fatalf("create shared: %v", err)
	}
	id := created.GetTarget().GetId()
	if created.GetTarget().GetOwnerUserId() != "" {
		t.Fatalf("an admin's target must be shared, owner = %q", created.GetTarget().GetOwnerUserId())
	}
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Id: id, Name: "db01", Hostname: "db01.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}}); err != nil {
		t.Fatalf("admin pin on shared: %v", err)
	}
	if got := listedTarget(t, s, owner, id).GetSshHostKeys(); len(got) != 1 || got[0] != key {
		t.Fatalf("pins after admin pin = %q", got)
	}
}

// #164: the refusal must read as "a person has to do this", not "you're
// missing a role" — a token whose user IS the box's site admin is refused
// with the same reason as anyone else, because no token can pin host keys,
// admin's included. A human admin still can.
func TestSaveTargetHostKeysRefusalNamesThePersonOnlyRule(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	key, _ := genHostKey(t)
	adminToken := tokenActor("user-admin", true)

	_, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: adminToken, Target: &vaultv1.Target{
		Name: "lab02", Hostname: "lab02.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("admin token pin: code = %v, want PermissionDenied", code(err))
	}
	if !strings.Contains(err.Error(), "admin's") || strings.Contains(err.Error(), "site admin") {
		t.Fatalf("message must say a person must do this, not that the caller lacks a role: %v", err)
	}
	st, _ := status.FromError(err)
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			info = i
		}
	}
	if info == nil || info.GetReason() != ReasonHostKeysPersonOnly {
		t.Fatalf("error info = %v, want reason %s", info, ReasonHostKeysPersonOnly)
	}

	// A human admin still pins.
	if _, err := s.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "lab03", Hostname: "lab03.example.org", ConnectionId: "conn-ssh-default", SshHostKeys: []string{key},
	}}); err != nil {
		t.Fatalf("human admin pin: %v", err)
	}
}
