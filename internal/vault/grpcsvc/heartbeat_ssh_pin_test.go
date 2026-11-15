// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// #162: an SSH Key secret's heartbeat needs a target with a connection AND at
// least one pinned host key, since the broker refuses to send a credential to
// an unpinned host. A Windows/AD secret needs only the target+connection
// (covered by heartbeat_no_target_test.go) — pinning is SSH-only.

func (fx *noTargetFixture) createSSH(t *testing.T, targetID string) string {
	t.Helper()
	c, err := fx.s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "deploy-key", FolderId: fx.folder, TypeId: "type-ssh-key", TargetId: targetID,
		Fields: map[string]string{"username": "deploy", "keyFormat": "Ed25519", "privateKey": "placeholder-key-material"},
	})
	if err != nil {
		t.Fatalf("CreateSecret (ssh): %v", err)
	}
	return c.GetSecret().GetId()
}

// pinHostKey pins a fresh host key on fx.target.
func (fx *noTargetFixture) pinHostKey(t *testing.T) {
	t.Helper()
	key, _ := genHostKey(t)
	if _, err := fx.s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: siteAdmin, Target: &vaultv1.Target{
			Id: fx.target, Name: "dc1", Hostname: "dc1.example.org", ConnectionId: fx.conn,
			SshHostKeys: []string{key},
		},
	}); err != nil {
		t.Fatalf("pin host key: %v", err)
	}
}

func TestHeartbeatSchedule_SSHNotCreatedWithoutAPinnedHostKey(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createSSH(t, fx.target)
	if fx.hasHBRow(t, id) {
		t.Fatal("an SSH secret with a reachable target but no pinned host key must not get a heartbeat_schedule row")
	}
}

func TestHeartbeatSchedule_SSHCreatedWithAPinnedHostKey(t *testing.T) {
	fx := newNoTargetFixture(t)
	fx.pinHostKey(t)
	id := fx.createSSH(t, fx.target)
	if !fx.hasHBRow(t, id) {
		t.Fatal("an SSH secret with a pinned host key should be scheduled at create")
	}
}

func TestHeartbeatSchedule_SSHCreatedWhenHostKeyPinnedByUpdate(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createSSH(t, fx.target)
	if fx.hasHBRow(t, id) {
		t.Fatal("precondition: no pin yet, no row")
	}
	fx.pinHostKey(t)
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Name: "deploy-key-renamed", TargetId: fx.target,
	}); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	if !fx.hasHBRow(t, id) {
		t.Fatal("pinning the host key then saving the secret should schedule the heartbeat")
	}
}

func TestHeartbeatOptIn_SSHRefusedNamingTheMissingHostKey(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createSSH(t, fx.target)
	if _, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
		Actor: orgCarol, SecretId: id, DisableHeartbeat: true,
	}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	_, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
		Actor: orgCarol, SecretId: id, DisableHeartbeat: false,
	})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "pinned host key") {
		t.Fatalf("opting back in without a pin: want FailedPrecondition naming the host key, got %v", err)
	}
	if fx.hasHBRow(t, id) {
		t.Fatal("a refused opt-in must not create the heartbeat_schedule row")
	}
}

func TestHeartbeatOptIn_SSHSucceedsOncePinned(t *testing.T) {
	fx := newNoTargetFixture(t)
	id := fx.createSSH(t, fx.target)
	if _, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
		Actor: orgCarol, SecretId: id, DisableHeartbeat: true,
	}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	fx.pinHostKey(t)
	if _, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
		Actor: orgCarol, SecretId: id, DisableHeartbeat: false,
	}); err != nil {
		t.Fatalf("opt back in once pinned: %v", err)
	}
	if !fx.hasHBRow(t, id) {
		t.Fatal("opting back in once the host key is pinned should schedule the heartbeat")
	}
}

// The principal view says heartbeat is available-but-blocked, naming what's
// missing, so a create result (and the secret page) can say "heartbeat
// available: switch it on" instead of leaving an operator to guess why it
// never started.
func TestPrincipalView_HeartbeatBlockedReasonNamesWhatsMissing(t *testing.T) {
	fx := newNoTargetFixture(t)
	noTarget := fx.createSSH(t, "")
	fx.s.mu.RLock()
	view := fx.s.principalSecretView(fx.s.findSecret(noTarget))
	fx.s.mu.RUnlock()
	if view.GetHeartbeatBlockedReason() != "no target" {
		t.Fatalf("blocked reason = %q, want %q", view.GetHeartbeatBlockedReason(), "no target")
	}

	noPin := fx.createSSH(t, fx.target)
	fx.s.mu.RLock()
	view = fx.s.principalSecretView(fx.s.findSecret(noPin))
	fx.s.mu.RUnlock()
	if view.GetHeartbeatBlockedReason() != "no pinned host key" {
		t.Fatalf("blocked reason = %q, want %q", view.GetHeartbeatBlockedReason(), "no pinned host key")
	}

	fx.pinHostKey(t)
	ready := fx.createSSH(t, fx.target)
	fx.s.mu.RLock()
	view = fx.s.principalSecretView(fx.s.findSecret(ready))
	fx.s.mu.RUnlock()
	if view.GetHeartbeatBlockedReason() != "" {
		t.Fatalf("a scheduled secret must carry no blocked reason, got %q", view.GetHeartbeatBlockedReason())
	}

	if _, err := fx.s.SetSecretAutomation(context.Background(), &vaultv1.SetSecretAutomationRequest{
		Actor: orgCarol, SecretId: ready, DisableHeartbeat: true,
	}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	fx.s.mu.RLock()
	view = fx.s.principalSecretView(fx.s.findSecret(ready))
	fx.s.mu.RUnlock()
	if view.GetHeartbeatBlockedReason() != "" {
		t.Fatalf("an opt-out is a choice, not a blocked state, got %q", view.GetHeartbeatBlockedReason())
	}
}
