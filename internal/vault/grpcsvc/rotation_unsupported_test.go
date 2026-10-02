// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A rotation the secret can't do is refused up front, with a reason, instead
// of being queued for a job that never finishes.

func TestEnqueueRotationRefusesATypeWithoutRotation(t *testing.T) {
	s, ca, domainID := newRotationServer(t)
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	dom := s.findSecret(domainID)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "portal", FolderId: dom.GetFolderId(), TypeId: "type-web-password", TargetId: dom.GetTargetId(),
		Fields: map[string]string{"url": "https://portal.example.test", "username": "u", "password": "p"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := created.GetSecret().GetId()
	ca.events = nil
	_, err = s.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{Actor: carol, SecretId: sid, Reason: "manual"})
	if got := reasonOf(t, err, codes.FailedPrecondition); got != ReasonRotationNotSupported {
		t.Fatalf("reason %q", got)
	}
	if ok, _ := s.rot.Exists(ctx, sid); ok {
		t.Fatal("a refused rotation was queued")
	}
	if ca.find("rotate.enqueue") != nil {
		t.Fatal("a refused rotation was audited as queued")
	}
	if ev := ca.find("rotate.refused"); ev == nil || ev.Attributes["reason"] != ReasonRotationNotSupported {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestEnqueueRotationRefusesASecretThatOptedOut(t *testing.T) {
	s, _, sid := newRotationServer(t)
	s.findSecret(sid).RotationOptOut = true
	_, err := s.EnqueueRotation(context.Background(), &vaultv1.EnqueueRotationRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}, SecretId: sid, Reason: "manual"})
	if got := reasonOf(t, err, codes.FailedPrecondition); got != ReasonRotationOptedOut {
		t.Fatalf("reason %q", got)
	}
}
