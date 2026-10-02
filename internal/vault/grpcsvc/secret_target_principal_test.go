// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSetSecretTargetForPrincipal(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	conn := adminConnection(t, s)
	shared := sharedTarget(t, s, conn)
	seedPersonalFolder(s, "user-ada")
	ada := tokenActor("user-ada", false)
	sec := secretIn(t, s, &vaultv1.ActorContext{UserId: "user-ada"}, "folder-personal-ada", "ada-dc-admin")
	set := func(actor *vaultv1.ActorContext, secret, target string) (*vaultv1.SetSecretTargetForPrincipalResponse, error) {
		return s.SetSecretTargetForPrincipal(context.Background(), &vaultv1.SetSecretTargetForPrincipalRequest{Actor: actor, SecretId: secret, TargetId: target})
	}

	resp, err := set(ada, sec, shared)
	if err != nil || resp.GetSecret().GetTargetId() != shared {
		t.Fatalf("attach shared target: %+v, %v", resp.GetSecret(), err)
	}
	if ev := ca.find("secret.target.principal"); ev == nil || ev.ActorUserID != "user-ada" || ev.Attributes["target_id"] != shared {
		t.Fatalf("attach audit = %+v", ev)
	}
	if resp, err := set(ada, sec, ""); err != nil || resp.GetSecret().GetTargetId() != "" {
		t.Fatalf("detach: %+v, %v", resp.GetSecret(), err)
	}

	bobs, err := s.SaveTarget(context.Background(), &vaultv1.SaveTargetRequest{
		Actor: &vaultv1.ActorContext{UserId: "user-bob"}, Target: &vaultv1.Target{Name: "bob-box", Hostname: "bob.example.org", ConnectionId: conn},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		actor          *vaultv1.ActorContext
		secret, target string
		want           codes.Code
	}{
		"another user's personal target": {ada, sec, bobs.GetTarget().GetId(), codes.PermissionDenied},
		"missing target":                 {ada, sec, "no-such-target", codes.NotFound},
		"no author right on the secret":  {tokenActor("user-eve", false), sec, shared, codes.PermissionDenied},
		"a person uses the human path":   {&vaultv1.ActorContext{UserId: "user-ada"}, sec, shared, codes.PermissionDenied},
	} {
		if _, err := set(c.actor, c.secret, c.target); status.Code(err) != c.want {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}
