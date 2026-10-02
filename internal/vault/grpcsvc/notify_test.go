// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
)

type recNotifier struct{ last *NotifyEvent }

func (r *recNotifier) Notify(_ context.Context, ev NotifyEvent) { e := ev; r.last = &e }

func TestNotifyInformedFiltersSubjectsAndFires(t *testing.T) {
	s := &Server{}
	rn := &recNotifier{}
	s.SetNotifier(rn)
	chain := []authz.CategoryRuleset{{Name: "sec", Rules: []authz.Rule{
		{Subject: authz.RuleSubject{Kind: authz.SubjUser, Name: "user-a"}, Grants: map[authz.Action]authz.Grant{authz.ActAck: authz.GrantAllow}},
		{Subject: authz.RuleSubject{Kind: authz.SubjUser, Name: "user-x"}, Grants: map[authz.Action]authz.Grant{authz.ActRead: authz.GrantAllow}},
	}}}
	s.notifyInformed(context.Background(), "user-carol", "secret.reveal", "secret", "sec-1", "prod-db", chain)
	if rn.last == nil {
		t.Fatal("notifier not fired")
	}
	if len(rn.last.Subjects) != 1 || rn.last.Subjects[0].Name != "user-a" {
		t.Fatalf("subjects: %+v", rn.last.Subjects)
	}
	if rn.last.ResourceLabel != "prod-db" || rn.last.ActorUserID != "user-carol" {
		t.Fatalf("event: %+v", rn.last)
	}
}

func TestNotifyInformedNilNotifierIsNoop(t *testing.T) {
	s := &Server{}
	s.notifyInformed(context.Background(), "u", "secret.reveal", "secret", "s", "l", nil) // must not panic
}
