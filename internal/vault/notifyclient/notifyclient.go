// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package notifyclient adapts the vault's grpcsvc.Notifier seam onto the notify
// service gRPC contract. Fire-and-forget: never blocks or fails the mutation.
package notifyclient

import (
	"context"
	"time"

	notifyv1 "github.com/Sneakers-PAM/sneakers-notify/gen/go/sneakers/notify/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
)

type client struct{ c notifyv1.NotifyServiceClient }

// New returns a grpcsvc.Notifier backed by the notify service.
func New(c notifyv1.NotifyServiceClient) grpcsvc.Notifier { return &client{c: c} }

func (a *client) Notify(ctx context.Context, ev grpcsvc.NotifyEvent) {
	subs := make([]*notifyv1.InformedSubject, 0, len(ev.Subjects))
	for _, s := range ev.Subjects {
		subs = append(subs, &notifyv1.InformedSubject{Kind: string(s.Kind), Name: s.Name})
	}
	req := &notifyv1.NotifyEventRequest{
		Action: ev.Action, ResourceKind: ev.ResourceKind, ResourceId: ev.ResourceID,
		ResourceLabel: ev.ResourceLabel, ActorUserId: ev.ActorUserID, InformedSubjects: subs,
	}
	go func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = a.c.NotifyEvent(cctx, req) // best-effort; audit already has the truth
	}()
}
