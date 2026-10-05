// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/maintenance"
)

// Every workflow method is placed for the read-only mode: the reads are
// declared on the proto and the rest are refused. A new RPC fails this test
// until it's placed.
func TestMaintenanceClassifiesEveryWorkflowMethod(t *testing.T) {
	want := map[string]maintenance.Class{
		"ListActiveLeasesForUser": maintenance.Read,
		"GetActiveLease":          maintenance.Read,
		"ListApprovalRequests":    maintenance.Read,
		"CheckoutSecret":          maintenance.Mutation,
		"CheckinSecret":           maintenance.Mutation,
		"CreateAccessRequest":     maintenance.Mutation,
		"CreateFolderMoveRequest": maintenance.Mutation,
		"CreateSecretMoveRequest": maintenance.Mutation,
		"ResolveApproval":         maintenance.Mutation,
		"AddApprovalComment":      maintenance.Mutation,
		"RotateSecret":            maintenance.Mutation,
	}
	got := MaintenanceClasses()
	desc := workflowv1.WorkflowService_ServiceDesc
	if len(desc.Streams) != 0 {
		t.Fatalf("the workflow has streaming methods now; classify them: %v", desc.Streams)
	}
	for _, md := range desc.Methods {
		w, ok := want[md.MethodName]
		if !ok {
			t.Errorf("%s isn't classified for maintenance", md.MethodName)
			continue
		}
		if g := got["/"+desc.ServiceName+"/"+md.MethodName]; g != w {
			t.Errorf("%s: class %v, want %v", md.MethodName, g, w)
		}
	}
	if len(want) != len(desc.Methods) {
		t.Errorf("want lists %d methods, the service has %d", len(want), len(desc.Methods))
	}
}

// The lease reaper doesn't sweep while the mode is on, and catches the
// expired lease on the first pass after.
func TestMaintenancePausesTheReaper(t *testing.T) {
	s, vc := newTestServerWithVault(t)
	ctx := context.Background()
	resp, err := s.CheckoutSecret(ctx, &workflowv1.CheckoutSecretRequest{
		Actor: &workflowv1.ActorContext{UserId: "user-carol"}, SecretId: "secret-maint", Hours: 1,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	runID, _ := s.store.ActiveLeaseRunForSecretUser(ctx, "secret-maint", "user-carol")
	backdateLease(t, s, resp.GetLease().GetId(), time.Now().UTC().Add(-time.Hour))

	mode := maintenance.New(true)
	s.SetMaintenance(mode)
	if n := s.reapOnce(ctx); n != 0 {
		t.Fatalf("reaped %d during maintenance, want 0", n)
	}
	if vc.callCount() != 0 {
		t.Fatalf("vault called %d times during maintenance", vc.callCount())
	}
	mode.Set(false)
	if n := s.reapOnce(ctx); n != 1 {
		t.Fatalf("reaped %d after maintenance, want 1", n)
	}
	waitLeaseReturned(t, s, runID)
}

type purgeCountingStore struct {
	Store
	purges int
}

func (p *purgeCountingStore) PurgeResolvedRequestsOlderThan(ctx context.Context, cutoff string) (int, error) {
	p.purges++
	return p.Store.PurgeResolvedRequestsOlderThan(ctx, cutoff)
}

// The history purge deletes nothing while the mode is on.
func TestMaintenancePausesTheHistoryPurge(t *testing.T) {
	s, _ := newTestServerWithVault(t)
	st := &purgeCountingStore{Store: s.store}
	s.store = st
	mode := maintenance.New(true)
	s.SetMaintenance(mode)
	s.purgeHistoryOnce(context.Background(), nil)
	if st.purges != 0 {
		t.Fatalf("purged %d times during maintenance", st.purges)
	}
	mode.Set(false)
	s.purgeHistoryOnce(context.Background(), nil)
	if st.purges != 1 {
		t.Fatalf("purges after maintenance = %d, want 1", st.purges)
	}
}
