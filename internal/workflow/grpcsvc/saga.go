// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"time"

	"github.com/Bugs5382/go-saga-orchestration/domain"
	"github.com/Bugs5382/go-saga-orchestration/engine/verbs"
	sagasdk "github.com/Bugs5382/go-saga-orchestration/saga"
	"github.com/Bugs5382/go-saga-orchestration/store"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
	"github.com/google/uuid"
)

// Workflow definition IDs.
const (
	wfCheckout   = "checkout"
	wfRotation   = "rotation"
	wfBreakGlass = "break-glass"
)

// Action names dispatched by the single in-process action verb.
const (
	actIssueLease = "wf.issue_lease"
	actRotate     = "wf.rotate"
	actCloseLease = "wf.close_lease"
)

// BuildEngine constructs an in-process saga engine over st, registers the
// synchronous action verb (so issue/rotate/close run in-process, no broker),
// and publishes the workflow definitions. vault is the outbound client the
// rotate action uses to enqueue real rotations (never nil in production;
// SetRotation-style construction happens in main.go).
func BuildEngine(st store.Store, s Store, vault vaultv1.VaultServiceClient) (*sagasdk.Saga, error) {
	sc, err := sagasdk.New(sagasdk.Options{Store: st})
	if err != nil {
		return nil, fmt.Errorf("saga.New: %w", err)
	}
	registerActionVerb(sc, s, vault)
	for _, def := range definitions() {
		if err := sc.Register(def); err != nil {
			return nil, fmt.Errorf("register %s: %w", def.ID, err)
		}
	}
	return sc, nil
}

// BuildInMemoryEngine is BuildEngine over a fresh in-memory store (tests).
func BuildInMemoryEngine(s Store, vault vaultv1.VaultServiceClient) (*sagasdk.Saga, error) {
	sc := sagasdk.InMemory()
	registerActionVerb(sc, s, vault)
	for _, def := range definitions() {
		if err := sc.Register(def); err != nil {
			return nil, fmt.Errorf("register %s: %w", def.ID, err)
		}
	}
	return sc, nil
}

// registerActionVerb installs the synchronous handler for every action step.
// It closes over the service Store so lease lifecycle transitions persist,
// and over the vault client so wf.rotate can enqueue a real rotation.
func registerActionVerb(sc *sagasdk.Saga, s Store, vault vaultv1.VaultServiceClient) {
	sc.RegisterVerb(string(domain.StepTypeAction), "common",
		verbs.HandlerFunc(func(ctx context.Context, run domain.SagaRun, step domain.Step) (map[string]any, error) {
			switch step.Action {
			case actIssueLease:
				return issueLease(ctx, s, run)
			case actRotate:
				return rotate(ctx, vault, run)
			case actCloseLease:
				if err := s.CloseLeaseByRun(ctx, run.ID.String()); err != nil {
					return nil, err
				}
				// The lease has ended (explicit check-in, reaper-driven expiry, or
				// a failed run's compensation all reach this step): revoke the
				// temporary secret-level read grant the approval added for this
				// lease's holder, so reveal access lapses with the lease. Keyed by
				// the run's (secret_id, user_id); a no-op when no temp grant exists.
				if err := revokeSecretRead(ctx, vault, runStr(run, "secret_id"), runStr(run, "user_id")); err != nil {
					return nil, fmt.Errorf("revoke temp read grant: %w", err)
				}
				return map[string]any{"closed": true}, nil
			default:
				return nil, fmt.Errorf("unknown action %q", step.Action)
			}
		}))
}

// rotate enqueues a real rotation with vault. The reason comes from the run's
// inputs when the caller set one explicitly (e.g. RotateSecret sets
// reason="manual"); otherwise it defaults from which workflow is running the
// step, so the checkout saga's check-in leg and the break-glass saga get
// sensible reasons without every caller having to supply one.
//
// This always enqueues on check-in, regardless of whether the secret's type
// actually declares rotate-on-checkin: workflow has no visibility into the
// secret type's policy (that lives in vault), so it enqueues unconditionally
// and lets vault's typeHasRotation gate the no-op case. Vault is the source
// of truth for what rotation-capable means.
func rotate(ctx context.Context, vault vaultv1.VaultServiceClient, run domain.SagaRun) (map[string]any, error) {
	secretID := runStr(run, "secret_id")
	if secretID == "" {
		return map[string]any{"rotated": false}, nil
	}
	reason := runStr(run, "reason")
	if reason == "" {
		reason = defaultRotateReason(run.WorkflowID)
	}
	// Rotations driven through this saga action (check-in, lease-expiry,
	// break-glass) have no user actor — the saga engine runs them, not a
	// human. Vault's EnqueueRotation authorizes via RACI canManage OR
	// actor.IsRoot/IsSiteAdmin, so present a system root principal here or
	// every system-triggered rotation would be rejected as unauthorized.
	if _, err := vault.EnqueueRotation(ctx, &vaultv1.EnqueueRotationRequest{
		Actor:    &vaultv1.ActorContext{IsRoot: true, UserId: "system-rotation"},
		SecretId: secretID,
		Reason:   reason,
	}); err != nil {
		return nil, fmt.Errorf("enqueue rotation: %w", err)
	}
	return map[string]any{"rotated": true}, nil
}

// defaultRotateReason maps a workflow definition ID to the reason its
// rotate step reports to vault when the run didn't set one explicitly.
func defaultRotateReason(workflowID string) string {
	switch workflowID {
	case wfCheckout:
		return "checkin"
	case wfBreakGlass:
		return "break-glass"
	default:
		return "manual"
	}
}

func issueLease(ctx context.Context, s Store, run domain.SagaRun) (map[string]any, error) {
	secretID := runStr(run, "secret_id")
	userID := runStr(run, "user_id")
	hours := runInt(run, "hours")
	if hours <= 0 {
		hours = 4
	}
	now := time.Now().UTC()
	lease := newLease(secretID, userID, now, hours)
	if err := s.InsertLease(ctx, lease, run.ID.String()); err != nil {
		return nil, err
	}
	return map[string]any{"lease_id": lease.GetId()}, nil
}

func newLease(secretID, userID string, now time.Time, hours int) *workflowv1.Lease {
	return &workflowv1.Lease{
		Id:        uuid.NewString(),
		SecretId:  secretID,
		UserId:    userID,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Duration(hours) * time.Hour).Format(time.RFC3339),
	}
}

func runStr(run domain.SagaRun, k string) string {
	if run.Inputs != nil {
		if v, ok := run.Inputs[k].(string); ok {
			return v
		}
	}
	return ""
}
func runInt(run domain.SagaRun, k string) int {
	if run.Inputs == nil {
		return 0
	}
	switch n := run.Inputs[k].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// definitions returns the workflow definitions the engine serves.
//
//	checkout:    issue_lease -> [wait: checkin] -> rotate -> close_lease -> end
//	             (compensation on issue = close_lease, so a failed run releases it)
//	rotation:    rotate -> end
//	break-glass: issue_lease -> rotate -> close_lease -> end  (elevated, forced rotate)
func definitions() []domain.WorkflowDefinition {
	action := func(id, act, next string, comp *domain.Compensation) domain.Step {
		return domain.Step{ID: id, Type: domain.StepTypeAction, Action: act, Next: next, Compensation: comp}
	}
	end := domain.Step{ID: "done", Type: domain.StepTypeEnd}
	closeComp := &domain.Compensation{Action: actCloseLease}

	return []domain.WorkflowDefinition{
		{
			ID: wfCheckout, Version: 1, Name: "Secret checkout", Start: "issue", Published: true,
			Steps: []domain.Step{
				action("issue", actIssueLease, "await", closeComp),
				{ID: "await", Type: domain.StepTypeWaitForSignal, Inputs: map[string]any{"name": "checkin"}, Next: "rotate"},
				action("rotate", actRotate, "close", nil),
				action("close", actCloseLease, "done", nil),
				end,
			},
		},
		{
			ID: wfRotation, Version: 1, Name: "Credential rotation", Start: "rotate", Published: true,
			Steps: []domain.Step{action("rotate", actRotate, "done", nil), end},
		},
		{
			ID: wfBreakGlass, Version: 1, Name: "Break-glass access", Start: "issue", Published: true,
			Steps: []domain.Step{
				action("issue", actIssueLease, "rotate", closeComp),
				action("rotate", actRotate, "close", nil),
				action("close", actCloseLease, "done", nil),
				end,
			},
		},
	}
}
