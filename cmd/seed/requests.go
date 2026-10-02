// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	seed "github.com/Bugs5382/go-seed"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/workflow/v1"
)

const reqFolderName = "Production Servers"

// scenario is the go-seed target: the gRPC clients plus state that earlier steps
// populate for later ones (the created folder + secret ids).
type scenario struct {
	vc      vaultv1.VaultServiceClient
	wf      workflowv1.WorkflowServiceClient
	alan    *vaultv1.ActorContext
	folder  string
	secrets map[string]string // name -> id
}

func (s *scenario) findFolder(ctx context.Context) (string, error) {
	resp, err := s.vc.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: s.alan})
	if err != nil {
		return "", err
	}
	for _, f := range resp.GetFolders() {
		if f.GetName() == reqFolderName {
			return f.GetId(), nil
		}
	}
	return "", nil
}

func (s *scenario) findSecret(ctx context.Context, name string) (string, error) {
	resp, err := s.vc.ListSecretsInFolder(ctx, &vaultv1.ListSecretsInFolderRequest{Actor: s.alan, FolderId: s.folder})
	if err != nil {
		return "", err
	}
	for _, sec := range resp.GetSecrets() {
		if sec.GetName() == name {
			return sec.GetId(), nil
		}
	}
	return "", nil
}

func (s *scenario) hasPendingRequest(ctx context.Context, userID, secretID string) (bool, error) {
	resp, err := s.wf.ListApprovalRequests(ctx, &workflowv1.ListApprovalRequestsRequest{})
	if err != nil {
		return false, err
	}
	for _, r := range resp.GetRequests() {
		if r.GetRequestedByUserId() == userID && r.GetSecretId() == secretID &&
			r.GetStatus() == workflowv1.ApprovalStatus_APPROVAL_STATUS_PENDING {
			return true, nil
		}
	}
	return false, nil
}

// secretStep returns a create-if-missing + assert step for one secret.
func secretStep(name, typeID string, fields map[string]string) seed.Step[*scenario] {
	return seed.Step[*scenario]{
		Name: "secret:" + name,
		Apply: func(ctx context.Context, s *scenario) error {
			id, err := s.findSecret(ctx, name)
			if err != nil {
				return err
			}
			if id == "" {
				r, err := s.vc.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
					Actor: s.alan, Name: name, FolderId: s.folder, TypeId: typeID, Fields: fields,
				})
				if err != nil {
					return err
				}
				id = r.GetSecret().GetId()
			}
			s.secrets[name] = id
			return nil
		},
		Assert: func(ctx context.Context, s *scenario) error {
			if s.secrets[name] == "" {
				return fmt.Errorf("secret %q not created", name)
			}
			return nil
		},
	}
}

// requestStep returns a create-if-missing + assert step for one pending request.
func requestStep(userID, display, secretName, reason string) seed.Step[*scenario] {
	return seed.Step[*scenario]{
		Name: "request:" + display + "->" + secretName,
		Apply: func(ctx context.Context, s *scenario) error {
			secretID := s.secrets[secretName]
			ok, err := s.hasPendingRequest(ctx, userID, secretID)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
			_, err = s.wf.CreateAccessRequest(ctx, &workflowv1.CreateAccessRequestRequest{
				Actor: &workflowv1.ActorContext{UserId: userID}, SecretId: secretID, Reason: reason,
			})
			return err
		},
		Assert: func(ctx context.Context, s *scenario) error {
			ok, err := s.hasPendingRequest(ctx, userID, s.secrets[secretName])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("pending request %s -> %s missing", display, secretName)
			}
			return nil
		},
	}
}

// seedRequests builds a small, realistic access-request scenario so the Requests
// page can be exercised: a shared "Production Servers" folder owned by Alan
// Turing, two privileged secrets in it, and PENDING access requests from other
// users (which Alan, as owner/site-admin, approves/denies).
//
// It is idempotent + asserted via go-seed: every step creates-if-missing then
// verifies the object exists, so re-running never duplicates. DEV/QA-ONLY.
// Env: VAULT_ADDR (default vault:9091), WORKFLOW_ADDR (default workflow:9193).
func seedRequests(ctx context.Context) error {
	logger := log.New("simrequest")
	sc := &scenario{
		vc:      vaultv1.NewVaultServiceClient(dial(env("VAULT_ADDR", "vault:9091"))),
		wf:      workflowv1.NewWorkflowServiceClient(dial(env("WORKFLOW_ADDR", "workflow:9193"))),
		alan:    &vaultv1.ActorContext{UserId: "user-turing", IsSiteAdmin: true, IsRoot: true},
		secrets: map[string]string{},
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	const domainAdmin = "PROD Domain Admin"
	const coreSwitch = "core-switch01 (root)"

	runner := seed.New(sc)
	// 1) Shared folder owned by Alan (owner => approver of its requests).
	runner.Add(seed.Step[*scenario]{
		Name: "folder:" + reqFolderName,
		Apply: func(ctx context.Context, s *scenario) error {
			id, err := s.findFolder(ctx)
			if err != nil {
				return err
			}
			if id == "" {
				r, err := s.vc.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: s.alan, Name: reqFolderName})
				if err != nil {
					return err
				}
				id = r.GetFolder().GetId()
				if _, err := s.vc.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
					Actor: s.alan, FolderId: id, Owners: []string{"user-turing"},
				}); err != nil {
					return err
				}
			}
			s.folder = id
			return nil
		},
		Assert: func(ctx context.Context, s *scenario) error {
			if s.folder == "" {
				return fmt.Errorf("folder %q not created", reqFolderName)
			}
			return nil
		},
	})
	// 2) Two privileged secrets.
	runner.Add(secretStep(domainAdmin, "type-windows-domain", map[string]string{
		"domain": "corp.example.com", "username": "svc-domain-admin", "password": "S@mpleP@ssw0rd!1",
	}))
	runner.Add(secretStep(coreSwitch, "type-unix-ssh", map[string]string{
		"host": "core-sw01.example.com", "username": "netadmin", "password": "S@mpleP@ssw0rd!2",
	}))
	// 3) Pending access requests from other users.
	runner.Add(requestStep("user-hopper", "Grace Hopper", domainAdmin,
		"Deploying the Q3 patch to the domain controllers tonight — need the domain admin for the maintenance window."))
	runner.Add(requestStep("user-jobs", "Steve Jobs", domainAdmin,
		"On-call: investigating a failed GPO push, need temporary domain admin to read the event logs."))
	runner.Add(requestStep("user-lovelace", "Ada Lovelace", coreSwitch,
		"Core switch showing CRC errors on Gi1/0/24 — need root to pull interface counters."))

	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("simrequest seed: %w", err)
	}
	logger.Info().Str("folder", sc.folder).Int("secrets", len(sc.secrets)).Msg("simrequest seed complete")
	return nil
}
