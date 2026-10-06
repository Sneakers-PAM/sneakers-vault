// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// canManageOrOwnSecret mirrors the UpdateSecret/DeleteFolder gate: an actor
// may retire/restore/hard-delete a secret if they hold RACI manage (Author)
// rights on its folder, or own the folder (ownership inherits down the
// chain, plus site-admin/root — see isFolderOwner).
func (s *Server) canManageOrOwnSecret(a *vaultv1.ActorContext, sec *vaultv1.Secret) bool {
	if s.canManage(a, sec.GetFolderId()) {
		return true
	}
	return s.isFolderOwner(a, s.findFolder(sec.GetFolderId()))
}

// isProd reports whether the service is running in a production environment,
// gating irreversible operations (hard delete).
func (s *Server) isProd() bool {
	return s.env == "prod" || s.env == "production"
}

// RetireSecret soft-deletes a secret: hidden from default ListSecretsInFolder
// results and unrevealable, but recoverable via RestoreSecret.
func (s *Server) RetireSecret(ctx context.Context, req *vaultv1.RetireSecretRequest) (*vaultv1.RetireSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to retire this secret")
	}
	sec.Retired = true
	sec.RetiredAt = time.Now().UTC().Format(time.RFC3339)
	sec.Position = 0
	s.compactFolder(sec.GetFolderId())
	s.emit(ctx, req.GetActor().GetUserId(), "secret.retire", sec.Id, false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.retire", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	if s.hb != nil {
		_ = s.hb.Remove(ctx, sec.GetId())
	}
	return &vaultv1.RetireSecretResponse{Secret: sec}, nil
}

// RestoreSecret reverses RetireSecret, clearing retired/retired_at.
func (s *Server) RestoreSecret(ctx context.Context, req *vaultv1.RestoreSecretRequest) (*vaultv1.RestoreSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to restore this secret")
	}
	if sec.GetRetired() {
		sec.Position = s.nextPosition(sec.GetFolderId())
	}
	sec.Retired = false
	sec.RetiredAt = ""
	s.emit(ctx, req.GetActor().GetUserId(), "secret.restore", sec.Id, false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.restore", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	s.ensureHeartbeatScheduled(ctx, sec)
	// A retired secret's row is dropped at claim time, so restore schedules
	// it again.
	s.ensureRotationScheduled(ctx, sec)
	return &vaultv1.RestoreSecretResponse{Secret: sec}, nil
}

// DeleteSecret HARD-removes a secret and its encrypted field set: permanent
// and unrecoverable (unlike RetireSecret). In production this additionally
// requires a site-admin/root actor — the UI's type-to-confirm dialog is the
// human speed bump; this is the backend's hard stop.
func (s *Server) DeleteSecret(ctx context.Context, req *vaultv1.DeleteSecretRequest) (*vaultv1.DeleteSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to delete this secret")
	}
	if s.isProd() && !isHumanAdmin(req.GetActor()) {
		return nil, status.Error(codes.PermissionDenied, "hard delete in production requires a site admin")
	}
	if s.vers != nil {
		if err := s.vers.DeleteAll(ctx, sec.GetId()); err != nil {
			return nil, status.Error(codes.Internal, "delete secret versions")
		}
	}
	chain := s.secretChain(sec) // captured before removal
	s.secrets = removeByID(s.secrets, req.GetId())
	delete(s.records, req.GetId())
	s.compactFolder(sec.GetFolderId())
	s.emit(ctx, req.GetActor().GetUserId(), "secret.delete", req.GetId(), false)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.delete", "secret", sec.GetId(), sec.GetName(), chain)
	if s.hb != nil {
		_ = s.hb.Remove(ctx, sec.GetId())
	}
	return &vaultv1.DeleteSecretResponse{}, nil
}
