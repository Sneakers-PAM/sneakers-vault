// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	secretUseTTL        = 10 * time.Minute
	redeemAfterApproval = time.Minute
	useGrantMaxSpan     = 24 * time.Hour
	maxUseArgv          = 64
)

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) useStoreOrUnavailable() (useStore, error) {
	if s.uses == nil {
		return nil, status.Error(codes.Unavailable, "secret use is not configured")
	}
	return s.uses, nil
}

func useAttrs(u *vaultv1.SecretUse, extra map[string]string) map[string]string {
	out := map[string]string{
		"use_id": u.GetId(), "token_id": u.GetTokenId(), "field": u.GetFieldKey(),
		"argv": strings.Join(u.GetArgv(), " "), "client_label": u.GetClientLabel(),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// useRefused audits a use request or release that did not go through. outcome
// is "denied" for an authorization refusal and "failed" otherwise.
func (s *Server) useRefused(ctx context.Context, actor *vaultv1.ActorContext, action, subject, outcome, reason string, attrs map[string]string) {
	out := map[string]string{"outcome": outcome, "reason": reason, "token_id": actor.GetTokenId()}
	for k, v := range attrs {
		out[k] = v
	}
	s.emitAttrs(ctx, actor.GetUserId(), action, subject, true, out)
}

// PrepareSecretUse records a request by a personal token to use one field of
// one secret for one exact command. It is approved at once when a use grant
// the owner created covers it; otherwise it waits for the owner.
func (s *Server) PrepareSecretUse(ctx context.Context, req *vaultv1.PrepareSecretUseRequest) (*vaultv1.PrepareSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if !isUserToken(actor) {
		return nil, status.Error(codes.PermissionDenied, "secret use is for personal tokens")
	}
	argv := req.GetArgv()
	if err := checkUseArgv(req.GetReveal(), argv); err != nil {
		return nil, err
	}
	s.mu.RLock()
	sec := s.findSecret(req.GetSecretId())
	readable := sec != nil && !sec.GetRetired() && s.canRead(actor, sec)
	var hasField, needsApproval bool
	if readable {
		_, hasField = s.records[sec.GetId()].Fields[req.GetFieldKey()]
		if req.GetReveal() {
			hasField = hasField && s.isSensitiveField(s.findType(sec.TypeId), req.GetFieldKey())
		}
		needsApproval = sec.GetRequireTokenApproval()
	}
	s.mu.RUnlock()
	attempt := map[string]string{"field": req.GetFieldKey(), "argv": strings.Join(argv, " "), "client_label": req.GetClientLabel()}
	if !readable {
		s.useRefused(ctx, actor, "secret.use.prepare", req.GetSecretId(), "denied", "no read access", attempt)
		return nil, status.Error(codes.PermissionDenied, "not permitted to use this secret")
	}
	if !hasField {
		s.useRefused(ctx, actor, "secret.use.prepare", req.GetSecretId(), "failed", "no such field", attempt)
		return nil, status.Error(codes.NotFound, "secret field not found")
	}
	now := s.clock()
	use := &vaultv1.SecretUse{
		Id: s.nextID("use"), SecretId: sec.GetId(), SecretName: sec.GetName(), FieldKey: req.GetFieldKey(),
		Argv: argv, UserId: actor.GetUserId(), TokenId: actor.GetTokenId(),
		State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(secretUseTTL).Unix(), ClientLabel: req.GetClientLabel(), Reveal: req.GetReveal(),
	}
	if err := s.approveAtPrepare(ctx, st, use, sec, needsApproval, now); err != nil {
		return nil, err
	}
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.emitAttrs(ctx, actor.GetUserId(), "secret.use.prepare", sec.GetId(), true, useAttrs(use, map[string]string{"grant_id": use.GetGrantId()}))
	return &vaultv1.PrepareSecretUseResponse{Use: use}, nil
}

// approveAtPrepare approves a use on the spot when that needs no person: a
// reveal of a secret without token approval, or a use a grant covers.
func (s *Server) approveAtPrepare(ctx context.Context, st useStore, use *vaultv1.SecretUse, sec *vaultv1.Secret, needsApproval bool, now time.Time) error {
	if use.GetReveal() && !needsApproval {
		use.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
		use.ExpiresAtUnix = now.Add(redeemAfterApproval).Unix()
		return nil
	}
	g, err := s.coveringGrant(ctx, st, use, sec, now)
	if err != nil {
		return status.Errorf(codes.Internal, "check use grants: %v", err)
	}
	if g != nil {
		use.State, use.GrantId = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED, g.GetId()
		use.ExpiresAtUnix = now.Add(redeemAfterApproval).Unix()
	}
	return nil
}

func checkUseArgv(reveal bool, argv []string) error {
	switch {
	case reveal && len(argv) != 0:
		return status.Error(codes.InvalidArgument, "a reveal releases the value to the token and names no command")
	case !reveal && (len(argv) == 0 || len(argv) > maxUseArgv || strings.TrimSpace(argv[0]) == ""):
		return status.Error(codes.InvalidArgument, "argv must name the command the value is used for")
	}
	return nil
}

// coveringGrant finds a live grant of the owner, for this token, whose scope
// holds the use, and counts the use against it.
func (s *Server) coveringGrant(ctx context.Context, st useStore, use *vaultv1.SecretUse, sec *vaultv1.Secret, now time.Time) (*vaultv1.UseGrant, error) {
	grants, err := st.GrantsFor(ctx, use.GetUserId())
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if !grantCovers(g, use, sec, now) {
			continue
		}
		g.Uses++
		if err := st.PutGrant(ctx, g); err != nil {
			return nil, err
		}
		return g, nil
	}
	return nil, nil
}

func grantCovers(g *vaultv1.UseGrant, use *vaultv1.SecretUse, sec *vaultv1.Secret, now time.Time) bool {
	switch {
	case g.GetTokenId() != use.GetTokenId(), g.GetRevokedAtUnix() != 0, now.Unix() >= g.GetExpiresAtUnix(),
		g.GetMaxUses() > 0 && g.GetUses() >= g.GetMaxUses():
		return false
	}
	inScope := slices.Contains(g.GetSecretIds(), sec.GetId()) || (g.GetFolderId() != "" && g.GetFolderId() == sec.GetFolderId())
	fields := g.GetFieldKeys()
	if len(fields) == 0 {
		fields = []string{"password"}
	}
	if !inScope || !slices.Contains(fields, use.GetFieldKey()) {
		return false
	}
	if use.GetReveal() {
		return g.GetAllowReveal()
	}
	// Exact, never by base name: a grant for "sha256sum" must not cover a
	// same-named program elsewhere on disk.
	program, args := use.GetArgv()[0], strings.Join(use.GetArgv()[1:], " ")
	for _, p := range g.GetPrograms() {
		if p.GetProgram() == program {
			if ok, _ := path.Match(p.GetArgPattern(), args); ok {
				return true
			}
		}
	}
	return false
}

func (s *Server) liveUse(ctx context.Context, st useStore, id string) (*vaultv1.SecretUse, error) {
	use, err := st.GetUse(ctx, id)
	if errors.Is(err, errUseNotFound) {
		return nil, status.Error(codes.NotFound, "secret use not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load secret use: %v", err)
	}
	live := use.GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_PENDING || use.GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
	if live && s.clock().Unix() >= use.GetExpiresAtUnix() {
		use.State = vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED
		_ = st.PutUse(ctx, use)
	}
	return use, nil
}

func (s *Server) GetSecretUse(ctx context.Context, req *vaultv1.GetSecretUseRequest) (*vaultv1.GetSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	owner := actor.GetUserId() == use.GetUserId()
	if !owner || (isUserToken(actor) && actor.GetTokenId() != use.GetTokenId()) {
		return nil, status.Error(codes.NotFound, "secret use not found")
	}
	return &vaultv1.GetSecretUseResponse{Use: use}, nil
}

func (s *Server) ListPendingSecretUses(ctx context.Context, req *vaultv1.ListPendingSecretUsesRequest) (*vaultv1.ListPendingSecretUsesResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || actor.GetUserId() == "" {
		return nil, status.Error(codes.PermissionDenied, "only the signed-in owner can review secret uses")
	}
	uses, err := st.PendingUses(ctx, actor.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secret uses: %v", err)
	}
	now := s.clock().Unix()
	out := make([]*vaultv1.SecretUse, 0, len(uses))
	for _, u := range uses {
		if now < u.GetExpiresAtUnix() {
			out = append(out, u)
		}
	}
	return &vaultv1.ListPendingSecretUsesResponse{Uses: out}, nil
}

// DecideSecretUse lets only the token's owner, signed in as themselves, approve
// or deny a pending use; the gateway requires a fresh second factor first.
func (s *Server) DecideSecretUse(ctx context.Context, req *vaultv1.DecideSecretUseRequest) (*vaultv1.DecideSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "only the signed-in owner can decide a secret use")
	}
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	if use.GetUserId() != actor.GetUserId() {
		return nil, status.Error(codes.PermissionDenied, "only the token's owner can decide this use")
	}
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		return nil, status.Errorf(codes.FailedPrecondition, "secret use is %s", use.GetState())
	}
	action := "secret.use.deny"
	use.State = vaultv1.SecretUseState_SECRET_USE_STATE_DENIED
	if req.GetApprove() {
		action = "secret.use.approve"
		use.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
		use.ExpiresAtUnix = s.clock().Add(redeemAfterApproval).Unix()
	}
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.emitAttrs(ctx, actor.GetUserId(), action, use.GetSecretId(), true, useAttrs(use, nil))
	return &vaultv1.DecideSecretUseResponse{Use: use}, nil
}

// RedeemSecretUse releases the value once, to the token that prepared the use,
// after approval and only while the owner can still read the secret.
func (s *Server) RedeemSecretUse(ctx context.Context, req *vaultv1.RedeemSecretUseRequest) (*vaultv1.RedeemSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	if !isUserToken(actor) || actor.GetTokenId() != use.GetTokenId() || actor.GetUserId() != use.GetUserId() {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "denied", "not the preparing token", map[string]string{"use_id": use.GetId()})
		return nil, status.Error(codes.PermissionDenied, "only the token that prepared this use can redeem it")
	}
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "failed", "use is "+use.GetState().String(), useAttrs(use, nil))
		return nil, status.Errorf(codes.FailedPrecondition, "secret use is %s", use.GetState())
	}
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	readable := sec != nil && !sec.GetRetired() && s.canRead(actor, sec)
	rec := s.records[use.GetSecretId()]
	s.mu.RUnlock()
	if !readable {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "denied", "read access lost", useAttrs(use, nil))
		return nil, status.Error(codes.PermissionDenied, "not permitted to use this secret any more")
	}
	value, err := s.crypt.Open(rec, use.GetFieldKey())
	if err != nil {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "failed", "open secret field", useAttrs(use, nil))
		return nil, status.Errorf(codes.Internal, "open secret field: %v", err)
	}
	use.State = vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	if use.GetReveal() {
		// Reads as the person revealing it, like a UI reveal.
		s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal", use.GetSecretId()+"#"+use.GetFieldKey(), true, map[string]string{
			"principal_kind": actor.GetPrincipalKind().String(), "token_id": actor.GetTokenId(), "via": "mcp",
			"use_id": use.GetId(), "grant_id": use.GetGrantId(), "client_label": use.GetClientLabel(),
		})
	} else {
		s.emitAttrs(ctx, actor.GetUserId(), "secret.use.redeem", use.GetSecretId(), true, useAttrs(use, map[string]string{"grant_id": use.GetGrantId()}))
	}
	return &vaultv1.RedeemSecretUseResponse{Use: use, Value: value}, nil
}

// validGrantProgram accepts a bare name, which sneakers-run resolves only from
// its trusted PATH, or an absolute path that must match argv[0] exactly.
func validGrantProgram(p string) bool {
	if p == "" {
		return false
	}
	if !strings.Contains(p, "/") {
		return true
	}
	return path.IsAbs(p) && path.Clean(p) == p
}

func requireHumanOwner(actor *vaultv1.ActorContext) error {
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || actor.GetUserId() == "" {
		return status.Error(codes.PermissionDenied, "use grants are managed by a signed-in person")
	}
	return nil
}

// CreateUseGrant stores a bounded pre-approval. Only a human session reaches
// this: no personal token, service account or MCP path can create one.
func (s *Server) CreateUseGrant(ctx context.Context, req *vaultv1.CreateUseGrantRequest) (*vaultv1.CreateUseGrantResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if err := requireHumanOwner(actor); err != nil {
		return nil, err
	}
	in := req.GetGrant()
	now := s.clock()
	switch {
	case in.GetTokenId() == "":
		return nil, status.Error(codes.InvalidArgument, "a grant is for one personal token")
	case len(in.GetSecretIds()) == 0 && in.GetFolderId() == "":
		return nil, status.Error(codes.InvalidArgument, "a grant needs secrets or a folder")
	case len(in.GetPrograms()) == 0 && !in.GetAllowReveal():
		return nil, status.Error(codes.InvalidArgument, "a grant needs at least one allowed program or allow_reveal")
	case in.GetExpiresAtUnix() <= now.Unix() || in.GetExpiresAtUnix() > now.Add(useGrantMaxSpan).Unix():
		return nil, status.Error(codes.InvalidArgument, "a grant must expire within 24 hours")
	}
	for _, p := range in.GetPrograms() {
		if !validGrantProgram(p.GetProgram()) {
			return nil, status.Errorf(codes.InvalidArgument, "program %q must be a bare command name or a clean absolute path", p.GetProgram())
		}
		if _, err := path.Match(p.GetArgPattern(), ""); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "bad argument pattern %q", p.GetArgPattern())
		}
	}
	g := &vaultv1.UseGrant{
		Id: s.nextID("usegrant"), UserId: actor.GetUserId(), TokenId: in.GetTokenId(),
		SecretIds: in.GetSecretIds(), FolderId: in.GetFolderId(), FieldKeys: in.GetFieldKeys(), Programs: in.GetPrograms(), AllowReveal: in.GetAllowReveal(),
		ExpiresAtUnix: in.GetExpiresAtUnix(), MaxUses: in.GetMaxUses(), CreatedAtUnix: now.Unix(),
	}
	if err := st.PutGrant(ctx, g); err != nil {
		return nil, status.Errorf(codes.Internal, "store use grant: %v", err)
	}
	s.emitAttrs(ctx, actor.GetUserId(), "use_grant.create", g.GetId(), false, map[string]string{"token_id": g.GetTokenId()})
	return &vaultv1.CreateUseGrantResponse{Grant: g}, nil
}

func (s *Server) ListUseGrants(ctx context.Context, req *vaultv1.ListUseGrantsRequest) (*vaultv1.ListUseGrantsResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	if err := requireHumanOwner(req.GetActor()); err != nil {
		return nil, err
	}
	grants, err := st.GrantsFor(ctx, req.GetActor().GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list use grants: %v", err)
	}
	return &vaultv1.ListUseGrantsResponse{Grants: grants}, nil
}

func (s *Server) RevokeUseGrant(ctx context.Context, req *vaultv1.RevokeUseGrantRequest) (*vaultv1.RevokeUseGrantResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if err := requireHumanOwner(actor); err != nil {
		return nil, err
	}
	g, err := st.GetGrant(ctx, req.GetGrantId())
	if err != nil || g.GetUserId() != actor.GetUserId() {
		return nil, status.Error(codes.NotFound, "use grant not found")
	}
	if g.RevokedAtUnix == 0 {
		g.RevokedAtUnix = s.clock().Unix()
		if err := st.PutGrant(ctx, g); err != nil {
			return nil, status.Errorf(codes.Internal, "store use grant: %v", err)
		}
	}
	s.emitAttrs(ctx, actor.GetUserId(), "use_grant.revoke", g.GetId(), false, map[string]string{"token_id": g.GetTokenId()})
	return &vaultv1.RevokeUseGrantResponse{Grant: g}, nil
}
