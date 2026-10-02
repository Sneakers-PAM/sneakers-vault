// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// bumpView records an access (reveal/copy) for the dashboard "top accessed".
// The PersistUnary interceptor snapshots after these RPCs so it survives restart.
func bumpView(sec *vaultv1.Secret) {
	sec.ViewCount++
	sec.LastAccessedAt = time.Now().UTC().Format(time.RFC3339)
}

// stringMapsEqual reports whether two field maps hold identical keys+values, so a
// save that changes nothing doesn't mint a redundant secret version.
func stringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (s *Server) ListSecretsInFolder(_ context.Context, req *vaultv1.ListSecretsInFolderRequest) (*vaultv1.ListSecretsInFolderResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultv1.Secret
	for _, sec := range s.secrets {
		if sec.FolderId != req.GetFolderId() {
			continue
		}
		if sec.GetRetired() && !req.GetIncludeRetired() {
			continue
		}
		out = append(out, sec)
	}
	return &vaultv1.ListSecretsInFolderResponse{Secrets: out}, nil
}

func (s *Server) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest) (*vaultv1.GetSecretResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	return &vaultv1.GetSecretResponse{Secret: sec}, nil
}

func (s *Server) CreateSecret(ctx context.Context, req *vaultv1.CreateSecretRequest) (*vaultv1.CreateSecretResponse, error) {
	if req.GetName() == "" || req.GetFolderId() == "" || req.GetTypeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, folder, and type are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findType(req.GetTypeId()) == nil {
		return nil, errNotFound("secret type")
	}
	if !s.canManage(req.GetActor(), req.GetFolderId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to create a secret in this folder")
	}
	// Authoritative server-side check that a submitted SSH private/public
	// key pair actually correspond, before anything is sealed and stored.
	if err := verifyKeyPairFields(req.GetFields()); err != nil {
		return nil, err
	}
	sec := &vaultv1.Secret{
		Id: s.nextID("secret"), Name: req.GetName(), FolderId: req.GetFolderId(),
		TypeId: req.GetTypeId(), TargetId: req.GetTargetId(), ExpiresAt: req.GetExpiresAt(),
	}
	rec, err := s.crypt.Seal(req.GetFields())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal fields: %v", err)
	}
	s.secrets = append(s.secrets, sec)
	s.records[sec.Id] = rec
	// Mirror the initial record into the append-only version ledger (v1, active).
	// Best-effort like the heartbeat schedule: the secret_records hot path already
	// succeeded and is the authoritative read; the ledger is history/rollback.
	if s.vers != nil {
		_, _ = s.vers.AppendActive(ctx, sec.Id, rec, req.GetActor().GetUserId())
	}
	s.emit(ctx, req.GetActor().GetUserId(), "secret.create", sec.Id, true)
	s.ensureLifecycle(ctx, sec)
	return &vaultv1.CreateSecretResponse{Secret: sec}, nil
}

// ensureLifecycle bootstraps a freshly created secret's heartbeat schedule (if
// heartbeat-enabled) and rotation schedule (if rotation-capable with a positive
// policy interval). Extracted from CreateSecret (no behavior change) so
// CreateSecretForPrincipal/GenerateSecretForPrincipal's shared
// buildAndStoreSecret (secrets_principal.go) runs the exact same lifecycle
// bootstrap a human-authored CreateSecret does. Caller holds s.mu (write lock).
func (s *Server) ensureLifecycle(ctx context.Context, sec *vaultv1.Secret) {
	s.ensureHeartbeatScheduled(ctx, sec)
	// Auto-schedule rotation-capable secrets whose policy carries a rotation
	// interval, so scheduled rotation is live from creation (not only after a
	// manual/system EnqueueRotation). Same capability/interval derivation as
	// the rest of rotation.go (typeHasRotation, policyForSecret). A future due
	// date only — never enqueue-due — EnsureScheduled leaves interval-0 dormant.
	s.ensureRotationScheduled(ctx, sec)
}

// ensureHeartbeatScheduled creates the secret's heartbeat schedule row when it
// is heartbeat-enabled and has a target whose connection exists. Without one
// the connector can only report UNREACHABLE, which alerts after a few rounds
// on a secret nobody asked it to check. Caller holds s.mu.
func (s *Server) ensureHeartbeatScheduled(ctx context.Context, sec *vaultv1.Secret) {
	if s.hb == nil || !s.secretHeartbeatEnabled(sec) {
		return
	}
	l := s.lg(ctx)
	if !s.rotationReachable(sec) {
		l.Info("heartbeat not scheduled: secret has no target with a connection", log.F("secret_id", sec.GetId()), log.F("target_id", sec.GetTargetId()))
		return
	}
	if err := s.hb.Ensure(ctx, sec.GetId(), int(sec.GetHeartbeatIntervalSeconds())); err != nil {
		l.Error(err, "create heartbeat schedule failed", log.F("secret_id", sec.GetId()))
	}
}

// ensureRotationScheduled creates the secret's rotation schedule row when it is
// rotation-capable, its policy carries an interval, and it has a target whose
// connection exists. Without a reachable target the connector has nothing to
// rotate against, so a row would be claimed forever and never complete.
// Caller holds s.mu.
func (s *Server) ensureRotationScheduled(ctx context.Context, sec *vaultv1.Secret) {
	if s.rot == nil || !s.typeHasRotation(sec) {
		return
	}
	days := policyRotationDays(s.policyForSecret(sec))
	if days <= 0 {
		return
	}
	l := s.lg(ctx)
	if !s.rotationReachable(sec) {
		l.Info("rotation not scheduled: secret has no target with a connection", log.F("secret_id", sec.GetId()), log.F("target_id", sec.GetTargetId()))
		return
	}
	if err := s.rot.EnsureScheduled(ctx, sec.GetId(), days); err != nil {
		l.Error(err, "create rotation schedule failed", log.F("secret_id", sec.GetId()))
	}
}

//nolint:gocognit,gocyclo // pre-existing complexity
func (s *Server) UpdateSecret(ctx context.Context, req *vaultv1.UpdateSecretRequest) (*vaultv1.UpdateSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManageOrOwnSecret(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to edit this secret")
	}
	oldName := sec.Name
	var changes []fieldChange
	var sensitiveChanged []string
	// Move to another folder. A secret's scope is its folder's, so a move is
	// just reassigning FolderId — but it obeys the same rule as MoveFolder: you
	// must be able to place it in the destination, personal -> shared is free, and
	// moving into a personal folder that isn't already yours needs site-admin
	// (a non-admin is rejected; the gateway routes it through an approval that
	// re-applies this move as the system actor).
	if dest := req.GetDestFolderId(); dest != "" && dest != sec.FolderId {
		df := s.findFolder(dest)
		if df == nil {
			return nil, errNotFound("destination folder")
		}
		if !s.isFolderOwner(req.GetActor(), df) && !s.canManage(req.GetActor(), dest) {
			return nil, status.Error(codes.PermissionDenied, "not permitted to move the secret to that folder")
		}
		if destPersonal, destOwner := s.destPersonal(df); destPersonal {
			src := s.findFolder(sec.FolderId)
			alreadyYours := src.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && src.GetOwnerUserId() == destOwner
			if !alreadyYours && !isHumanAdmin(req.GetActor()) {
				return nil, status.Error(codes.PermissionDenied, "moving a secret into a personal folder requires site-admin approval")
			}
		}
		sec.FolderId = dest
		s.emit(ctx, req.GetActor().GetUserId(), "secret.move", sec.Id, false)
	}
	if req.GetName() != "" {
		sec.Name = req.GetName()
	}
	if oldName != sec.Name {
		changes = append(changes, fieldChange{Field: "name", Old: oldName, New: sec.Name})
	}
	oldTarget := sec.TargetId
	sec.TargetId = req.GetTargetId()
	sec.ExpiresAt = req.GetExpiresAt()
	if sec.TargetId != "" && sec.TargetId != oldTarget {
		s.ensureRotationScheduled(ctx, sec)
	}

	// Re-seal: start from the current plaintext, overlay only the provided
	// fields (the gateway omits a sensitive field to keep it unchanged), then
	// seal under a fresh DEK — but ONLY when the plaintext actually changed. The
	// editor re-sends every non-sensitive field on each save, so without this a
	// no-op save (e.g. a folder move, or an edit that touched nothing) would mint
	// a redundant version. Unchanged values collapse into the existing version.
	if patch := req.GetFields(); len(patch) > 0 {
		cur := map[string]string{}
		if rec, ok := s.records[sec.Id]; ok {
			opened, err := s.crypt.OpenAll(rec)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "open existing: %v", err)
			}
			cur = opened
		}
		merged := map[string]string{}
		for k, v := range cur {
			merged[k] = v
		}
		for k, v := range patch {
			merged[k] = v
		}
		if !stringMapsEqual(cur, merged) {
			// Same authoritative key-pair check as CreateSecret, run on the
			// merged (patched-over-stored) plaintext that is about to be re-sealed.
			if err := verifyKeyPairFields(merged); err != nil {
				return nil, err
			}
			fc, sc := s.diffSecretFields(s.findType(sec.TypeId), cur, merged)
			changes = append(changes, fc...)
			sensitiveChanged = append(sensitiveChanged, sc...)
			rec, err := s.crypt.Seal(merged)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "seal fields: %v", err)
			}
			s.records[sec.Id] = rec
			// Append the re-sealed record as the new active version (prior retained
			// inactive). Best-effort; hot-path read stays secret_records.
			if s.vers != nil {
				_, _ = s.vers.AppendActive(ctx, sec.Id, rec, req.GetActor().GetUserId())
			}
			s.resumeHeartbeatOnValueChange(ctx, sec, req.GetActor().GetUserId(), map[string]string{"reason": "credential_updated"})
		}
	}
	s.emitAttrs(ctx, req.GetActor().GetUserId(), "secret.update", sec.Id, true, secretUpdateAttributes(changes, sensitiveChanged))
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.update", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	s.ensureHeartbeatScheduled(ctx, sec)
	return &vaultv1.UpdateSecretResponse{Secret: sec}, nil
}

// SetSecretTokenApproval turns the per-secret requirement for the owner to
// approve each personal-token reveal on or off.
func (s *Server) SetSecretTokenApproval(ctx context.Context, req *vaultv1.SetSecretTokenApprovalRequest) (*vaultv1.SetSecretTokenApprovalResponse, error) {
	actor := req.GetActor()
	// A person only: a token of the secret's owner would pass canManage, and a
	// token must never be able to lift its own approval requirement.
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || actor.GetUserId() == "" {
		return nil, status.Error(codes.PermissionDenied, "token approval is set by a signed-in person")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManage(actor, sec.FolderId) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to change this secret's token approval")
	}
	if sec.GetRequireTokenApproval() != req.GetRequired() {
		sec.RequireTokenApproval = req.GetRequired()
		action := "secret.token_approval.disable"
		if sec.RequireTokenApproval {
			action = "secret.token_approval.enable"
		}
		s.emit(ctx, actor.GetUserId(), action, sec.GetId(), false)
	}
	return &vaultv1.SetSecretTokenApprovalResponse{Secret: sec}, nil
}

// SetSecretAutomation toggles the per-secret rotation/heartbeat opt-outs. Each
// disable is audited (a deliberate, notice-worthy exception) and immediately
// removes the matching schedule; re-enabling re-establishes it when the type
// supports that automation.
func (s *Server) SetSecretAutomation(ctx context.Context, req *vaultv1.SetSecretAutomationRequest) (*vaultv1.SetSecretAutomationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetSecretId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canManage(req.GetActor(), sec.FolderId) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to change this secret's automation")
	}
	actor := req.GetActor().GetUserId()
	if err := s.applyAutomation(ctx, sec, req.GetDisableRotation(), req.GetDisableHeartbeat(), func(action string) {
		s.emit(ctx, actor, action, sec.GetId(), false)
	}); err != nil {
		return nil, err
	}
	return &vaultv1.SetSecretAutomationResponse{Secret: sec}, nil
}

// applyAutomation sets the rotation/heartbeat opt-outs to the requested values,
// removing or re-establishing the matching schedule rows, and calls audit with
// the action for each flag that actually changed. Turning rotation back on
// for the built-in Administrator is refused before anything changes (audited
// secret.rotation.enable.refused); a request that leaves rotation as it is
// still goes through. Caller holds s.mu (write).
func (s *Server) applyAutomation(ctx context.Context, sec *vaultv1.Secret, disableRotation, disableHeartbeat bool, audit func(action string)) error {
	if sec.GetBuiltinAdministrator() && sec.GetRotationOptOut() && !disableRotation {
		l := s.lg(ctx)
		l.Warn("rotation enable refused: built-in Administrator account", log.F("secret_id", sec.GetId()))
		audit("secret.rotation.enable.refused")
		return errBuiltinAdministrator
	}
	if disableRotation != sec.GetRotationOptOut() {
		s.setRotationOptOut(ctx, sec, disableRotation, audit)
	}
	if disableHeartbeat != sec.GetHeartbeatOptOut() {
		s.setHeartbeatOptOut(ctx, sec, disableHeartbeat, audit)
	}
	return nil
}

func (s *Server) setRotationOptOut(ctx context.Context, sec *vaultv1.Secret, optOut bool, audit func(action string)) {
	l := s.lg(ctx)
	sec.RotationOptOut = optOut
	l.Info("secret rotation automation changed", log.F("secret_id", sec.GetId()), log.F("rotation_opt_out", optOut))
	if !optOut {
		s.ensureRotationScheduled(ctx, sec)
		audit("secret.rotation.enable")
		return
	}
	if s.rot != nil {
		if err := s.rot.Remove(ctx, sec.GetId()); err != nil {
			l.Error(err, "remove rotation schedule on opt-out failed", log.F("secret_id", sec.GetId()))
		}
	}
	audit("secret.rotation.disable")
}

func (s *Server) setHeartbeatOptOut(ctx context.Context, sec *vaultv1.Secret, optOut bool, audit func(action string)) {
	l := s.lg(ctx)
	sec.HeartbeatOptOut = optOut
	l.Info("secret heartbeat automation changed", log.F("secret_id", sec.GetId()), log.F("heartbeat_opt_out", optOut))
	if !optOut {
		s.ensureHeartbeatScheduled(ctx, sec)
		audit("secret.heartbeat.enable")
		return
	}
	if s.hb != nil {
		if err := s.hb.Remove(ctx, sec.GetId()); err != nil {
			l.Error(err, "remove heartbeat schedule on opt-out failed", log.F("secret_id", sec.GetId()))
		}
	}
	audit("secret.heartbeat.disable")
}

// GetSecretFields returns only the NON-sensitive field values (safe without an
// audited reveal).
func (s *Server) GetSecretFields(_ context.Context, req *vaultv1.GetSecretFieldsRequest) (*vaultv1.GetSecretFieldsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	t := s.findType(sec.TypeId)
	rec, ok := s.records[sec.Id]
	out := map[string]string{}
	if ok {
		all, err := s.crypt.OpenAll(rec)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "open: %v", err)
		}
		for k, v := range all {
			if !s.isSensitiveField(t, k) {
				out[k] = v
			}
		}
	}
	return &vaultv1.GetSecretFieldsResponse{Fields: out}, nil
}

// RevealSecretField decrypts ONE sensitive field, gated by folder RBAC and
// recorded as an audited, sensitive reveal.
func (s *Server) RevealSecretField(ctx context.Context, req *vaultv1.RevealSecretFieldRequest) (*vaultv1.RevealSecretFieldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.isSensitiveField(s.findType(sec.TypeId), req.GetFieldKey()) {
		return nil, status.Error(codes.InvalidArgument, "field is not sensitive")
	}
	if !s.canRead(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to reveal this secret")
	}
	rec, ok := s.records[sec.Id]
	if !ok {
		return nil, errNotFound("secret value")
	}
	val, err := s.crypt.Open(rec, req.GetFieldKey())
	if err == crypto.ErrFieldNotFound {
		return nil, errNotFound("field")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	bumpView(sec)
	s.emit(ctx, req.GetActor().GetUserId(), "secret.reveal", sec.Id+"#"+req.GetFieldKey(), true)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.reveal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.RevealSecretFieldResponse{Value: val}, nil
}

// RevealSecretFieldForPrincipal decrypts ONE field for a non-human
// principal — service-account, workload or a user's personal token,
// which reads as its user under the token limits canRead applies — gated by RACI-read
// (evalOf maps a machine principal to its own EvalSubject) and a full audit
// trail. Deliberately does NOT consult any MFA/checkout gate: those are human
// interactive-session affordances enforced above the vault (gateway/UI), and
// this path — modeled on RevealSecretField — never checks them, matching
// "machine reveal = RACI-read + full audit, no MFA/checkout". A HUMAN-kind
// actor is rejected by revealForPrincipal below (defense-in-depth: humans
// must use RevealSecretField instead).
func (s *Server) RevealSecretFieldForPrincipal(ctx context.Context, req *vaultv1.RevealSecretFieldForPrincipalRequest) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revealForPrincipal(ctx, req.GetActor(), req.GetId(), req.GetFieldKey())
}

// revealForPrincipal is the shared reveal-for-any-principal core
// (factored out so the SA path (RevealSecretFieldForPrincipal) and the
// workload path share one implementation). Caller must hold s.mu (write
// lock) — bumpView mutates the secret.
//
// Deliberate defense-in-depth restriction: PRINCIPAL_KIND_HUMAN (including
// the zero-value/unspecified kind, which defaults to HUMAN) is rejected here.
// The no-MFA principal-reveal path must be reachable ONLY by non-human
// principals, so a human is forced through RevealSecretField (subject to the
// gateway's MFA/checkout step-up) instead of this path bypassing it — the
// security property doesn't rest solely on the gateway routing humans
// correctly.
func (s *Server) revealForPrincipal(ctx context.Context, actor *vaultv1.ActorContext, id, fieldKey string) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal reveal is for non-human principals")
	}
	sec := s.findSecret(id)
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	sensitive := s.isSensitiveField(s.findType(sec.TypeId), fieldKey)
	if !s.canRead(actor, sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to reveal this secret")
	}
	rec, ok := s.records[sec.Id]
	if !ok {
		return nil, errNotFound("secret value")
	}
	val, err := s.crypt.Open(rec, fieldKey)
	if err == crypto.ErrFieldNotFound {
		return nil, errNotFound("field")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reveal: %v", err)
	}
	if !sensitive {
		return s.plainReadForPrincipal(ctx, actor, sec, fieldKey, val), nil
	}
	if isUserToken(actor) && sec.GetRequireTokenApproval() {
		s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal.approval_required", sec.Id+"#"+fieldKey, true, map[string]string{
			"principal_kind": actor.GetPrincipalKind().String(), "token_id": actor.GetTokenId(), "via": "mcp",
		})
		return nil, status.Error(codes.FailedPrecondition, "approval_required: this secret needs the owner's approval for each token reveal; prepare a reveal use")
	}
	bumpView(sec)
	// A personal token reveals as its user: the same action a UI reveal records,
	// so the trail reads as that person, marked as coming through the token.
	if isUserToken(actor) {
		s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal", sec.Id+"#"+fieldKey, true, map[string]string{
			"principal_kind": actor.GetPrincipalKind().String(),
			"token_id":       actor.GetTokenId(),
			"via":            "mcp",
		})
		s.notifyInformed(ctx, actor.GetUserId(), "secret.reveal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
		return &vaultv1.RevealSecretFieldForPrincipalResponse{Value: val}, nil
	}
	// Same audit tier/sensitivity as secret.reveal (audit.TierActivity,
	// sensitive=true) — attributed to the principal, carrying principal_kind/
	// principal_id as attributes, NEVER the revealed value.
	s.emitAttrs(ctx, principalActorID(actor), "secret.reveal.principal", sec.Id+"#"+fieldKey, true, map[string]string{
		"principal_kind": actor.GetPrincipalKind().String(),
		"principal_id":   actor.GetPrincipalId(),
	})
	s.notifyInformed(ctx, principalActorID(actor), "secret.reveal.principal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.RevealSecretFieldForPrincipalResponse{Value: val}, nil
}

// plainReadForPrincipal releases a NON-sensitive field. A person reads these
// through GetSecretFields with no reveal, view bump or Informed notice, so a
// principal gets the same treatment; only a plain read audit is added because
// a principal has no UI session trail. The token approval toggle does not
// apply: it gates reveals of secret values only.
func (s *Server) plainReadForPrincipal(ctx context.Context, actor *vaultv1.ActorContext, sec *vaultv1.Secret, fieldKey, val string) *vaultv1.RevealSecretFieldForPrincipalResponse {
	attrs := map[string]string{
		"principal_kind": actor.GetPrincipalKind().String(),
		"principal_id":   actor.GetPrincipalId(),
	}
	if isUserToken(actor) {
		attrs["token_id"] = actor.GetTokenId()
		attrs["via"] = "mcp"
	}
	l := s.lg(ctx)
	l.Info("principal read a non-sensitive field", log.F("secret_id", sec.GetId()), log.F("field_key", fieldKey), log.F("principal_kind", actor.GetPrincipalKind().String()))
	s.emitAttrs(ctx, principalActorID(actor), "secret.read.principal", sec.Id+"#"+fieldKey, false, attrs)
	return &vaultv1.RevealSecretFieldForPrincipalResponse{Value: val}
}

// CopySecret reveals the secret's PRIMARY sensitive field for clipboard copy,
// recorded as a distinct audited "copy" event. Returns an empty value if the
// secret's type has no sensitive field.
func (s *Server) CopySecret(ctx context.Context, req *vaultv1.CopySecretRequest) (*vaultv1.CopySecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.findSecret(req.GetId())
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.canRead(req.GetActor(), sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to copy this secret")
	}
	t := s.findType(sec.TypeId)
	var key string
	for _, f := range t.GetFields() {
		if s.isSensitiveField(t, f.GetKey()) {
			key = f.GetKey()
			break
		}
	}
	if key == "" {
		return &vaultv1.CopySecretResponse{Value: ""}, nil
	}
	rec, ok := s.records[sec.Id]
	if !ok {
		return nil, errNotFound("secret value")
	}
	val, err := s.crypt.Open(rec, key)
	if err == crypto.ErrFieldNotFound {
		return &vaultv1.CopySecretResponse{Value: ""}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "copy: %v", err)
	}
	bumpView(sec)
	s.emit(ctx, req.GetActor().GetUserId(), "secret.copy", sec.Id+"#"+key, true)
	s.notifyInformed(ctx, req.GetActor().GetUserId(), "secret.copy", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.CopySecretResponse{Value: val}, nil
}
