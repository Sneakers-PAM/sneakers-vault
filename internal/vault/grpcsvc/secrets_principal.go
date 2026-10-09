// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Non-human principal operations on top of RevealSecretFieldForPrincipal: a service-account or workload principal — never PRINCIPAL_KIND_HUMAN —
// may discover (RACI-read filtered), create, and generate+store secrets using
// the same RACI engine humans use, via evalOf's machine branch. Kept out of the
// already-large secrets.go.
package grpcsvc

import (
	"context"
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListSecretsForPrincipal returns the metadata of secrets the non-human
// principal may READ (RACI C), optionally filtered by name/folder/type and by
// changed_since (value changed at or after it). Field
// values are never included — Secret is a metadata-only message.
func (s *Server) ListSecretsForPrincipal(ctx context.Context, req *vaultv1.ListSecretsForPrincipalRequest) (*vaultv1.ListSecretsForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal list is for non-human principals")
	}
	since, err := parseChangedSince(req.GetChangedSince())
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := strings.ToLower(strings.TrimSpace(req.GetQuery()))
	out := make([]*vaultv1.Secret, 0)
	for _, sec := range s.secrets {
		if sec.GetRetired() {
			continue
		}
		if fid := req.GetFolderId(); fid != "" && sec.GetFolderId() != fid {
			continue
		}
		if tid := req.GetTypeId(); tid != "" && sec.GetTypeId() != tid {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(sec.GetName()), q) {
			continue
		}
		if !changedSince(sec, since) {
			continue
		}
		if !s.canRead(actor, sec) {
			continue
		}
		out = append(out, s.principalSecretView(sec))
	}
	attrs := map[string]string{
		"principal_kind": actor.GetPrincipalKind().String(),
		"principal_id":   actor.GetPrincipalId(),
		"count":          strconv.Itoa(len(out)),
	}
	if !since.IsZero() {
		attrs["changed_since"] = req.GetChangedSince()
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.list.principal", req.GetFolderId(), false, attrs)
	return &vaultv1.ListSecretsForPrincipalResponse{Secrets: out}, nil
}

// CreateSecretForPrincipal creates a secret as a non-human principal. Requires
// RACI-Author (R) on the folder chain — the same grant human CreateSecret
// requires — never a spoofed admin flag (evalOf strips admin for machines).
func (s *Server) CreateSecretForPrincipal(ctx context.Context, req *vaultv1.CreateSecretForPrincipalRequest) (*vaultv1.CreateSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal create is for non-human principals")
	}
	if req.GetName() == "" || req.GetFolderId() == "" || req.GetTypeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, folder_id and type_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findType(req.GetTypeId()) == nil {
		return nil, errNotFound("secret type")
	}
	if !s.canManage(actor, req.GetFolderId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to create a secret in this folder")
	}
	if err := s.principalUsableTarget(ctx, actor, req.GetTargetId()); err != nil {
		return nil, err
	}
	sec, err := s.buildAndStoreSecret(ctx, actor, newSecretSpec{
		folderID: req.GetFolderId(), typeID: req.GetTypeId(), targetID: req.GetTargetId(), name: req.GetName(),
		disableRotation: req.GetDisableRotation(), disableHeartbeat: req.GetDisableHeartbeat(),
	}, req.GetFields())
	if err != nil {
		return nil, err
	}
	return &vaultv1.CreateSecretForPrincipalResponse{Secret: s.principalSecretView(sec)}, nil
}

// newSecretSpec is the metadata of a principal-created secret.
type newSecretSpec struct {
	folderID, typeID, targetID, name  string
	disableRotation, disableHeartbeat bool
}

// buildAndStoreSecret factors the shared create body used by
// CreateSecretForPrincipal and GenerateSecretForPrincipal: verify,
// build, seal, store, version, audit as secret.create.principal, and bootstrap
// heartbeat/rotation via ensureLifecycle (the exact block CreateSecret runs).
// Caller holds s.mu (write lock) and has already gated canManage/typeId.
func (s *Server) buildAndStoreSecret(ctx context.Context, actor *vaultv1.ActorContext, spec newSecretSpec, fields map[string]string) (*vaultv1.Secret, error) {
	// Authoritative server-side check that a submitted SSH private/public
	// key pair actually correspond, before anything is sealed and stored.
	if err := verifyKeyPairFields(fields); err != nil {
		return nil, err
	}
	// The opt-outs are set before ensureLifecycle so an opted-out secret never
	// gets a schedule row, not even briefly.
	sec := &vaultv1.Secret{
		Id: s.nextID("secret"), Name: spec.name, FolderId: spec.folderID, TypeId: spec.typeID, TargetId: spec.targetID,
		RotationOptOut: spec.disableRotation, HeartbeatOptOut: spec.disableHeartbeat,
		Position: s.nextPosition(spec.folderID),
	}
	rec, err := s.crypt.Seal(fields)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal fields: %v", err)
	}
	s.secrets = append(s.secrets, sec)
	s.records[sec.Id] = rec
	var ledgerNo int
	if s.vers != nil {
		ledgerNo, _ = s.vers.AppendActive(ctx, sec.Id, rec, principalActorID(actor))
	}
	s.markValueChanged(ctx, sec, ledgerNo)
	var optOuts map[string]string
	if spec.disableRotation || spec.disableHeartbeat {
		optOuts = map[string]string{
			"rotation_opt_out":  strconv.FormatBool(spec.disableRotation),
			"heartbeat_opt_out": strconv.FormatBool(spec.disableHeartbeat),
		}
		l := s.lg(ctx)
		l.Info("principal created secret with automation opt-out", log.F("secret_id", sec.Id), log.F("rotation_opt_out", spec.disableRotation), log.F("heartbeat_opt_out", spec.disableHeartbeat))
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.create.principal", sec.Id, true, principalAttrs(actor, optOuts))
	s.ensureLifecycle(ctx, sec)
	return sec, nil
}

// passwordFieldKey returns the key of st's password-kind field (the field
// generate fills in), or "" if the type declares none.
func passwordFieldKey(st *vaultv1.SecretType) string {
	for _, f := range st.GetFields() {
		if f.GetKind() == vaultv1.FieldKind_FIELD_KIND_PASSWORD {
			return f.GetKey()
		}
	}
	return ""
}

// passwordPolicyForField resolves the policy GenerateSecretForPrincipal should
// use: an explicit policyID override if given, else the policy bound to the
// type's password field, else the instance default — reusing rotation.go's
// resolvePolicy (the exact resolution ReportRotation/EnqueueRotation already
// perform via policyForSecret) rather than reinventing policy lookup. Caller
// holds s.mu.
func (s *Server) passwordPolicyForField(st *vaultv1.SecretType, fieldKey, policyID string) *vaultv1.PasswordPolicy {
	if policyID != "" {
		return s.resolvePolicy(policyID)
	}
	var fieldPolicyID string
	for _, f := range st.GetFields() {
		if f.GetKey() == fieldKey && f.GetKind() == vaultv1.FieldKind_FIELD_KIND_PASSWORD {
			fieldPolicyID = f.GetPolicyId()
			break
		}
	}
	return s.resolvePolicy(fieldPolicyID)
}

// GenerateSecretForPrincipal generates a policy-compliant password for the
// type's password field and stores the secret, as a non-human principal.
// Requires RACI-Author (R), same as CreateSecretForPrincipal. The generated
// value is returned ONLY when return_value=true, and that disclosure is
// separately audited (secret.generate.value_returned.principal) — the
// create itself is audited via buildAndStoreSecret's secret.create.principal.
func (s *Server) GenerateSecretForPrincipal(ctx context.Context, req *vaultv1.GenerateSecretForPrincipalRequest) (*vaultv1.GenerateSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal generate is for non-human principals")
	}
	if req.GetName() == "" || req.GetFolderId() == "" || req.GetTypeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, folder_id and type_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.findType(req.GetTypeId())
	if st == nil {
		return nil, errNotFound("secret type")
	}
	if !s.canManage(actor, req.GetFolderId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to create a secret in this folder")
	}
	if err := s.principalUsableTarget(ctx, actor, req.GetTargetId()); err != nil {
		return nil, err
	}
	pwField := passwordFieldKey(st)
	if pwField == "" {
		return nil, status.Error(codes.InvalidArgument, "type has no generatable password field")
	}
	policy := s.passwordPolicyForField(st, pwField, req.GetPolicyId())
	pw, err := GeneratePassword(policy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate password: %v", err)
	}
	fields := make(map[string]string, len(req.GetFields())+1)
	for k, v := range req.GetFields() {
		fields[k] = v
	}
	fields[pwField] = pw
	sec, err := s.buildAndStoreSecret(ctx, actor, newSecretSpec{
		folderID: req.GetFolderId(), typeID: req.GetTypeId(), targetID: req.GetTargetId(), name: req.GetName(),
		disableRotation: req.GetDisableRotation(), disableHeartbeat: req.GetDisableHeartbeat(),
	}, fields)
	if err != nil {
		return nil, err
	}
	resp := &vaultv1.GenerateSecretForPrincipalResponse{Secret: s.principalSecretView(sec)}
	if req.GetReturnValue() {
		resp.GeneratedValue = pw
		s.emitAttrs(ctx, principalActorID(actor), "secret.generate.value_returned.principal", sec.Id, true, map[string]string{
			"principal_kind": actor.GetPrincipalKind().String(),
			"principal_id":   actor.GetPrincipalId(),
		})
	}
	return resp, nil
}
