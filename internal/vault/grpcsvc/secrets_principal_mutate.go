// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Non-human principal move + change-type. Same authz as the human edit
// path (UpdateSecret): RACI Author via canManage, evaluated through evalOf so a
// machine never inherits admin authority. Non-human principals only.
package grpcsvc

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/certsvc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// canManageSecretAsPrincipal is the machine edit gate on an existing secret:
// RACI Author on the secret's folder chain (the human UpdateSecret gate,
// canManageOrOwnSecret, minus folder ownership which is keyed by human user id
// and never matches a machine) AND Author on the secret's own chain, so a
// per-secret deny override is honoured. In a personal subtree everyone rules
// are ignored (principalFolderAccess/principalSecretAccess): a machine reaches
// personal content only through an explicit grant. Strictly at least as tight
// as the human gate. Caller holds s.mu.
func (s *Server) canManageSecretAsPrincipal(a *vaultv1.ActorContext, sec *vaultv1.Secret) bool {
	return s.principalFolderAccess(a, sec.GetFolderId()).Author.Allowed && s.principalSecretAccess(a, sec).Author.Allowed
}

// principalMutableSecret resolves the secret for a machine mutation and applies
// the shared gates: exists, not retired, Author on it. Caller holds s.mu.
func (s *Server) principalMutableSecret(actor *vaultv1.ActorContext, id, verb string) (*vaultv1.Secret, error) {
	sec := s.findSecret(id)
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if sec.GetRetired() {
		return nil, status.Error(codes.FailedPrecondition, "secret is retired")
	}
	if !s.canManageSecretAsPrincipal(actor, sec) {
		return nil, status.Errorf(codes.PermissionDenied, "not permitted to %s this secret", verb)
	}
	return sec, nil
}

func principalAttrs(actor *vaultv1.ActorContext, extra map[string]string) map[string]string {
	out := map[string]string{
		"principal_kind": actor.GetPrincipalKind().String(),
		"principal_id":   actor.GetPrincipalId(),
	}
	if id := actor.GetTokenId(); id != "" {
		out["token_id"] = id
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// MoveSecretForPrincipal moves a secret to another folder as a non-human
// principal, mirroring UpdateSecret's dest_folder_id move: Author on the
// source and on the destination folder chain (a personal destination only via
// an explicit grant). A move into a personal folder happens directly only when
// it rearranges within the same owner's personal tree (the human rule); every
// other personal destination needs a site-admin approval: the vault moves
// nothing and returns approval_required, and the gateway files the request.
// The secret keeps its id, sealed record, versions and audit history.
func (s *Server) MoveSecretForPrincipal(ctx context.Context, req *vaultv1.MoveSecretForPrincipalRequest) (*vaultv1.MoveSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal move is for non-human principals")
	}
	if req.GetId() == "" || req.GetDestFolderId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id and dest_folder_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetId(), "move")
	if err != nil {
		return nil, err
	}
	dest := req.GetDestFolderId()
	if dest == sec.GetFolderId() {
		return nil, status.Error(codes.InvalidArgument, "secret is already in that folder")
	}
	df := s.findFolder(dest)
	if df == nil {
		return nil, errNotFound("destination folder")
	}
	destAccess := s.principalFolderAccess(actor, dest)
	if !destAccess.Author.Allowed {
		return nil, status.Error(codes.PermissionDenied, "not permitted to move the secret to that folder")
	}
	destView := principalFolderView(df, true)
	moveAttrs := principalAttrs(actor, map[string]string{
		"from_folder_id": sec.GetFolderId(),
		"to_folder_id":   dest,
	})
	if destPersonal, destOwner := s.destPersonal(df); destPersonal {
		src := s.findFolder(sec.GetFolderId())
		alreadyYours := src.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && src.GetOwnerUserId() == destOwner
		if !alreadyYours {
			// The human route is a site-admin approval; so is the machine's.
			// Every RACI check has passed; move nothing and let the gateway file
			// the approval request with this principal as requester.
			s.emitAttrs(ctx, principalActorID(actor), "secret.move.approval_required.principal", sec.GetId(), false, moveAttrs)
			return &vaultv1.MoveSecretForPrincipalResponse{Secret: sec, ApprovalRequired: true, Destination: destView}, nil
		}
	}
	sec.FolderId = dest
	s.emitAttrs(ctx, principalActorID(actor), "secret.move.principal", sec.GetId(), false, moveAttrs)
	s.notifyInformed(ctx, principalActorID(actor), "secret.move.principal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.MoveSecretForPrincipalResponse{Secret: sec, Destination: destView}, nil
}

// machineTypeChangeBlocked reports why a machine may not change a secret from
// st to nt, or "" if it may. Dropping checkout lifts a human governance
// control, so it stays human-only for plain checkout types. Every
// rotation/heartbeat type carries checkout, and converting out of those is
// allowed outright, so they are exempt.
func machineTypeChangeBlocked(st, nt *vaultv1.SecretType) string {
	if st.GetCheckout() && !nt.GetCheckout() && !st.GetRotation() && !st.GetHeartbeat() {
		return "changing to a type without checkout requires a human"
	}
	return ""
}

// connectableTypeIDs take a target without having heartbeat or rotation: the
// target is the host a session opens to. Mirrors the staff UI's CONNECTABLE set.
var connectableTypeIDs = map[string]bool{"type-ssh-key": true, "type-unix-ssh": true}

// typeTakesTarget reports whether secrets of t can carry a target.
func typeTakesTarget(t *vaultv1.SecretType) bool {
	return t.GetHeartbeat() || t.GetRotation() || connectableTypeIDs[t.GetId()]
}

// retypeOutcome is what a type change did to a secret's automation and target.
// rotation: none | off. heartbeat: none | scheduled | no_target | opted_out.
// target: none | kept | detached.
type retypeOutcome struct {
	rotation, heartbeat, target, fromTargetID string
}

// certRetypeFields validates material converted into the certificate type the
// way ImportCertificate validates an upload, and adds the derived metadata an
// import stores. A derived key that already carries a different value is
// refused rather than overwritten. Returns the certificate's expiry. Errors
// name fields, never values.
func certRetypeFields(out map[string]string) (string, error) {
	derived, meta, err := certsvc.StoredFieldsMeta(out)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "type change into the certificate type: "+strings.TrimPrefix(err.Error(), "certsvc: "))
	}
	for _, k := range sortedKeys(derived) {
		if v := out[k]; v != "" && v != derived[k] {
			return "", status.Errorf(codes.InvalidArgument,
				"field %q carries a value that differs from the one derived from the certificate; map it to another field with field_mapping", k)
		}
		out[k] = derived[k]
	}
	return certExpiresAt(meta), nil
}

// retypeChecks runs the checks every save runs on the new plaintext, plus the
// certificate validation when nt is the certificate type, and returns the
// secret's expiry under nt.
func (s *Server) retypeChecks(ctx context.Context, sec *vaultv1.Secret, nt *vaultv1.SecretType, next map[string]string) (string, error) {
	// The same authoritative key-pair check every save runs.
	if err := verifyKeyPairFields(next); err != nil {
		return "", err
	}
	if nt.GetId() != certSecretTypeID {
		return sec.GetExpiresAt(), nil
	}
	exp, err := certRetypeFields(next)
	if err != nil {
		l := s.lg(ctx)
		l.Info("type change refused: certificate material does not validate", log.F("secret_id", sec.GetId()))
		return "", err
	}
	return exp, nil
}

// applyRetypeAutomation brings a retyped secret's target and schedules in line
// with its new type. Rotation is opted out after any change into a rotation
// type, so a credential nobody has reviewed under its new type is never rotated
// unasked. Heartbeat follows the new type only when the secret has a target
// whose connection exists. Schedule rows of the old type are removed, which
// also drops their claims. Caller holds s.mu (write).
func (s *Server) applyRetypeAutomation(ctx context.Context, sec *vaultv1.Secret, st, nt *vaultv1.SecretType) retypeOutcome {
	o := retypeOutcome{rotation: "none", target: "none", fromTargetID: sec.GetTargetId()}
	if o.fromTargetID != "" {
		o.target = "kept"
		if !typeTakesTarget(nt) {
			sec.TargetId = ""
			o.target = "detached"
		}
	}
	s.retypeRotation(ctx, sec, st, nt)
	if nt.GetRotation() {
		o.rotation = "off"
	}
	o.heartbeat = s.retypeHeartbeat(ctx, sec, st, nt)
	l := s.lg(ctx)
	l.Info("type change automation applied", log.F("secret_id", sec.GetId()), log.F("from_type_id", st.GetId()), log.F("to_type_id", nt.GetId()), log.F("rotation", o.rotation), log.F("heartbeat", o.heartbeat), log.F("target", o.target), log.F("from_target_id", o.fromTargetID))
	return o
}

// retypeRotation removes any rotation row the old type left and opts the
// secret out of rotation when the new type rotates. Caller holds s.mu (write).
func (s *Server) retypeRotation(ctx context.Context, sec *vaultv1.Secret, st, nt *vaultv1.SecretType) {
	if s.rot != nil && (st.GetRotation() || nt.GetRotation()) {
		if err := s.rot.Remove(ctx, sec.GetId()); err != nil {
			l := s.lg(ctx)
			l.Error(err, "remove rotation schedule on type change failed", log.F("secret_id", sec.GetId()))
		}
	}
	if nt.GetRotation() {
		sec.RotationOptOut = true
	}
}

// retypeHeartbeat creates or removes the heartbeat row for the new type and
// returns the outcome. Caller holds s.mu (write).
func (s *Server) retypeHeartbeat(ctx context.Context, sec *vaultv1.Secret, st, nt *vaultv1.SecretType) string {
	outcome := "none"
	switch {
	case !nt.GetHeartbeat():
	case sec.GetHeartbeatOptOut():
		outcome = "opted_out"
	case !s.rotationReachable(sec):
		outcome = "no_target"
	default:
		outcome = "scheduled"
	}
	if s.hb == nil || (!st.GetHeartbeat() && !nt.GetHeartbeat()) {
		return outcome
	}
	var err error
	if outcome == "scheduled" {
		err = s.hb.Ensure(ctx, sec.GetId(), int(sec.GetHeartbeatIntervalSeconds()))
	} else {
		err = s.hb.Remove(ctx, sec.GetId())
	}
	if err != nil {
		l := s.lg(ctx)
		l.Error(err, "heartbeat schedule update on type change failed", log.F("secret_id", sec.GetId()), log.F("heartbeat", outcome))
	}
	return outcome
}

// retypeAllowed applies machineTypeChangeBlocked, and refuses a type change
// while a rotation of a rotation-type secret is claimed: the connector may
// already have changed the credential, and its report must still find the
// schedule row. Caller holds s.mu.
func (s *Server) retypeAllowed(ctx context.Context, sec *vaultv1.Secret, st, nt *vaultv1.SecretType) error {
	if why := machineTypeChangeBlocked(st, nt); why != "" {
		return status.Error(codes.FailedPrecondition, why)
	}
	if !st.GetRotation() || s.rot == nil {
		return nil
	}
	l := s.lg(ctx)
	claimed, err := s.rot.Claimed(ctx, sec.GetId())
	if err != nil {
		l.Error(err, "type change: rotation claim check failed", log.F("secret_id", sec.GetId()))
		return status.Error(codes.Internal, "check rotation claim")
	}
	if claimed {
		l.Info("type change refused: rotation in flight", log.F("secret_id", sec.GetId()))
		return status.Error(codes.FailedPrecondition, "a rotation of this secret is in progress; retry the type change once it finishes")
	}
	return nil
}

func fieldDef(t *vaultv1.SecretType, key string) *vaultv1.SecretFieldDef {
	for _, f := range t.GetFields() {
		if f.GetKey() == key {
			return f
		}
	}
	return nil
}

func defSensitive(f *vaultv1.SecretFieldDef) bool {
	return f.GetKind() == vaultv1.FieldKind_FIELD_KIND_PASSWORD || f.GetSensitive() || f.GetSuperSensitive()
}

// retypeResult is retypeFields' output: the new plaintext, plus which old keys
// (if any) were appended to the new type's notes field and which field that was.
type retypeResult struct {
	fields   map[string]string
	moved    []string
	notesKey string
}

// retypeFields computes the new plaintext for a type change from st to nt.
// Every non-empty stored value lands in a field of nt (identical key, or
// mapping[old]=new, which always wins). A value with nowhere to go is never
// dropped: under the NOTES policy (the default) it is appended to nt's notes
// field (appendToNotes), under REFUSE the call fails. Sensitivity never
// decreases. extra fills only keys the mapping left empty. Errors name field
// keys, never values.
//
//nolint:gocognit,gocyclo // a flat sequence of independent validation rules
func retypeFields(st, nt *vaultv1.SecretType, cur, mapping, extra map[string]string, policy vaultv1.UnmappedFieldPolicy) (retypeResult, error) {
	for from, to := range mapping {
		if _, stored := cur[from]; !stored && fieldDef(st, from) == nil {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "field_mapping source %q is not a field of this secret", from)
		}
		if to == "" || fieldDef(nt, to) == nil {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "field_mapping target for %q is not a field of the new type", from)
		}
	}
	out := map[string]string{}
	srcOf := map[string]string{}
	var unmapped, downgraded []string
	for _, from := range sortedKeys(cur) {
		v := cur[from]
		if v == "" {
			continue // an empty field holds no value to lose
		}
		to := from
		if m, ok := mapping[from]; ok {
			to = m
		}
		nf := fieldDef(nt, to)
		if nf == nil {
			unmapped = append(unmapped, from)
			continue
		}
		if prev, dup := srcOf[to]; dup {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "fields %q and %q both map to %q", prev, from, to)
		}
		srcOf[to] = from
		// A stored key the old type no longer declares is treated as sensitive.
		of := fieldDef(st, from)
		srcSensitive := of == nil || defSensitive(of)
		switch {
		case srcSensitive && !defSensitive(nf):
			downgraded = append(downgraded, from+" (sensitive -> "+to+")")
		case of.GetSuperSensitive() && !nf.GetSuperSensitive():
			downgraded = append(downgraded, from+" (super-sensitive -> "+to+")")
		}
		out[to] = v
	}
	if len(unmapped) > 0 && policy == vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE {
		return retypeResult{}, status.Errorf(codes.FailedPrecondition,
			"type change would drop the value of field(s) %s: map each to a field of the new type with field_mapping",
			strings.Join(unmapped, ", "))
	}
	if len(downgraded) > 0 {
		return retypeResult{}, status.Errorf(codes.FailedPrecondition,
			"type change would lower field protection: %s", strings.Join(downgraded, ", "))
	}
	for _, k := range sortedKeys(extra) {
		if fieldDef(nt, k) == nil {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "field %q is not a field of the new type", k)
		}
		if _, carried := out[k]; carried {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "field %q already carries a value over; fields cannot overwrite it", k)
		}
		if extra[k] != "" {
			out[k] = extra[k]
		}
	}
	res := retypeResult{fields: out}
	if len(unmapped) > 0 {
		nk, err := appendToNotes(st, nt, out, cur, unmapped)
		if err != nil {
			return retypeResult{}, err
		}
		res.moved, res.notesKey = unmapped, nk
	}
	for _, f := range nt.GetFields() {
		v, ok := out[f.GetKey()]
		if !ok {
			if f.GetRequired() {
				return retypeResult{}, status.Errorf(codes.InvalidArgument, "the new type requires field %q", f.GetKey())
			}
			continue
		}
		if ml := f.GetMaxLength(); ml > 0 && utf8.RuneCountInString(v) > int(ml) {
			return retypeResult{}, status.Errorf(codes.InvalidArgument, "value for field %q exceeds the new type's max length", f.GetKey())
		}
		if p := f.GetPattern(); p != "" {
			if re, err := regexp.Compile(p); err == nil && !re.MatchString(v) {
				return retypeResult{}, status.Errorf(codes.InvalidArgument, "value for field %q does not match the new type's pattern", f.GetKey())
			}
		}
	}
	return res, nil
}

// notesFieldKey picks the new type's notes field for unmapped values: "notes",
// else "note" (type-secure-note), else "" (none).
func notesFieldKey(nt *vaultv1.SecretType) string {
	for _, k := range []string{"notes", "note"} {
		if fieldDef(nt, k) != nil {
			return k
		}
	}
	return ""
}

// jsonString encodes v as a JSON string literal without HTML escaping, so a
// value round-trips exactly through the "[moved from k]: <json>" note lines.
func jsonString(v string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}

// appendToNotes appends each unmapped old value to nt's notes field, one line
// per key in key order, "[moved from <key>]: <value as a JSON string>",
// separated from existing notes by a blank line. Fails closed (keys only, never
// values) when nt has no notes field, when a sensitive/super-sensitive value
// would land in a less-protected notes field, or when the result would exceed
// the field's max_length (never truncated). Mutates out on success.
func appendToNotes(st, nt *vaultv1.SecretType, out, cur map[string]string, unmapped []string) (string, error) {
	nk := notesFieldKey(nt)
	if nk == "" {
		return "", status.Errorf(codes.FailedPrecondition,
			"type change would drop the value of field(s) %s: the new type has no notes field to move them into; map each to a field of the new type with field_mapping",
			strings.Join(unmapped, ", "))
	}
	nf := fieldDef(nt, nk)
	var tooSensitive []string
	for _, from := range unmapped {
		of := fieldDef(st, from)
		srcSensitive := of == nil || defSensitive(of) // an undeclared stored key counts as sensitive
		if (srcSensitive && !defSensitive(nf)) || (of.GetSuperSensitive() && !nf.GetSuperSensitive()) {
			tooSensitive = append(tooSensitive, from)
		}
	}
	if len(tooSensitive) > 0 {
		return "", status.Errorf(codes.FailedPrecondition,
			"type change would move protected field(s) %s into the less-protected notes field %q; map each to a field of the new type with the same protection using field_mapping",
			strings.Join(tooSensitive, ", "), nk)
	}
	lines := make([]string, 0, len(unmapped))
	for _, from := range unmapped {
		lines = append(lines, "[moved from "+from+"]: "+jsonString(cur[from]))
	}
	notes := out[nk]
	if notes != "" {
		notes += "\n\n"
	}
	notes += strings.Join(lines, "\n")
	if ml := nf.GetMaxLength(); ml > 0 && utf8.RuneCountInString(notes) > int(ml) {
		return "", status.Errorf(codes.FailedPrecondition,
			"moving field(s) %s into the notes field %q would exceed its max length; map them with field_mapping or use a type with room",
			strings.Join(unmapped, ", "), nk)
	}
	out[nk] = notes
	return nk, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ChangeSecretTypeForPrincipal changes a secret's type as a non-human
// principal. Requires Author on the secret (the human edit gate). The stored
// values are re-keyed per retypeFields (never dropped, never down-classified),
// re-sealed as a new active version (the prior values stay in version history)
// and the change is audited as the principal. Into the certificate type the
// material must parse as an import's (certRetypeFields); the target and
// schedules then follow the new type (applyRetypeAutomation). Refused while a
// rotation of the secret is in flight (retypeAllowed).
func (s *Server) ChangeSecretTypeForPrincipal(ctx context.Context, req *vaultv1.ChangeSecretTypeForPrincipalRequest) (*vaultv1.ChangeSecretTypeForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal type change is for non-human principals")
	}
	if req.GetId() == "" || req.GetNewTypeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id and new_type_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetId(), "change the type of")
	if err != nil {
		return nil, err
	}
	nt := s.findType(req.GetNewTypeId())
	if nt == nil {
		return nil, errNotFound("secret type")
	}
	if nt.GetId() == sec.GetTypeId() {
		return nil, status.Error(codes.InvalidArgument, "secret already has that type")
	}
	st := s.findType(sec.GetTypeId())
	if st == nil {
		return nil, status.Error(codes.FailedPrecondition, "secret's current type is unknown; a human must repair it")
	}
	if err := s.retypeAllowed(ctx, sec, st, nt); err != nil {
		return nil, err
	}
	cur := map[string]string{}
	if rec, ok := s.records[sec.GetId()]; ok {
		opened, err := s.crypt.OpenAll(rec)
		if err != nil {
			return nil, status.Error(codes.Internal, "open existing record")
		}
		cur = opened
	}
	rt, err := retypeFields(st, nt, cur, req.GetFieldMapping(), req.GetFields(), req.GetUnmappedFields())
	if err != nil {
		return nil, err
	}
	next := rt.fields
	expiresAt, err := s.retypeChecks(ctx, sec, nt, next)
	if err != nil {
		return nil, err
	}
	rec, err := s.crypt.Seal(next)
	if err != nil {
		return nil, status.Error(codes.Internal, "seal fields")
	}
	from := sec.GetTypeId()
	s.records[sec.GetId()] = rec
	sec.TypeId = nt.GetId()
	sec.ExpiresAt = expiresAt
	if s.vers != nil {
		_, _ = s.vers.AppendActive(ctx, sec.GetId(), rec, principalActorID(actor))
	}
	auto := s.applyRetypeAutomation(ctx, sec, st, nt)
	keys := sortedKeys(next)
	s.emitAttrs(ctx, principalActorID(actor), "secret.type_change.principal", sec.GetId(), true, principalAttrs(actor, map[string]string{
		"from_type_id":        from,
		"to_type_id":          nt.GetId(),
		"field_keys":          strings.Join(keys, ","),
		"moved_to_notes_keys": strings.Join(rt.moved, ","),
		"rotation_managed":    strconv.FormatBool(nt.GetRotation()),
		"heartbeat_managed":   strconv.FormatBool(nt.GetHeartbeat()),
		"rotation":            auto.rotation,
		"heartbeat":           auto.heartbeat,
		"target":              auto.target,
		"from_target_id":      auto.fromTargetID,
		"target_id":           sec.GetTargetId(),
	}))
	s.notifyInformed(ctx, principalActorID(actor), "secret.type_change.principal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret: sec, FieldKeys: keys, MovedToNotesKeys: rt.moved, NotesFieldKey: rt.notesKey,
	}, nil
}

// principalUsableTarget checks a target id a principal wants to attach: empty
// (no target) is fine; otherwise it must exist and be shared or owned by the
// token's user. Caller holds s.mu.
func (s *Server) principalUsableTarget(ctx context.Context, actor *vaultv1.ActorContext, id string) error {
	if id == "" {
		return nil
	}
	l := s.lg(ctx)
	t := findByID(s.targets, id)
	if t == nil {
		l.Info("principal target refused: not found", log.F("target_id", id), log.F("principal_kind", actor.GetPrincipalKind().String()))
		return errNotFound("target")
	}
	if t.GetOwnerUserId() != "" && t.GetOwnerUserId() != actor.GetUserId() {
		l.Warn("principal target refused: another user's target", log.F("target_id", id), log.F("principal_kind", actor.GetPrincipalKind().String()))
		return status.Error(codes.PermissionDenied, "not permitted to use this target")
	}
	return nil
}

// SetSecretTargetForPrincipal attaches or detaches a secret's target for a
// non-human principal with RACI-Author on the secret. The target must be one
// the principal can see: shared, or owned by the token's user.
func (s *Server) SetSecretTargetForPrincipal(ctx context.Context, req *vaultv1.SetSecretTargetForPrincipalRequest) (*vaultv1.SetSecretTargetForPrincipalResponse, error) {
	actor := req.GetActor()
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, status.Error(codes.PermissionDenied, "principal target change is for non-human principals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetSecretId(), "change the target of")
	if err != nil {
		return nil, err
	}
	if err := s.principalUsableTarget(ctx, actor, req.GetTargetId()); err != nil {
		return nil, err
	}
	from := sec.GetTargetId()
	sec.TargetId = req.GetTargetId()
	if sec.TargetId != "" && sec.TargetId != from {
		s.ensureRotationScheduled(ctx, sec)
		s.ensureHeartbeatScheduled(ctx, sec)
	}
	l := s.lg(ctx)
	l.Info("secret target changed by principal", log.F("secret_id", sec.GetId()), log.F("from_target_id", from), log.F("target_id", sec.GetTargetId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
	s.emitAttrs(ctx, principalActorID(actor), "secret.target.principal", sec.GetId(), false, principalAttrs(actor, map[string]string{
		"from_target_id": from, "target_id": sec.GetTargetId(),
	}))
	return &vaultv1.SetSecretTargetForPrincipalResponse{Secret: sec}, nil
}

// SetSecretAutomationForPrincipal opts a secret out of (or back into) rotation
// and heartbeat for a non-human principal with RACI-Author on the secret. Same
// schedule handling as SetSecretAutomation; audited as the principal.
func (s *Server) SetSecretAutomationForPrincipal(ctx context.Context, req *vaultv1.SetSecretAutomationForPrincipalRequest) (*vaultv1.SetSecretAutomationForPrincipalResponse, error) {
	actor := req.GetActor()
	l := s.lg(ctx)
	if actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		l.Warn("principal automation change refused for a human caller", log.F("secret_id", req.GetSecretId()))
		return nil, status.Error(codes.PermissionDenied, "principal automation change is for non-human principals")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetSecretId(), "change the automation of")
	if err != nil {
		l.Info("principal automation change refused", log.F("error", err.Error()), log.F("secret_id", req.GetSecretId()), log.F("principal_kind", actor.GetPrincipalKind().String()))
		return nil, err
	}
	if err := s.applyAutomation(ctx, sec, req.GetDisableRotation(), req.GetDisableHeartbeat(), func(action string) {
		s.emitAttrs(ctx, principalActorID(actor), action+".principal", sec.GetId(), false, principalAttrs(actor, nil))
	}); err != nil {
		return nil, err
	}
	return &vaultv1.SetSecretAutomationForPrincipalResponse{Secret: sec}, nil
}
