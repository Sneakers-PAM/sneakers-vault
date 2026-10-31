// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// A secret's type change: the code a person's ChangeSecretType and a machine's
// ChangeSecretTypeForPrincipal share, and the person's RPCs with their preview.
// The two paths differ only in who may call them, how they are audited, and
// that a person may drop checkout. See docs/type-change.md.
package grpcsvc

import (
	"context"
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Stable refusal reasons for a type change. The ErrorInfo metadata carries
// "fields": the field keys involved, joined by commas. Never values.
const (
	// ReasonTypeChangeUnmappedFields: a value has no field and may not move to
	// notes, under unmapped_fields = REFUSE or because the new type has no notes.
	ReasonTypeChangeUnmappedFields = "TYPE_CHANGE_UNMAPPED_FIELDS"
	// ReasonTypeChangeLowersProtection: a value would land in a less protected
	// field, the notes field included.
	ReasonTypeChangeLowersProtection = "TYPE_CHANGE_LOWERS_PROTECTION"
	// ReasonTypeChangeNotesTooLong: moving values to notes would pass its max length.
	ReasonTypeChangeNotesTooLong = "TYPE_CHANGE_NOTES_TOO_LONG"
	// ReasonTypeChangeInvalidField: a mapping or a value doesn't fit the new
	// type (unknown field, two sources for one field, length, pattern, key pair).
	ReasonTypeChangeInvalidField = "TYPE_CHANGE_INVALID_FIELD"
	// ReasonTypeChangeCertificateInvalid: the material doesn't validate as a
	// certificate, or a stored value differs from the one derived from it.
	ReasonTypeChangeCertificateInvalid = "TYPE_CHANGE_CERTIFICATE_INVALID"
	// ReasonTypeChangeCheckoutHumanOnly: a machine tried to drop checkout.
	ReasonTypeChangeCheckoutHumanOnly = "TYPE_CHANGE_CHECKOUT_HUMAN_ONLY"
)

// retypeRefusal is a refusal with its reason and the field keys it concerns.
func retypeRefusal(code codes.Code, reason, msg string, keys ...string) error {
	st := status.New(code, msg)
	info := &errdetails.ErrorInfo{Domain: errorDomain, Reason: reason}
	if len(keys) > 0 {
		info.Metadata = map[string]string{"fields": strings.Join(keys, ",")}
	}
	if d, err := st.WithDetails(info); err == nil {
		return d.Err()
	}
	return st.Err()
}

// retypeRefusalReason returns the ErrorInfo reason on err, or "".
func retypeRefusalReason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}

// retypeInput is what a caller asks of a type change.
type retypeInput struct {
	mapping map[string]string
	extra   map[string]string
	policy  vaultv1.UnmappedFieldPolicy
	human   bool
}

// retypeEval is a type change worked out but not written. cur is set whenever
// the record opened, also when the rules refused the change.
type retypeEval struct {
	st, nt    *vaultv1.SecretType
	cur       map[string]string
	result    retypeResult
	expiresAt string
}

// retypeTypes resolves the two types of a type change. Caller holds s.mu.
func (s *Server) retypeTypes(sec *vaultv1.Secret, newTypeID string) (st, nt *vaultv1.SecretType, err error) {
	nt = s.findType(newTypeID)
	if nt == nil {
		return nil, nil, errNotFound("secret type")
	}
	if nt.GetId() == sec.GetTypeId() {
		return nil, nil, status.Error(codes.InvalidArgument, "secret already has that type")
	}
	st = s.findType(sec.GetTypeId())
	if st == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "secret's current type is unknown; a human must repair it")
	}
	return st, nt, nil
}

// evaluateRetype runs every rule of a type change and writes nothing: who may
// change what (retypeAllowed), the value rules (retypeFields) and the checks on
// the result (retypeChecks). Both paths and the preview go through here. Caller
// holds s.mu.
func (s *Server) evaluateRetype(ctx context.Context, sec *vaultv1.Secret, st, nt *vaultv1.SecretType, in retypeInput) (retypeEval, error) {
	ev := retypeEval{st: st, nt: nt, cur: map[string]string{}}
	if rec, ok := s.records[sec.GetId()]; ok {
		opened, err := s.crypt.OpenAll(rec)
		if err != nil {
			return ev, status.Error(codes.Internal, "open existing record")
		}
		ev.cur = opened
	}
	if err := s.retypeAllowed(ctx, sec, st, nt, in.human); err != nil {
		return ev, err
	}
	var err error
	if ev.result, err = retypeFields(st, nt, ev.cur, in.mapping, in.extra, in.policy); err != nil {
		return ev, err
	}
	ev.expiresAt, err = s.retypeChecks(ctx, sec, nt, ev.result.fields)
	return ev, err
}

// retypeDone is what a written type change reports.
type retypeDone struct {
	keys  []string
	label string
}

// commitRetype writes an evaluated type change: the new sealed values as the
// active version, the type, the automation, the audit event and the informed
// notices. wrapAttrs adds a path's own audit attributes. Caller holds s.mu (write).
func (s *Server) commitRetype(ctx context.Context, sec *vaultv1.Secret, ev retypeEval, mapping map[string]string, actorID, action string, wrapAttrs func(map[string]string) map[string]string) (retypeDone, error) {
	next := ev.result.fields
	rec, err := s.crypt.Seal(next)
	if err != nil {
		return retypeDone{}, status.Error(codes.Internal, "seal fields")
	}
	from := sec.GetTypeId()
	s.records[sec.GetId()] = rec
	sec.TypeId = ev.nt.GetId()
	sec.ExpiresAt = ev.expiresAt
	label := typeChangeLabel(ev.st, ev.nt, mapping, next, ev.result.moved)
	var ledgerNo int
	if s.vers != nil {
		ledgerNo, _ = s.vers.AppendActiveWithNote(ctx, sec.GetId(), rec, actorID, label)
	}
	s.markValueChanged(ctx, sec, ledgerNo)
	auto := s.applyRetypeAutomation(ctx, sec, ev.st, ev.nt)
	keys := sortedKeys(next)
	s.emitAttrs(ctx, actorID, action, sec.GetId(), true, wrapAttrs(map[string]string{
		"from_type_id":        from,
		"to_type_id":          ev.nt.GetId(),
		"field_keys":          strings.Join(keys, ","),
		"moved_to_notes_keys": strings.Join(ev.result.moved, ","),
		"rotation_managed":    strconv.FormatBool(ev.nt.GetRotation()),
		"heartbeat_managed":   strconv.FormatBool(ev.nt.GetHeartbeat()),
		"rotation":            auto.rotation,
		"heartbeat":           auto.heartbeat,
		"target":              auto.target,
		"from_target_id":      auto.fromTargetID,
		"target_id":           sec.GetTargetId(),
		"change_label":        label,
	}))
	s.notifyInformed(ctx, actorID, action, "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return retypeDone{keys: keys, label: label}, nil
}

// canChangeTypeAsPerson is the person's gate: the human edit gate
// (canManageOrOwnSecret), except that a per-secret deny on Author holds, as it
// does for a machine and in GetMySecretAccess. A folder's owner can lift such a
// deny anyway. Caller holds s.mu.
func (s *Server) canChangeTypeAsPerson(a *vaultv1.ActorContext, sec *vaultv1.Secret) bool {
	if s.isFolderOwner(a, s.findFolder(sec.GetFolderId())) {
		return true
	}
	return s.canManage(a, sec.GetFolderId()) && s.resolveSecret(a, sec).Author.Allowed
}

// requirePersonRetype refuses anything but a signed-in person: a token of the
// secret's owner would pass the gate, and dropping checkout is a person's call.
func (s *Server) requirePersonRetype(ctx context.Context, actor *vaultv1.ActorContext, id, newTypeID string) error {
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || actor.GetUserId() == "" {
		l := s.lg(ctx)
		l.Warn("type change refused: not a signed-in person", log.F("secret_id", id), log.F("principal_kind", actor.GetPrincipalKind().String()))
		return status.Error(codes.PermissionDenied, "this type change is for a signed-in person")
	}
	if id == "" || newTypeID == "" {
		return status.Error(codes.InvalidArgument, "id and new_type_id are required")
	}
	return nil
}

// personRetypeSecret resolves the secret for a person's type change and applies
// the gates: exists, may change it, not retired. Caller holds s.mu.
func (s *Server) personRetypeSecret(actor *vaultv1.ActorContext, id string) (*vaultv1.Secret, error) {
	sec := s.findSecret(id)
	if sec == nil {
		return nil, errNotFound("secret")
	}
	if !s.canChangeTypeAsPerson(actor, sec) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to change the type of this secret")
	}
	if sec.GetRetired() {
		return nil, refuseCode(codes.FailedPrecondition, ReasonRetired, "secret is retired")
	}
	return sec, nil
}

// ChangeSecretType changes a secret's type for a signed-in person with Author
// on it, on the same rules as ChangeSecretTypeForPrincipal, except that a person
// may drop checkout from a plain checkout type. Audited as secret.type_change.
func (s *Server) ChangeSecretType(ctx context.Context, req *vaultv1.ChangeSecretTypeRequest) (*vaultv1.ChangeSecretTypeResponse, error) {
	actor := req.GetActor()
	if err := s.requirePersonRetype(ctx, actor, req.GetId(), req.GetNewTypeId()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lg(ctx).With(log.F("secret_id", req.GetId()), log.F("to_type_id", req.GetNewTypeId()), log.F("user_id", actor.GetUserId()))
	l.Debug("type change requested by a person")
	sec, err := s.personRetypeSecret(actor, req.GetId())
	if err != nil {
		l.Info("type change refused", log.F("error", err.Error()))
		return nil, err
	}
	st, nt, err := s.retypeTypes(sec, req.GetNewTypeId())
	if err != nil {
		return nil, err
	}
	ev, err := s.evaluateRetype(ctx, sec, st, nt, retypeInput{
		mapping: req.GetFieldMapping(), extra: req.GetFields(), policy: req.GetUnmappedFields(), human: true,
	})
	if err != nil {
		l.Info("type change refused", log.F("error", err.Error()))
		return nil, err
	}
	done, err := s.commitRetype(ctx, sec, ev, req.GetFieldMapping(), actor.GetUserId(), "secret.type_change", func(attrs map[string]string) map[string]string { return attrs })
	if err != nil {
		return nil, err
	}
	l.Info("secret type changed by a person", log.F("from_type_id", st.GetId()))
	return &vaultv1.ChangeSecretTypeResponse{
		Secret: sec, FieldKeys: done.keys, MovedToNotesKeys: ev.result.moved, NotesFieldKey: ev.result.notesKey, ChangeLabel: done.label,
	}, nil
}

// PreviewSecretTypeChange runs a person's type change through evaluateRetype
// without writing, and says what it would do, in keys only. A change the rules
// refuse is an answer here, not an error, so the web can show it. Not audited:
// nothing is revealed or changed.
func (s *Server) PreviewSecretTypeChange(ctx context.Context, req *vaultv1.PreviewSecretTypeChangeRequest) (*vaultv1.PreviewSecretTypeChangeResponse, error) {
	actor := req.GetActor()
	if err := s.requirePersonRetype(ctx, actor, req.GetId(), req.GetNewTypeId()); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, err := s.personRetypeSecret(actor, req.GetId())
	if err != nil {
		return nil, err
	}
	st, nt, err := s.retypeTypes(sec, req.GetNewTypeId())
	if err != nil {
		return nil, err
	}
	ev, err := s.evaluateRetype(ctx, sec, st, nt, retypeInput{
		mapping: req.GetFieldMapping(), extra: req.GetFields(), policy: req.GetUnmappedFields(), human: true,
	})
	resp := &vaultv1.PreviewSecretTypeChangeResponse{Allowed: err == nil}
	switch status.Code(err) {
	case codes.OK:
		resp.FieldKeys = sortedKeys(ev.result.fields)
		resp.ChangeLabel = typeChangeLabel(st, nt, req.GetFieldMapping(), ev.result.fields, ev.result.moved)
	case codes.InvalidArgument, codes.FailedPrecondition:
		resp.RefusalReason, resp.RefusalMessage = retypeRefusalReason(err), status.Convert(err).Message()
	default:
		return nil, err
	}
	resp.FieldChanges, resp.NotesFieldKey = previewFieldChanges(st, nt, ev.cur, req.GetFieldMapping(), req.GetUnmappedFields(), resp.GetRefusalReason())
	resp.MissingRequiredKeys = missingRequiredKeys(nt, resp.GetFieldChanges(), req.GetFields())

	after, _ := proto.Clone(sec).(*vaultv1.Secret)
	after.TypeId = nt.GetId()
	auto := s.planRetypeAutomation(after, nt)
	resp.Rotation, resp.Heartbeat, resp.Target = auto.rotation, auto.heartbeat, auto.target
	resp.FromTargetId, resp.TargetId = auto.fromTargetID, after.GetTargetId()

	l := s.lg(ctx)
	l.Debug("type change previewed", log.F("secret_id", sec.GetId()), log.F("to_type_id", nt.GetId()), log.F("allowed", resp.GetAllowed()), log.F("reason", resp.GetRefusalReason()))
	return resp, nil
}

// previewFieldChanges reports where each stored value would go, from the same
// classification retypeFields uses. notesRefusal is the change's refusal
// reason: a notes overflow can only be told once the notes are built, so it
// arrives from there. Returns the notes field, when anything would move into it.
func previewFieldChanges(st, nt *vaultv1.SecretType, cur, mapping map[string]string, policy vaultv1.UnmappedFieldPolicy, notesRefusal string) ([]*vaultv1.SecretTypeChangeField, string) {
	nk := notesFieldKey(nt)
	moved := ""
	items := classifyRetype(st, nt, cur, mapping)
	out := make([]*vaultv1.SecretTypeChangeField, 0, len(items))
	blocked := func(it retypeItem, to, reason string) *vaultv1.SecretTypeChangeField {
		return &vaultv1.SecretTypeChangeField{
			FromKey: it.from, ToKey: to, Reason: reason,
			Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_BLOCKED,
		}
	}
	for _, it := range items {
		var c *vaultv1.SecretTypeChangeField
		switch it.kind {
		case retypeCarried:
			c = &vaultv1.SecretTypeChangeField{FromKey: it.from, ToKey: it.to, Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_CARRIED}
		case retypeRenamed:
			c = &vaultv1.SecretTypeChangeField{FromKey: it.from, ToKey: it.to, Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_RENAMED}
		case retypeLowered:
			c = blocked(it, it.to, ReasonTypeChangeLowersProtection)
		case retypeDuplicate:
			c = blocked(it, it.to, ReasonTypeChangeInvalidField)
		case retypeUnmapped:
			switch {
			case policy == vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE || nk == "":
				c = blocked(it, "", ReasonTypeChangeUnmappedFields)
			case notesTooOpenFor(st, fieldDef(nt, nk), it.from):
				c = blocked(it, "", ReasonTypeChangeLowersProtection)
			case notesRefusal == ReasonTypeChangeNotesTooLong:
				c = blocked(it, "", ReasonTypeChangeNotesTooLong)
			default:
				moved = nk
				c = &vaultv1.SecretTypeChangeField{FromKey: it.from, ToKey: nk, Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_MOVED_TO_NOTES}
			}
		}
		out = append(out, c)
	}
	return out, moved
}

// missingRequiredKeys lists the new type's required fields that neither a
// stored value nor extra fills.
func missingRequiredKeys(nt *vaultv1.SecretType, changes []*vaultv1.SecretTypeChangeField, extra map[string]string) []string {
	filled := map[string]bool{}
	for _, c := range changes {
		filled[c.GetToKey()] = true
	}
	for k, v := range extra {
		if v != "" {
			filled[k] = true
		}
	}
	var out []string
	for _, f := range nt.GetFields() {
		if f.GetRequired() && !filled[f.GetKey()] {
			out = append(out, f.GetKey())
		}
	}
	return out
}
