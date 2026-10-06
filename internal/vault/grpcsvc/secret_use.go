// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	secretUseTTL        = 10 * time.Minute
	redeemAfterApproval = time.Minute
	useGrantMaxSpan     = 24 * time.Hour
	maxUseArgv          = 64
	maxUsePurpose       = 200
)

var useRunID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// checkUseRunID accepts an empty run id (optional) or one matching useRunID.
func checkUseRunID(runID string) error {
	if runID != "" && !useRunID.MatchString(runID) {
		return status.Error(codes.InvalidArgument, "run_id must be 1 to 64 letters, digits, '_' or '-'")
	}
	return nil
}

// checkUsePurpose keeps purpose to one line of plain text: it is the agent's
// own words, shown to the owner and written to audit.
func checkUsePurpose(purpose string) error {
	if !utf8.ValidString(purpose) || utf8.RuneCountInString(purpose) > maxUsePurpose ||
		strings.ContainsFunc(purpose, unicode.IsControl) {
		return status.Errorf(codes.InvalidArgument, "purpose must be plain text of at most %d characters", maxUsePurpose)
	}
	return nil
}

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
		"argv": strings.Join(u.GetArgv(), " "), "client_label": u.GetClientLabel(), "run_id": u.GetRunId(),
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

// PrepareSecretUse records a request to use one field of one secret: by a
// personal token for one exact command or a reveal to the token, or by a
// signed-in person for a reveal in the web. It is approved at once unless the
// secret's approval level says the requester needs a decision (see
// approval.go); then it waits for another owner or approver, or, when nobody
// else can decide, for the requester's one-time confirmation.
func (s *Server) PrepareSecretUse(ctx context.Context, req *vaultv1.PrepareSecretUseRequest) (*vaultv1.PrepareSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if err := checkPrepareCaller(actor, req.GetReveal()); err != nil {
		return nil, err
	}
	argv := req.GetArgv()
	if err := checkPrepareRequest(req); err != nil {
		return nil, err
	}
	sec, chk, apiErr := s.prepareChecks(ctx, actor, req)
	readable, hasField, needsApproval, confirm, decidable := chk.readable, chk.hasField, chk.needsApproval, chk.confirm, chk.decidable
	if apiErr != nil {
		return nil, apiErr
	}
	attempt := map[string]string{"field": req.GetFieldKey(), "argv": strings.Join(argv, " "), "client_label": req.GetClientLabel(), "run_id": req.GetRunId()}
	if !readable {
		s.useRefused(ctx, actor, "secret.use.prepare", req.GetSecretId(), "denied", "no read access", attempt)
		return nil, status.Error(codes.PermissionDenied, "not permitted to use this secret")
	}
	if !hasField {
		s.useRefused(ctx, actor, "secret.use.prepare", req.GetSecretId(), "failed", "no such field", attempt)
		return nil, status.Error(codes.NotFound, "secret field not found")
	}
	if needsApproval && !decidable {
		s.useRefused(ctx, actor, "secret.use.prepare", req.GetSecretId(), "failed", ReasonNoApprover, attempt)
		return nil, refuseCode(codes.FailedPrecondition, ReasonNoApprover, "nobody can approve this use: the secret has no active owner or approver")
	}
	now := s.clock()
	use := &vaultv1.SecretUse{
		Id: s.nextID("use"), SecretId: sec.GetId(), SecretName: sec.GetName(), FieldKey: req.GetFieldKey(),
		Argv: argv, UserId: actor.GetUserId(), TokenId: actor.GetTokenId(),
		State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: now.Add(secretUseTTL).Unix(), ClientLabel: req.GetClientLabel(), Reveal: req.GetReveal(),
		RunId: req.GetRunId(), Purpose: req.GetPurpose(), Confirm: confirm,
	}
	if err := s.approveAtPrepare(ctx, st, use, sec, needsApproval, now); err != nil {
		return nil, err
	}
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.lg(ctx).Debug("secret use prepared", log.F("use_id", use.GetId()), log.F("secret_id", sec.GetId()),
		log.F("state", use.GetState().String()), log.F("confirm", use.GetConfirm()), log.F("run_id", use.GetRunId()))
	s.emitAttrs(ctx, actor.GetUserId(), "secret.use.prepare", sec.GetId(), true, useAttrs(use, map[string]string{
		"grant_id": use.GetGrantId(), "approval_level": strconv.Itoa(approvalLevel(sec)), "confirm": strconv.FormatBool(use.GetConfirm()),
	}))
	return &vaultv1.PrepareSecretUseResponse{Use: use}, nil
}

// approveAtPrepare approves a use on the spot when that needs no person: the
// requester needs no approval, or nobody else can decide and the requester
// already confirmed this run (or holds a use grant, an MFA-backed
// pre-confirmation). A grant never stands in for another approver.
func (s *Server) approveAtPrepare(ctx context.Context, st useStore, use *vaultv1.SecretUse, sec *vaultv1.Secret, needsApproval bool, now time.Time) error {
	approve := func() {
		use.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
		use.ExpiresAtUnix = now.Add(redeemAfterApproval).Unix()
	}
	if !needsApproval {
		approve()
		return nil
	}
	if !use.GetConfirm() {
		return nil
	}
	if use.GetRunId() != "" {
		ok, err := st.RunConfirmedSince(ctx, use.GetUserId(), use.GetTokenId(), use.GetRunId(), now.Add(-runConfirmSpan).Unix())
		if err != nil {
			return status.Errorf(codes.Internal, "check run confirmation: %v", err)
		}
		if ok {
			approve()
			return nil
		}
	}
	if use.GetTokenId() == "" {
		return nil
	}
	g, err := s.coveringGrant(ctx, st, use, sec, now)
	if err != nil {
		return status.Errorf(codes.Internal, "check use grants: %v", err)
	}
	if g != nil {
		approve()
		use.GrantId = g.GetId()
	}
	return nil
}

// checkPrepareCaller allows a personal token, or a signed-in person for a
// reveal only.
func checkPrepareCaller(actor *vaultv1.ActorContext, reveal bool) error {
	person := isHumanUser(actor)
	if !isUserToken(actor) && !person {
		return status.Error(codes.PermissionDenied, "secret use is for personal tokens and signed-in people")
	}
	if person && !reveal {
		return status.Error(codes.InvalidArgument, "a person's secret use is a reveal")
	}
	return nil
}

type prepareCheck struct{ readable, hasField, needsApproval, confirm, decidable bool }

// prepareChecks reads, under the lock, what PrepareSecretUse decides on.
func (s *Server) prepareChecks(ctx context.Context, actor *vaultv1.ActorContext, req *vaultv1.PrepareSecretUseRequest) (*vaultv1.Secret, prepareCheck, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var c prepareCheck
	sec := s.findSecret(req.GetSecretId())
	c.readable = sec != nil && !sec.GetRetired() && s.canRead(actor, sec)
	if !c.readable {
		return sec, c, nil
	}
	if err := s.checkAPIForSensitive(ctx, actor, sec, req.GetFieldKey(), "use.prepare"); err != nil {
		return sec, c, err
	}
	_, c.hasField = s.records[sec.GetId()].Fields[req.GetFieldKey()]
	if req.GetReveal() {
		c.hasField = c.hasField && s.isSensitiveField(s.findType(sec.TypeId), req.GetFieldKey())
	}
	c.needsApproval = s.useNeedsApproval(actor.GetUserId(), sec)
	if c.needsApproval {
		c.confirm, c.decidable = s.confirmMode(actor, sec, req.GetActiveUsers())
	}
	return sec, c, nil
}

func checkPrepareRequest(req *vaultv1.PrepareSecretUseRequest) error {
	if err := checkUseArgv(req.GetReveal(), req.GetArgv()); err != nil {
		return err
	}
	if err := checkUseRunID(req.GetRunId()); err != nil {
		return err
	}
	return checkUsePurpose(req.GetPurpose())
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
	if owner && (!isUserToken(actor) || actor.GetTokenId() == use.GetTokenId()) {
		return &vaultv1.GetSecretUseResponse{Use: use}, nil
	}
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	decider := sec != nil && s.mayDecide(actor, sec, use.GetUserId())
	s.mu.RUnlock()
	if !decider {
		return nil, status.Error(codes.NotFound, "secret use not found")
	}
	return &vaultv1.GetSecretUseResponse{Use: use}, nil
}

// ListPendingSecretUses lists the signed-in owner's pending uses, optionally
// of one run. A personal token may list only its own pending uses of one run,
// so an agent can show what is still waiting in its run.
func (s *Server) ListPendingSecretUses(ctx context.Context, req *vaultv1.ListPendingSecretUsesRequest) (*vaultv1.ListPendingSecretUsesResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor, runID := req.GetActor(), req.GetRunId()
	if err := checkUseRunID(runID); err != nil {
		return nil, err
	}
	human := actor.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN
	token := isUserToken(actor) && actor.GetTokenId() != "" && runID != ""
	if actor.GetUserId() == "" || (!human && !token) {
		return nil, status.Error(codes.PermissionDenied, "only the signed-in owner, or a personal token for one of its runs, can list secret uses")
	}
	uses, err := st.PendingUses(ctx, actor.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secret uses: %v", err)
	}
	now := s.clock().Unix()
	out := make([]*vaultv1.SecretUse, 0, len(uses))
	for _, u := range uses {
		switch {
		case now >= u.GetExpiresAtUnix(), runID != "" && u.GetRunId() != runID,
			token && u.GetTokenId() != actor.GetTokenId():
			continue
		}
		out = append(out, u)
	}
	return &vaultv1.ListPendingSecretUsesResponse{Uses: out}, nil
}

// DecideSecretUse lets an eligible person approve or deny someone else's
// pending use: an owner of the secret, or for an always-approve secret also a
// designated approver (RACI A). The requester may deny (withdraw) their own
// use but never approve it. The gateway requires a second factor within the
// step-up window first.
func (s *Server) DecideSecretUse(ctx context.Context, req *vaultv1.DecideSecretUseRequest) (*vaultv1.DecideSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if !isHumanUser(actor) {
		return nil, status.Error(codes.PermissionDenied, "only a signed-in person can decide a secret use")
	}
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	own := use.GetUserId() == actor.GetUserId()
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	allowed := sec != nil && s.mayDecide(actor, sec, use.GetUserId())
	s.mu.RUnlock()
	refused := func(reason, msg string) error {
		s.lg(ctx).Warn("secret use decision refused", log.F("use_id", use.GetId()), log.F("user_id", actor.GetUserId()), log.F("reason", reason))
		s.useRefused(ctx, actor, "secret.use.decide", use.GetSecretId(), "denied", reason, useAttrs(use, nil))
		return refuseCode(codes.PermissionDenied, reason, msg)
	}
	switch {
	case own && req.GetApprove():
		return nil, refused(ReasonSelfApproval, "you can't approve your own request")
	case !own && !allowed:
		return nil, refused(ReasonNotApprover, "only an owner or approver of this secret can decide this use")
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
	use.DecidedByUserId = actor.GetUserId()
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.lg(ctx).Info("secret use decided", log.F("use_id", use.GetId()), log.F("decided_by", actor.GetUserId()), log.F("state", use.GetState().String()))
	s.emitAttrs(ctx, actor.GetUserId(), action, use.GetSecretId(), true, useAttrs(use, map[string]string{"requested_by": use.GetUserId()}))
	return &vaultv1.DecideSecretUseResponse{Use: use}, nil
}

// ConfirmSecretUse is the requester's one-time confirmation of their own
// pending use when nobody else can decide it: a single-user install, or an
// always-approve secret whose only approver is the requester. It needs a
// second factor within MFA_MAX_AGE, and is refused while another owner or
// approver could decide instead.
func (s *Server) ConfirmSecretUse(ctx context.Context, req *vaultv1.ConfirmSecretUseRequest) (*vaultv1.ConfirmSecretUseResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if !isHumanUser(actor) {
		return nil, status.Error(codes.PermissionDenied, "only a signed-in person can confirm a secret use")
	}
	use, err := s.liveUse(ctx, st, req.GetUseId())
	if err != nil {
		return nil, err
	}
	refused := func(code codes.Code, reason, msg string) error {
		s.lg(ctx).Warn("secret use confirmation refused", log.F("use_id", use.GetId()), log.F("user_id", actor.GetUserId()), log.F("reason", reason))
		s.useRefused(ctx, actor, "secret.use.confirm", use.GetSecretId(), "denied", reason, useAttrs(use, nil))
		return refuseCode(code, reason, msg)
	}
	if use.GetUserId() != actor.GetUserId() {
		return nil, refused(codes.PermissionDenied, ReasonNotRequester, "only the person who asked can confirm this use")
	}
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		return nil, status.Errorf(codes.FailedPrecondition, "secret use is %s", use.GetState())
	}
	if !s.mfaFresh(actor) {
		return nil, refused(codes.PermissionDenied, ReasonStepUpRequired, "confirm your MFA again to continue")
	}
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	readable := sec != nil && !sec.GetRetired() && s.canRead(actor, sec)
	var confirm, decidable bool
	if readable {
		confirm, decidable = s.confirmMode(actor, sec, req.GetActiveUsers())
	}
	s.mu.RUnlock()
	switch {
	case !readable:
		return nil, refused(codes.PermissionDenied, ReasonNoAccess, "not permitted to use this secret any more")
	case !decidable:
		return nil, refused(codes.FailedPrecondition, ReasonNoApprover, "nobody can approve this use")
	case !confirm:
		return nil, refused(codes.FailedPrecondition, ReasonOtherApprover, "an owner or approver of this secret decides this use")
	}
	now := s.clock()
	use.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
	use.ExpiresAtUnix = now.Add(redeemAfterApproval).Unix()
	use.ConfirmedAtUnix = now.Unix()
	if err := st.PutUse(ctx, use); err != nil {
		return nil, status.Errorf(codes.Internal, "store secret use: %v", err)
	}
	s.lg(ctx).Info("secret use confirmed by the requester", log.F("use_id", use.GetId()), log.F("run_id", use.GetRunId()))
	s.emitAttrs(ctx, actor.GetUserId(), "secret.use.confirm", use.GetSecretId(), true, useAttrs(use, nil))
	return &vaultv1.ConfirmSecretUseResponse{Use: use}, nil
}

// ListSecretUsesToDecide lists other people's pending uses the signed-in
// person may decide. A use only its requester can confirm still shows when
// the caller may decide it now.
func (s *Server) ListSecretUsesToDecide(ctx context.Context, req *vaultv1.ListSecretUsesToDecideRequest) (*vaultv1.ListSecretUsesToDecideResponse, error) {
	st, err := s.useStoreOrUnavailable()
	if err != nil {
		return nil, err
	}
	actor := req.GetActor()
	if !isHumanUser(actor) {
		return nil, status.Error(codes.PermissionDenied, "only a signed-in person can list uses to decide")
	}
	uses, err := st.AllPendingUses(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secret uses: %v", err)
	}
	now := s.clock().Unix()
	out := make([]*vaultv1.SecretUse, 0, len(uses))
	s.mu.RLock()
	for _, u := range uses {
		if now >= u.GetExpiresAtUnix() {
			continue
		}
		if sec := s.findSecret(u.GetSecretId()); sec != nil && s.mayDecide(actor, sec, u.GetUserId()) {
			out = append(out, u)
		}
	}
	s.mu.RUnlock()
	s.lg(ctx).Debug("secret uses to decide listed", log.F("user_id", actor.GetUserId()), log.F("count", len(out)))
	return &vaultv1.ListSecretUsesToDecideResponse{Uses: out}, nil
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
	webUse := use.GetTokenId() == ""
	if !sameRequester(actor, use) {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "denied", "not the preparing requester", map[string]string{"use_id": use.GetId(), "run_id": use.GetRunId()})
		return nil, status.Error(codes.PermissionDenied, "only the token or person that prepared this use can redeem it")
	}
	if use.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED {
		s.useRefused(ctx, actor, "secret.use.redeem", use.GetSecretId(), "failed", "use is "+use.GetState().String(), useAttrs(use, nil))
		return nil, status.Errorf(codes.FailedPrecondition, "secret use is %s", use.GetState())
	}
	s.mu.RLock()
	sec := s.findSecret(use.GetSecretId())
	readable := sec != nil && !sec.GetRetired() && s.canRead(actor, sec)
	rec := s.records[use.GetSecretId()]
	var apiErr error
	if readable {
		apiErr = s.checkAPIForSensitive(ctx, actor, sec, use.GetFieldKey(), "use.redeem")
		if apiErr == nil {
			apiErr = s.checkRevealStepUp(ctx, actor, sec, "reveal")
		}
	}
	s.mu.RUnlock()
	if apiErr != nil {
		return nil, apiErr
	}
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
		via := "mcp"
		if webUse {
			via = "web"
		}
		// Reads as the person revealing it, like a UI reveal.
		s.emitAttrs(ctx, actor.GetUserId(), "secret.reveal", use.GetSecretId()+"#"+use.GetFieldKey(), true, map[string]string{
			"principal_kind": actor.GetPrincipalKind().String(), "token_id": actor.GetTokenId(), "via": via,
			"use_id": use.GetId(), "grant_id": use.GetGrantId(), "client_label": use.GetClientLabel(),
		})
	} else {
		s.emitAttrs(ctx, actor.GetUserId(), "secret.use.redeem", use.GetSecretId(), true, useAttrs(use, map[string]string{"grant_id": use.GetGrantId()}))
	}
	return &vaultv1.RedeemSecretUseResponse{Use: use, Value: value}, nil
}

// sameRequester reports whether actor is the token, or for a web use the
// person, that prepared use.
func sameRequester(actor *vaultv1.ActorContext, use *vaultv1.SecretUse) bool {
	if actor.GetUserId() != use.GetUserId() || actor.GetTokenId() != use.GetTokenId() {
		return false
	}
	if use.GetTokenId() == "" {
		return isHumanUser(actor)
	}
	return isUserToken(actor)
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

// isHumanUser reports a signed-in person with a real user id.
func isHumanUser(a *vaultv1.ActorContext) bool {
	uid := a.GetUserId()
	return a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN && uid != "" && uid != "system"
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
