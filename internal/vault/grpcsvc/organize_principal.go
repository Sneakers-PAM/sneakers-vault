// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Non-human principal "organize" verbs: rename a secret,
// partially update its fields, and list/create/rename/move folders. Every verb
// is non-human only, evaluates RACI for the principal id (evalOf: never an
// admin flag, never folder ownership), treats a personal subtree as reachable
// only through an explicit user/group grant, and audits as the principal. There
// is deliberately no machine delete.
package grpcsvc

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxOrganizeNameRunes caps a machine-supplied secret/folder name.
const maxOrganizeNameRunes = 256

func requireNonHuman(a *vaultv1.ActorContext, verb string) error {
	if a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return status.Errorf(codes.PermissionDenied, "principal %s is for non-human principals", verb)
	}
	return nil
}

// organizeName trims and validates a machine-supplied name.
func organizeName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", status.Error(codes.InvalidArgument, "name is required")
	}
	if utf8.RuneCountInString(n) > maxOrganizeNameRunes {
		return "", status.Errorf(codes.InvalidArgument, "name exceeds %d characters", maxOrganizeNameRunes)
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return "", status.Error(codes.InvalidArgument, "name contains control characters")
		}
	}
	// Agents and clients read a name with a separator as a folder path.
	if strings.ContainsAny(n, `/\`) {
		return "", status.Error(codes.InvalidArgument, "name must not contain / or \\")
	}
	return n, nil
}

// principalChainFor is chainFor for a machine. In a personal subtree the
// master personal root contributes no rules at all: a grant there would reach
// every user's personal folder at once, which is not a grant by the owner.
// Caller holds s.mu.
func (s *Server) principalChainFor(folderID string) []authz.CategoryRuleset {
	var chain []authz.CategoryRuleset
	for _, f := range s.ancestorsInclusive(folderID) {
		rs := s.rulesetOf(f)
		if f.GetIsMasterPersonal() {
			rs.Rules = nil
		}
		chain = append(chain, rs)
	}
	return chain
}

// principalResolveChain evaluates chain for a machine. resolveChain already
// drops the allow cells of everyone rules for every non-human actor (denies
// still apply), so a personal subtree is reached only through an explicit
// user or group grant. A personal token reaches only its own user's personal
// subtree: another user's is closed to it whatever the rules say, so no grant
// or admin standing can open it through a token.
func (s *Server) principalResolveChain(a *vaultv1.ActorContext, chain []authz.CategoryRuleset, folderID string) authz.ActionResult {
	if s.closedToToken(a, folderID) {
		return authz.ActionResult{}
	}
	return resolveChain(a, chain)
}

// principalFolderAccess is a machine's effective RACI on a folder. Caller holds s.mu.
func (s *Server) principalFolderAccess(a *vaultv1.ActorContext, folderID string) authz.ActionResult {
	return s.principalResolveChain(a, s.principalChainFor(folderID), folderID)
}

// principalSecretAccess is a machine's effective RACI on a secret (its own
// ruleset first, then its folder chain). Caller holds s.mu.
func (s *Server) principalSecretAccess(a *vaultv1.ActorContext, sec *vaultv1.Secret) authz.ActionResult {
	chain := append([]authz.CategoryRuleset{s.rulesetOfSecret(sec)}, s.principalChainFor(sec.GetFolderId())...)
	return s.principalResolveChain(a, chain, sec.GetFolderId())
}

// principalFolderView is the metadata-only folder a machine sees: no owners,
// owning user, group/role binding, or subtree count (which would count secrets
// the principal cannot read). can_manage = the principal holds Author there.
func principalFolderView(f *vaultv1.Folder, canAuthor bool) *vaultv1.Folder {
	return &vaultv1.Folder{
		Id: f.GetId(), Name: f.GetName(), ParentId: f.GetParentId(),
		Scope: f.GetScope(), Order: f.GetOrder(), CanManage: canAuthor,
	}
}

// siblingNameTaken reports whether another folder under parentID already uses
// name (case-insensitive). Caller holds s.mu.
func (s *Server) siblingNameTaken(parentID, name, exceptID string) bool {
	for _, f := range s.folders {
		if f.GetParentId() == parentID && f.GetId() != exceptID && strings.EqualFold(f.GetName(), name) {
			return true
		}
	}
	return false
}

// ---- secrets ----------------------------------------------------------------

// RenameSecretForPrincipal renames a secret as a non-human principal. Gate:
// principalMutableSecret (Author on the folder chain AND the secret's own
// ruleset, not retired).
func (s *Server) RenameSecretForPrincipal(ctx context.Context, req *vaultv1.RenameSecretForPrincipalRequest) (*vaultv1.RenameSecretForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "rename"); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	name, err := organizeName(req.GetName())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetId(), "rename")
	if err != nil {
		return nil, err
	}
	if sec.GetName() == name {
		return nil, status.Error(codes.InvalidArgument, "secret already has that name")
	}
	from := sec.GetName()
	sec.Name = name
	s.emitAttrs(ctx, principalActorID(actor), "secret.rename.principal", sec.GetId(), false, principalAttrs(actor, map[string]string{
		"from_name": from,
		"to_name":   name,
	}))
	s.notifyInformed(ctx, principalActorID(actor), "secret.rename.principal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.RenameSecretForPrincipalResponse{Secret: sec}, nil
}

// descriptiveFieldKeys are the only fields a machine may change on a managed
// type (see machineFieldUpdateBlocked).
var descriptiveFieldKeys = map[string]bool{"notes": true, "description": true}

// machineFieldUpdateBlocked reports why a machine may not change field key on
// a secret of type st, or "" if it may. On a type the vault manages (rotation,
// heartbeat, checkout, certificate) only the descriptive notes/description
// fields are open: the credential would desync from the real system, the
// account identity would point the connector at a different account, the
// certificate fields are derived from the imported material, and checkout
// gates human access to the value. Messages name keys, never values.
func machineFieldUpdateBlocked(st *vaultv1.SecretType, key string) string {
	if descriptiveFieldKeys[key] {
		return ""
	}
	switch {
	case st.GetRotation():
		return "field " + strconv.Quote(key) + " of a rotation-managed type can only be changed by a human (a machine change would desync it from the target); a machine may only change notes/description"
	case st.GetHeartbeat():
		return "field " + strconv.Quote(key) + " of a heartbeat-validated type can only be changed by a human; a machine may only change notes/description"
	case st.GetId() == certSecretTypeID:
		return "certificate fields can only be changed by a human (replace the certificate); a machine may only change notes"
	case st.GetCheckout():
		return "field " + strconv.Quote(key) + " of a checkout-protected type can only be changed by a human; a machine may only change notes/description"
	}
	return ""
}

// validateFieldValue applies a field definition's max_length and pattern to a
// non-empty value. Errors name the key, never the value.
func validateFieldValue(f *vaultv1.SecretFieldDef, v string) error {
	if v == "" {
		return nil
	}
	if ml := f.GetMaxLength(); ml > 0 && utf8.RuneCountInString(v) > int(ml) {
		return status.Errorf(codes.InvalidArgument, "value for field %q exceeds the type's max length", f.GetKey())
	}
	if p := f.GetPattern(); p != "" {
		if re, err := regexp.Compile(p); err == nil && !re.MatchString(v) {
			return status.Errorf(codes.InvalidArgument, "value for field %q does not match the type's pattern", f.GetKey())
		}
	}
	return nil
}

// UpdateSecretFieldsForPrincipal partially updates a secret's field values as
// a non-human principal: same gate as rename, every key declared by the type,
// required fields cannot be cleared, max_length/pattern honoured, managed
// types restricted to descriptive fields. The merge is re-sealed as a new
// active version (history kept); a no-op mints nothing. Audited with keys only.
//
//nolint:gocognit,gocyclo // a flat sequence of independent validation rules
func (s *Server) UpdateSecretFieldsForPrincipal(ctx context.Context, req *vaultv1.UpdateSecretFieldsForPrincipalRequest) (*vaultv1.UpdateSecretFieldsForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "update"); err != nil {
		return nil, err
	}
	if req.GetId() == "" || len(req.GetFields()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "id and at least one field are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, err := s.principalMutableSecret(actor, req.GetId(), "update")
	if err != nil {
		return nil, err
	}
	st := s.findType(sec.GetTypeId())
	if st == nil {
		return nil, status.Error(codes.FailedPrecondition, "secret's type is unknown; a human must repair it")
	}
	patch := req.GetFields()
	for _, k := range sortedKeys(patch) {
		fd := fieldDef(st, k)
		if fd == nil {
			return nil, status.Errorf(codes.InvalidArgument, "field %q is not a field of this secret's type", k)
		}
		if why := machineFieldUpdateBlocked(st, k); why != "" {
			return nil, status.Error(codes.FailedPrecondition, why)
		}
		if patch[k] == "" && fd.GetRequired() {
			return nil, status.Errorf(codes.InvalidArgument, "field %q is required and cannot be cleared", k)
		}
		if err := validateFieldValue(fd, patch[k]); err != nil {
			return nil, err
		}
	}
	cur := map[string]string{}
	if rec, ok := s.records[sec.GetId()]; ok {
		opened, err := s.crypt.OpenAll(rec)
		if err != nil {
			return nil, status.Error(codes.Internal, "open existing record")
		}
		cur = opened
	}
	merged := make(map[string]string, len(cur)+len(patch))
	for k, v := range cur {
		merged[k] = v
	}
	var changed []string
	for _, k := range sortedKeys(patch) {
		old, had := cur[k]
		if v := patch[k]; v == "" {
			delete(merged, k)
			if had && old != "" {
				changed = append(changed, k)
			}
		} else {
			merged[k] = v
			if v != old {
				changed = append(changed, k)
			}
		}
	}
	if len(changed) == 0 {
		return &vaultv1.UpdateSecretFieldsForPrincipalResponse{Secret: sec, ChangedFieldKeys: []string{}}, nil
	}
	// The same authoritative key-pair check every save runs.
	if err := verifyKeyPairFields(merged); err != nil {
		return nil, err
	}
	rec, err := s.crypt.Seal(merged)
	if err != nil {
		return nil, status.Error(codes.Internal, "seal fields")
	}
	s.records[sec.GetId()] = rec
	if s.vers != nil {
		_, _ = s.vers.AppendActive(ctx, sec.GetId(), rec, principalActorID(actor))
	}
	s.emitAttrs(ctx, principalActorID(actor), "secret.update.principal", sec.GetId(), true, principalAttrs(actor, map[string]string{
		"changed_field_keys": strings.Join(changed, ","),
	}))
	s.notifyInformed(ctx, principalActorID(actor), "secret.update.principal", "secret", sec.GetId(), sec.GetName(), s.secretChain(sec))
	return &vaultv1.UpdateSecretFieldsForPrincipalResponse{Secret: sec, ChangedFieldKeys: changed}, nil
}

// ---- folders ----------------------------------------------------------------

// ListFoldersForPrincipal lists the folders the principal may read, metadata
// only. The master personal root is never listed; a personal folder only with
// an explicit grant (principalFolderAccess ignores everyone rules there).
func (s *Server) ListFoldersForPrincipal(ctx context.Context, req *vaultv1.ListFoldersForPrincipalRequest) (*vaultv1.ListFoldersForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "folder list"); err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(req.GetQuery()))
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*vaultv1.Folder, 0)
	for _, f := range s.folders {
		if f.GetIsMasterPersonal() {
			continue
		}
		if pid := req.GetParentId(); pid != "" && f.GetParentId() != pid {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(f.GetName()), q) {
			continue
		}
		res := s.principalFolderAccess(actor, f.GetId())
		if !res.Read.Allowed {
			continue
		}
		out = append(out, principalFolderView(f, res.Author.Allowed))
	}
	s.emitAttrs(ctx, principalActorID(actor), "folder.list.principal", req.GetParentId(), false, principalAttrs(actor, map[string]string{
		"count": strconv.Itoa(len(out)),
	}))
	return &vaultv1.ListFoldersForPrincipalResponse{Folders: out}, nil
}

// CreateFolderForPrincipal creates a subfolder as a non-human principal:
// Author on the parent chain, never top level, no duplicate sibling name.
// Inherits the parent's scope and owning user; no owners. Inside a personal
// subtree only a personal token of that tree's owner may create (the token
// acts for the user in their own folder); a service account or workload never
// may, and nobody may under the master personal root.
func (s *Server) CreateFolderForPrincipal(ctx context.Context, req *vaultv1.CreateFolderForPrincipalRequest) (*vaultv1.CreateFolderForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "folder create"); err != nil {
		return nil, err
	}
	if req.GetParentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "parent_id is required: a machine cannot create a top-level folder")
	}
	name, err := organizeName(req.GetName())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := s.findFolder(req.GetParentId())
	if parent == nil {
		return nil, errNotFound("parent folder")
	}
	if !s.principalFolderAccess(actor, parent.GetId()).Author.Allowed {
		return nil, status.Error(codes.PermissionDenied, "not permitted to create a folder here")
	}
	if why := s.personalCreateBlocked(actor, parent); why != "" {
		l := s.lg(ctx)
		l.Info("principal folder create refused", log.F("parent_id", parent.GetId()), log.F("principal_kind", actor.GetPrincipalKind().String()), log.F("reason", why))
		return nil, status.Error(codes.PermissionDenied, why)
	}
	if s.siblingNameTaken(parent.GetId(), name, "") {
		return nil, status.Error(codes.AlreadyExists, "a folder with that name already exists here")
	}
	f := &vaultv1.Folder{
		Id: s.nextID("folder"), Name: name, ParentId: parent.GetId(),
		Scope: parent.GetScope(), OwnerUserId: parent.GetOwnerUserId(), GroupId: parent.GetGroupId(), Role: parent.GetRole(),
		Order: safeconv.Int32(s.childCount(parent.GetId())),
	}
	s.folders = append(s.folders, f)
	s.emitAttrs(ctx, principalActorID(actor), "folder.create.principal", f.GetId(), false, principalAttrs(actor, map[string]string{
		"parent_id": parent.GetId(),
		"name":      name,
	}))
	s.notifyInformed(ctx, principalActorID(actor), "folder.create.principal", "folder", f.GetId(), f.GetName(), s.chainFor(f.GetId()))
	return &vaultv1.CreateFolderForPrincipalResponse{Folder: principalFolderView(f, true)}, nil
}

// personalCreateBlocked reports why actor may not create a folder under
// parent because of the personal-folder rules, or "" if it may. Caller holds s.mu.
func (s *Server) personalCreateBlocked(actor *vaultv1.ActorContext, parent *vaultv1.Folder) string {
	if parent.GetIsMasterPersonal() {
		return "creating a folder under the personal folders root is not permitted"
	}
	personal, owner := s.destPersonal(parent)
	if !personal {
		return ""
	}
	if isUserToken(actor) && owner != "" && owner == actor.GetUserId() {
		return ""
	}
	return "creating a folder inside a personal folder requires a human or that user's own token"
}

// RenameFolderForPrincipal renames a folder as a non-human principal: Author
// on the folder chain; the master personal root is refused.
func (s *Server) RenameFolderForPrincipal(ctx context.Context, req *vaultv1.RenameFolderForPrincipalRequest) (*vaultv1.RenameFolderForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "folder rename"); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	name, err := organizeName(req.GetName())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.findFolder(req.GetId())
	if f == nil {
		return nil, errNotFound("folder")
	}
	if f.GetIsMasterPersonal() || !s.principalFolderAccess(actor, f.GetId()).Author.Allowed {
		return nil, status.Error(codes.PermissionDenied, "not permitted to rename this folder")
	}
	if f.GetName() == name {
		return nil, status.Error(codes.InvalidArgument, "folder already has that name")
	}
	if s.siblingNameTaken(f.GetParentId(), name, f.GetId()) {
		return nil, status.Error(codes.AlreadyExists, "a folder with that name already exists here")
	}
	from := f.GetName()
	f.Name = name
	s.emitAttrs(ctx, principalActorID(actor), "folder.rename.principal", f.GetId(), false, principalAttrs(actor, map[string]string{
		"from_name": from,
		"to_name":   name,
	}))
	s.notifyInformed(ctx, principalActorID(actor), "folder.rename.principal", "folder", f.GetId(), f.GetName(), s.chainFor(f.GetId()))
	return &vaultv1.RenameFolderForPrincipalResponse{Folder: principalFolderView(f, true)}, nil
}

// subtreeAuthorable reports whether the principal holds Author on every folder
// below root and on every secret in root's subtree (retired included): a
// machine may not re-parent content it could not manage itself. Caller holds s.mu.
func (s *Server) subtreeAuthorable(a *vaultv1.ActorContext, root string) bool {
	ids := s.descendantIDs(root)
	for id := range ids {
		if !s.principalFolderAccess(a, id).Author.Allowed {
			return false
		}
	}
	for _, sec := range s.secrets {
		if ids[sec.GetFolderId()] && !s.principalSecretAccess(a, sec).Author.Allowed {
			return false
		}
	}
	return true
}

// principalFolderMoveTargets resolves and checks a machine folder move: the
// folder and its current parent must be authorable, the destination must exist,
// be authorable and not be the folder, a descendant or its current parent, and
// the whole subtree must be authorable. Caller holds s.mu.
func (s *Server) principalFolderMoveTargets(actor *vaultv1.ActorContext, id, destID string) (f, dest *vaultv1.Folder, err error) {
	f = s.findFolder(id)
	if f == nil {
		return nil, nil, errNotFound("folder")
	}
	if f.GetIsMasterPersonal() || !s.principalFolderAccess(actor, f.GetId()).Author.Allowed {
		return nil, nil, status.Error(codes.PermissionDenied, "not permitted to move this folder")
	}
	if pid := f.GetParentId(); pid != "" && !s.principalFolderAccess(actor, pid).Author.Allowed {
		return nil, nil, status.Error(codes.PermissionDenied, "not permitted to move this folder out of its current parent")
	}
	if s.descendantIDs(f.GetId())[destID] {
		return nil, nil, status.Error(codes.InvalidArgument, "cannot move a folder into itself or one of its descendants")
	}
	if destID == f.GetParentId() {
		return nil, nil, status.Error(codes.InvalidArgument, "folder is already under that parent")
	}
	dest = s.findFolder(destID)
	if dest == nil {
		return nil, nil, errNotFound("destination folder")
	}
	if !s.principalFolderAccess(actor, destID).Author.Allowed {
		return nil, nil, status.Error(codes.PermissionDenied, "not permitted to move the folder there")
	}
	if !s.subtreeAuthorable(actor, f.GetId()) {
		return nil, nil, status.Error(codes.PermissionDenied, "the folder contains content the principal is not permitted to manage")
	}
	return f, dest, nil
}

// MoveFolderForPrincipal moves a folder (and its subtree) under another parent
// as a non-human principal, mirroring the human MoveFolder for a caller
// that can never be a site-admin. See the contract for the full rule list.
func (s *Server) MoveFolderForPrincipal(ctx context.Context, req *vaultv1.MoveFolderForPrincipalRequest) (*vaultv1.MoveFolderForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "folder move"); err != nil {
		return nil, err
	}
	if req.GetId() == "" || req.GetNewParentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id and new_parent_id are required: a machine cannot move a folder to the top level")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, dest, err := s.principalFolderMoveTargets(actor, req.GetId(), req.GetNewParentId())
	if err != nil {
		return nil, err
	}
	destID := dest.GetId()
	destView := principalFolderView(dest, true)
	moveAttrs := principalAttrs(actor, map[string]string{
		"from_parent_id": f.GetParentId(),
		"to_parent_id":   destID,
	})
	destPersonal, destOwner := s.destPersonal(dest)
	if destPersonal {
		alreadyOwned := f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && f.GetOwnerUserId() == destOwner
		if !alreadyOwned {
			// A site-admin approval, as for a human (folders.go MoveFolder).
			// Every RACI check has passed; move nothing, let the gateway file it.
			s.emitAttrs(ctx, principalActorID(actor), "folder.move.approval_required.principal", f.GetId(), false, moveAttrs)
			return &vaultv1.MoveFolderForPrincipalResponse{Folder: principalFolderView(f, true), ApprovalRequired: true, Destination: destView}, nil
		}
	}
	f.ParentId = destID
	s.rescopeSubtree(f, dest, destPersonal, destOwner)
	s.emitAttrs(ctx, principalActorID(actor), "folder.move.principal", f.GetId(), false, moveAttrs)
	s.notifyInformed(ctx, principalActorID(actor), "folder.move.principal", "folder", f.GetId(), f.GetName(), s.chainFor(f.GetId()))
	return &vaultv1.MoveFolderForPrincipalResponse{Folder: principalFolderView(f, true), Destination: destView}, nil
}
