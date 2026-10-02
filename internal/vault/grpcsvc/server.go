// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcsvc implements the sneakers.vault.v1.VaultService over an
// in-memory store. The store stands in for the Postgres-backed repository
// (envelope-encrypted at rest); the gRPC surface and domain logic are the same
// either way, so swapping the store for a pg implementation later is localised.
package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/Bugs5382/go-log"
	bredis "github.com/Bugs5382/go-redis"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/authz"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/safeconv"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Auditor records audit events. audit.Emitter satisfies it; a nil
// Auditor (e.g. before RabbitMQ is wired) is tolerated and skips emission.
type Auditor interface {
	Emit(ctx context.Context, ev audit.Event) error
}

// Notifier receives best-effort Informed-notification events. A nil Notifier is
// tolerated (skips notification), mirroring Auditor. Implementations must not
// block the caller — the concrete adapter fires asynchronously.
type Notifier interface {
	Notify(ctx context.Context, ev NotifyEvent)
}

// NotifyEvent is one material mutation plus the Informed subjects to fan out to.
type NotifyEvent struct {
	Action        string
	ResourceKind  string // "secret" | "folder"
	ResourceID    string
	ResourceLabel string
	ActorUserID   string
	Subjects      []authz.RuleSubject
}

// Server is the in-memory VaultService implementation.
type Server struct {
	vaultv1.UnimplementedVaultServiceServer

	mu          sync.RWMutex
	types       []*vaultv1.SecretType
	folders     []*vaultv1.Folder
	rules       []*vaultv1.FolderAccessRule
	raciRules   []*vaultv1.RaciRule
	secrets     []*vaultv1.Secret
	connections []*vaultv1.Connection
	targets     []*vaultv1.Target
	// targetRulesets holds each target's own ordered RACI ruleset, keyed
	// by target id — see state.targetRulesets (store.go) for why this is a map
	// rather than a flat slice like raciRules.
	targetRulesets map[string][]*vaultv1.RaciRule
	policies       []*vaultv1.PasswordPolicy
	settings       *vaultv1.SecuritySettings
	extCatalog     []*vaultv1.SecretType    // installable extension packs (not yet installed)
	records        map[string]crypto.Record // secretID -> encrypted field set

	crypt    *crypto.Envelope
	audit    Auditor
	notifier Notifier
	store    Store
	hb       *heartbeatStore
	vers     *versionStore
	rot      *rotationStore
	// uses holds secret use handles and use grants, shared by every replica.
	uses useStore
	// now is the clock for use-handle and grant expiry; nil means time.Now.
	now func() time.Time
	bg  *breakGlassStore
	wid workloadid.WorkloadIdentityVerifier

	// KEK keyring: the working-KEK ring backing s.crypt's KEKProvider,
	// its durable store, and the root KEK (+ its ref) that wraps every working
	// generation. Set by SetKeyring once the pool is open (nil in the
	// no-Postgres/demo path — RotateKek is unavailable there). rotating guards
	// rotateOnce/sweepRewrap so a second rotation never starts while one is in
	// flight (from a concurrent RPC call or the future scheduled sweep).
	keyring      *crypto.KeyringKEK
	keyringStore KeyringAdmin
	root         crypto.KEKProvider
	rootRef      string
	rotating     atomic.Bool
	// kekRotators is the SYSTEM-principal allowlist for RotateKek
	// (VAULT_KEK_ROTATION_PRINCIPALS, see kek_principals.go). Set once at boot
	// by SetKekRotationPrincipals and read-only after that. Empty = disabled.
	kekRotators map[string]struct{}

	// writeMu serializes state writes on this replica (see writeTx). It is
	// taken BEFORE the store's cross-replica lock, so a replica holds at most one
	// pool connection waiting on that lock no matter how many writes queue up.
	writeMu sync.Mutex

	// env is the running environment ("dev", "qa", "prod"/"production", ...),
	// read from ENVIRONMENT by cmd/vault/main.go. It gates irreversible ops
	// (e.g. DeleteSecret's hard-delete requires site-admin/root in prod).
	env string

	// Redis pub/sub cache invalidation (HA read-consistency across replicas).
	// After every durable mutation the writer publishes to invChannel; every
	// replica's background subscriber re-hydrates the in-memory slices from the
	// store. All of these are zero/nil when Redis is not wired (empty REDIS_URL
	// or an unreachable server at boot) — the service then degrades to the
	// legacy single-replica behaviour. See invalidate.go.
	redis        *bredis.Client
	invChannel   string
	instanceID   string
	invDebounceD time.Duration // coalesce window for a burst of peer writes
	invBackoffD  time.Duration // reconnect backoff for the subscriber

	seq int
}

// New builds an in-memory Server seeded with a small demonstrable dataset
// (used by tests and any no-Postgres path). Runs as "dev". Unlike a real
// (Postgres-backed) empty store — which now starts BLANK and is populated on
// demand by SeedBuiltins as part of /setup — the in-memory/demo path is seeded
// eagerly so tests and the no-Postgres Register path have the baseline present.
func New(env *crypto.Envelope, auditor Auditor) *Server {
	s, err := NewWithStore(context.Background(), newMemStore(), env, auditor, "dev")
	if err != nil { // memStore never errors
		panic(err)
	}
	s.seed()
	return s
}

// NewWithStore builds a Server backed by the given Store: it loads persisted
// state, or — for a fresh, EMPTY store — starts blank and persists an empty
// snapshot. In non-prod (dev/qa) it then auto-installs the built-in baseline on
// boot (idempotent) so a fresh deploy comes up already-catalogued — dev never
// runs /setup. In prod the baseline is installed on demand by SeedBuiltins as
// part of first-run /setup, so a prod database stays empty until setup
// completes. environment also gates irreversible ops (see Server.env).
func NewWithStore(ctx context.Context, store Store, env *crypto.Envelope, auditor Auditor, environment string) (*Server, error) {
	s := &Server{crypt: env, audit: auditor, records: map[string]crypto.Record{}, store: store, env: environment}
	// Boot runs under the write lock too: a pod starting during a
	// rollout must not persist a seed built on a Load that a peer's write has
	// since overtaken.
	err := withStoreLock(ctx, store, func(ctx context.Context, tx Store) error {
		st, empty, err := tx.Load(ctx)
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		if empty {
			// Fresh install: leave the vault empty and persist the empty snapshot so
			// the store is initialised (subsequent boots hydrate rather than re-enter
			// this path). The vault runs fine empty — ListFolders → [], etc.
			if err := tx.Persist(ctx, s.snapshot()); err != nil {
				return fmt.Errorf("persist empty init: %w", err)
			}
		} else {
			s.hydrate(st)
		}
		// DEV-ONLY auto-seed: install the built-in baseline (secret types incl.
		// type-oauth, password policies, security settings, extension catalog,
		// built-in connections) on every boot, idempotently, so the catalog is in
		// memory before the service serves a request. Dev never uses /setup. qa and
		// prod are prod-like: they start EMPTY and install the baseline via /setup's
		// SeedBuiltins AFTER setup completes — never before. So only dev/local
		// auto-seed here; anything else (qa, prod, staging, ...) waits for /setup.
		switch environment {
		case "dev", "local", "development", "":
			s.seed() // baselineSeedSteps with a nil actor (skips the per-admin personal folder)
			if err := tx.Persist(ctx, s.snapshot()); err != nil {
				return fmt.Errorf("persist dev baseline: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Register wires an in-memory vault service into a gRPC server.
func Register(gs *grpc.Server, env *crypto.Envelope, auditor Auditor) {
	vaultv1.RegisterVaultServiceServer(gs, New(env, auditor))
}

// RegisterInto registers this Server instance (used by main.go so the same
// instance backs both the service and the persistence interceptor).
func (s *Server) RegisterInto(gs *grpc.Server) {
	vaultv1.RegisterVaultServiceServer(gs, s)
}

// snapshot captures the current collections for persistence. Caller should hold
// at least a read lock. The collections and records are copied so Persist can
// iterate them after the lock is released while handlers keep writing to the
// live ones (sharing the live records map raced with those writes).
func (s *Server) snapshot() *state {
	records := make(map[string]crypto.Record, len(s.records))
	for id, rec := range s.records {
		rec.Fields = maps.Clone(rec.Fields)
		records[id] = rec
	}
	return &state{
		types: slices.Clone(s.types), folders: slices.Clone(s.folders), rules: slices.Clone(s.rules),
		raciRules: slices.Clone(s.raciRules), secrets: slices.Clone(s.secrets),
		connections: slices.Clone(s.connections), targets: slices.Clone(s.targets),
		targetRulesets: maps.Clone(s.targetRulesets), policies: slices.Clone(s.policies),
		extCatalog: slices.Clone(s.extCatalog), settings: s.settings, records: records,
	}
}

// errStatePersist marks a writeTx that could not make its mutation durable
// (lock, reload, persist or commit failed). The caller must not report success.
var errStatePersist = errors.New("vault state not persisted")

// writeTx runs mutate as one serialized, durable state write. A full
// snapshot replaces every row, so a write is only safe on the latest committed
// state with no other writer in between. writeTx takes writeMu (this replica)
// and then the store lock (every replica), reloads the committed state into
// memory, runs mutate, and persists the result in the same transaction.
//
// A mutate error is returned unchanged and nothing is persisted. Any other
// failure wraps errStatePersist. Either way memory is re-synced from the store
// so reads don't serve a mutation that never reached the database.
func (s *Server) writeTx(ctx context.Context, mutate func(ctx context.Context) error) error {
	if s.store == nil {
		return mutate(ctx)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var mutErr error
	err := withStoreLock(ctx, s.store, func(ctx context.Context, tx Store) error {
		if err := s.refresh(ctx, tx); err != nil {
			return fmt.Errorf("reload before write: %w", err)
		}
		if mutErr = mutate(ctx); mutErr != nil {
			return mutErr
		}
		s.mu.RLock()
		snap := s.snapshot()
		s.mu.RUnlock()
		return tx.Persist(ctx, snap)
	})
	if mutErr != nil {
		// A handler can change memory before it refuses; the transaction rolled
		// back, so drop those changes too or this replica diverges from the rest.
		if rerr := s.refresh(ctx, s.store); rerr != nil {
			l := log.Ctx(ctx)
			l.Warn().Err(rerr).Msg("vault re-sync after refused write failed")
		}
		return mutErr
	}
	if err != nil {
		if rerr := s.refresh(ctx, s.store); rerr != nil {
			l := log.Ctx(ctx)
			l.Warn().Err(rerr).Msg("vault re-sync after failed write failed")
		}
		return fmt.Errorf("%w: %w", errStatePersist, err)
	}
	return nil
}

func (s *Server) hydrate(st *state) {
	s.types, s.folders, s.rules, s.secrets = st.types, st.folders, st.rules, st.secrets
	s.raciRules = st.raciRules
	s.connections, s.targets, s.policies, s.extCatalog = st.connections, st.targets, st.policies, st.extCatalog
	s.targetRulesets = st.targetRulesets
	s.settings = st.settings
	if st.records != nil {
		s.records = st.records
	}
}

// mutatingMethods are the VaultService RPCs that change state and therefore
// trigger a persist. Reads/reveals are excluded.
var mutatingMethods = map[string]bool{
	"CreateSecret": true, "UpdateSecret": true, "SetSecretAutomation": true, "SetSecretTokenApproval": true,
	"SetSecretTargetForPrincipal": true, "SetSecretAutomationForPrincipal": true,
	// CreateSecretForPrincipal/GenerateSecretForPrincipal create a
	// secret via the same store-mutating path as CreateSecret, for a non-human
	// principal — must persist too.
	"CreateSecretForPrincipal": true, "GenerateSecretForPrincipal": true,
	// MoveSecretForPrincipal/ChangeSecretTypeForPrincipal mutate a secret's
	// folder / type + sealed record, like UpdateSecret.
	"MoveSecretForPrincipal": true, "ChangeSecretTypeForPrincipal": true,
	// Organize verbs. ListFoldersForPrincipal is read-only.
	"RenameSecretForPrincipal": true, "UpdateSecretFieldsForPrincipal": true,
	"CreateFolderForPrincipal": true, "RenameFolderForPrincipal": true, "MoveFolderForPrincipal": true,
	"CreateFolder": true, "RenameFolder": true, "MoveFolder": true, "DeleteFolder": true, "ReorderFolders": true,
	"AddFolderRule": true, "RemoveFolderRule": true, "SetFolderRuleset": true, "SetSecretRuleset": true,
	"SetTargetRuleset": true,
	"CreateSecretType": true, "UpdateSecretType": true, "DeleteSecretType": true, "CloneSecretType": true,
	"SaveConnection": true, "DeleteConnection": true, "SaveTarget": true, "DeleteTarget": true,
	"SavePasswordPolicy": true, "DeletePasswordPolicy": true, "UpdateSecuritySettings": true,
	"ImportExtension": true, "ImportExtensionFromJson": true,
	// Reveal/copy bump the secret's view_count (dashboard "top accessed"),
	// so they must persist too.
	"RevealSecretField": true, "CopySecret": true,
	// RevealSecretFieldForPrincipal is the same bumpView accounting as
	// RevealSecretField, for a non-human (or human) principal caller.
	"RevealSecretFieldForPrincipal": true,
	// RevealSecretVersionField reveals a historical value and bumps view_count
	// too (same access accounting as RevealSecretField).
	"RevealSecretVersionField": true,
	// Lifecycle: retire/restore flip Secret.retired; delete hard-removes the
	// secret (and its encrypted record) from the store slice.
	"RetireSecret": true, "RestoreSecret": true, "DeleteSecret": true,
	// Rotation commit updates the secret_records hot path (new active record) and
	// the Secret's rotation fields, so the outcome report must persist.
	"ReportRotation": true,
	// First-run baseline install (types/folders/policies/connections) — must
	// persist so the seeded state survives a restart.
	"SeedBuiltins": true,
	// ImportCertificate creates a secret (via the internal CreateSecret path,
	// which is a plain Go call and so doesn't go through this interceptor on
	// its own); ExportCertificate bumps view_count like RevealSecretField —
	// both must persist so the outcome survives a restart and every replica
	// invalidates its cache. ReplaceCertificate likewise mutates via the
	// internal UpdateSecret path (also a plain Go call) to overwrite a cert
	// secret's fields in place — same reasoning, must persist here too.
	"ImportCertificate": true, "ExportCertificate": true, "ReplaceCertificate": true,
	// ReportHeartbeat stamps the secret's last heartbeat result and verified_at.
	// Every write reloads committed state first, so an unpersisted
	// in-memory change would be wiped by the next write.
	"ReportHeartbeat": true,
	// RotateKek is deliberately ABSENT: rotateOnce runs its re-wrap sweep as its
	// own writeTx (kek_rotate.go), because the scheduler calls it outside any RPC.
}

// PersistUnary is a gRPC unary interceptor that runs every mutating RPC as a
// writeTx: serialized across replicas, based on freshly reloaded state, and
// persisted in the same transaction. Centralising it here keeps the handlers
// unchanged. A persist failure fails the RPC with Unavailable (it
// used to be logged while the caller was told the write succeeded).
func (s *Server) PersistUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	method := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
	if s.store == nil || !mutatingMethods[method] {
		return handler(ctx, req)
	}
	var resp any
	err := s.writeTx(ctx, func(ctx context.Context) error {
		var herr error
		resp, herr = handler(ctx, req)
		return herr
	})
	if errors.Is(err, errStatePersist) {
		l := log.Ctx(ctx)
		l.Error().Err(err).Str("rpc", method).Msg("persist after mutation failed")
		return nil, status.Error(codes.Unavailable, "the change could not be saved; retry")
	}
	if err != nil {
		return resp, err
	}
	// The write is durable. Publish a cache-invalidation so every replica
	// (including this one — the reload is idempotent) re-hydrates from the store
	// and converges on the new state. Best-effort: a publish failure is logged,
	// not fatal — a peer that misses it only serves stale reads, since its next
	// write reloads under the lock anyway. The RPC method name is carried as the
	// entity kind for observability; the subscriber reloads the full state
	// regardless.
	s.publishInvalidate(ctx, method, "")
	return resp, nil
}

func (s *Server) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), s.seq)
}

func (s *Server) emit(ctx context.Context, actor, action, subject string, sensitive bool) {
	s.emitAttrs(ctx, actor, action, subject, sensitive, nil)
}

// emitAttrs is emit plus non-sensitive attributes (e.g. an outcome string).
// Callers must never put a credential value in attrs — audit.Event.Attributes
// is stored and forwarded like any other event field, sensitive or not.
func (s *Server) emitAttrs(ctx context.Context, actor, action, subject string, sensitive bool, attrs map[string]string) {
	s.emitTier(ctx, audit.TierActivity, actor, action, subject, sensitive, attrs)
}

// emitTier is emitAttrs with an explicit tier. Routine events use
// audit.TierActivity (via emit/emitAttrs); security-critical events that must
// land in the tamper-evident tier (e.g. break-glass emergency reveal) pass
// audit.TierAudit. Same credential-value prohibition as emitAttrs. Best-effort:
// the emit error is swallowed. Callers for whom the audit event IS the
// compensating control for a deliberate policy bypass (and so must be
// fail-closed) should call emitTierErr directly instead.
func (s *Server) emitTier(ctx context.Context, tier audit.Tier, actor, action, subject string, sensitive bool, attrs map[string]string) {
	_ = s.emitTierErr(ctx, tier, actor, action, subject, sensitive, attrs)
}

// emitTierErr is emitTier but returns the emit error instead of swallowing it.
// A nil Auditor still counts as success (skips emission, mirrors emitTier).
func (s *Server) emitTierErr(ctx context.Context, tier audit.Tier, actor, action, subject string, sensitive bool, attrs map[string]string) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Emit(ctx, audit.Event{
		Tier:        tier,
		Action:      action,
		ActorUserID: actor,
		Subject:     subject,
		Sensitive:   sensitive,
		Attributes:  attrs,
	})
}

// SetNotifier installs the notification sink (called from cmd/vault).
func (s *Server) SetNotifier(n Notifier) { s.notifier = n }

// SetHeartbeat installs the heartbeat queue (pool-backed) + worker-identity
// verifier (called from cmd/vault after the pool is opened).
func (s *Server) SetHeartbeat(pool *pgxpool.Pool, wid workloadid.WorkloadIdentityVerifier) {
	s.hb = newHeartbeatStore(pool)
	s.wid = wid
}

// SetRotation installs the rotation queue + append-only version store (both
// pool-backed) and the worker-identity verifier (shared with heartbeat). Called
// from cmd/vault after the pool is opened. Idempotent for the version store so
// it can safely run alongside SetHeartbeat regardless of call order.
func (s *Server) SetRotation(pool *pgxpool.Pool, wid workloadid.WorkloadIdentityVerifier) {
	if s.vers == nil {
		s.vers = newVersionStore(pool)
	}
	s.rot = newRotationStore(pool)
	// Break-glass shares the same pool: its ledger insert and forced-rotation
	// enqueue happen together in the BreakGlassSecret handler.
	s.bg = newBreakGlassStore(pool)
	if wid != nil {
		s.wid = wid
	}
}

// SetKeyring installs the working-KEK keyring, its durable store (KeyringAdmin
// — *keyringStore in production, a fake in tests), and the root KEK + ref used
// to wrap new working-KEK generations. Called from cmd/vault right after
// NewWithStore, mirroring SetHeartbeat/SetRotation. RotateKek requires this to
// have been called; the future scheduled-rotation sweep will too.
func (s *Server) SetKeyring(kr *crypto.KeyringKEK, ks KeyringAdmin, root crypto.KEKProvider, rootRef string) {
	s.keyring = kr
	s.keyringStore = ks
	s.root = root
	s.rootRef = rootRef
}

// notifyInformed resolves the Informed subjects from the (live) chain and fires
// them at the notifier. Best-effort: no-op if unset or no informed subjects.
func (s *Server) notifyInformed(ctx context.Context, actor, action, kind, id, label string, chain []authz.CategoryRuleset) {
	if s.notifier == nil {
		return
	}
	subjects := authz.InformedSubjects(chain)
	if len(subjects) == 0 {
		return
	}
	s.notifier.Notify(context.WithoutCancel(ctx), NotifyEvent{
		Action: action, ResourceKind: kind, ResourceID: id,
		ResourceLabel: label, ActorUserID: actor, Subjects: subjects,
	})
}

// ---- lookups (caller holds the lock) ---------------------------------------

func (s *Server) findType(id string) *vaultv1.SecretType {
	for _, t := range s.types {
		if t.Id == id {
			return t
		}
	}
	return nil
}

func (s *Server) findFolder(id string) *vaultv1.Folder {
	for _, f := range s.folders {
		if f.Id == id {
			return f
		}
	}
	return nil
}

func (s *Server) findSecret(id string) *vaultv1.Secret {
	for _, sec := range s.secrets {
		if sec.Id == id {
			return sec
		}
	}
	return nil
}

// typeHasHeartbeat reports whether typeID names a heartbeat-capable secret
// type (e.g. Windows Domain Account), gating whether CreateSecret/UpdateSecret
// schedule a heartbeat_schedule row.
func (s *Server) typeHasHeartbeat(typeID string) bool {
	t := s.findType(typeID)
	return t != nil && t.GetHeartbeat()
}

// secretHeartbeatEnabled reports whether a secret should be heartbeat-scheduled:
// its type must be heartbeat-capable AND the secret must not carry a per-secret
// heartbeat opt-out.
func (s *Server) secretHeartbeatEnabled(sec *vaultv1.Secret) bool {
	return !sec.GetHeartbeatOptOut() && s.typeHasHeartbeat(sec.GetTypeId())
}

// ancestorsInclusive returns the folder and every ancestor up to the root. It
// visits each folder at most once, so a parent cycle ends the walk instead of
// spinning forever.
func (s *Server) ancestorsInclusive(id string) []*vaultv1.Folder {
	var out []*vaultv1.Folder
	seen := map[string]bool{}
	for cur := s.findFolder(id); cur != nil && !seen[cur.Id]; cur = s.findFolder(cur.ParentId) {
		seen[cur.Id] = true
		out = append(out, cur)
		if cur.ParentId == "" {
			break
		}
	}
	return out
}

// canRead reports whether actor may read a secret, via its folder's RBAC.
//
// NOTE: without the identity/authz layer (group membership, site-admin
// override) the vault can only evaluate personal ownership and DIRECT
// user-subject grants on the folder or an ancestor. Group/role grants and admin
// override are resolved by the gateway/authz layer (the authz package), which
// passes the actor's effective scopes.
// ---- firewall-RACI access (the authz package) ---------------------------------

// evalOf builds the authz subject from the gateway-resolved actor context. A
// non-human principal (service account or workload) is a RACI subject
// keyed by its principal id — the same SUBJECT_KIND_USER rule shape a human
// grant uses (the vault API has no distinct subject kind for
// machines) — and is never auto-admin: is_site_admin/is_root apply only to
// human callers, so a machine principal's access comes entirely from its
// RACI/Target grants, never from a spoofed admin flag.
func evalOf(a *vaultv1.ActorContext) authz.EvalSubject {
	if isUserToken(a) {
		return authz.EvalSubject{UserID: a.GetUserId(), GroupNames: a.GetGroupNames()}
	}
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return authz.EvalSubject{
			UserID:     machineSubjectID(a.GetPrincipalId()),
			GroupNames: a.GetGroupNames(),
		}
	}
	return authz.EvalSubject{
		UserID:      a.GetUserId(),
		IsSiteAdmin: a.GetIsSiteAdmin(),
		IsRoot:      a.GetIsRoot(),
		GroupNames:  a.GetGroupNames(),
	}
}

// humanUserIDPrefix starts every human user id identity mints.
const humanUserIDPrefix = "user-"

// machineSubjectID is the RACI subject key of a service account or workload:
// its principal id, unless that id has the human user-id shape. User rules and
// folder owners are keyed by the same string, so such a machine would
// otherwise match that user's grants and personal folder. It then matches no
// user rule at all, only its groups.
func machineSubjectID(principalID string) string {
	if strings.HasPrefix(principalID, humanUserIDPrefix) {
		return ""
	}
	return principalID
}

// resolveChain is the one RACI evaluation of an actor against a chain. An
// everyone rule means all people: a service account, workload or personal
// token gains nothing from its allow cells and matches only rules naming its
// id, its user or its groups. Its deny cells still apply, so an everyone deny
// never opens up for a machine.
func resolveChain(a *vaultv1.ActorContext, chain []authz.CategoryRuleset) authz.ActionResult {
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		chain = withoutEveryoneAllows(chain)
	}
	return authz.Resolve(evalOf(a), chain)
}

// withoutEveryoneAllows returns chain with the allow cells of every everyone
// rule removed, leaving its deny cells. The input is not modified.
func withoutEveryoneAllows(chain []authz.CategoryRuleset) []authz.CategoryRuleset {
	out := make([]authz.CategoryRuleset, 0, len(chain))
	for _, c := range chain {
		kept := make([]authz.Rule, 0, len(c.Rules))
		for _, r := range c.Rules {
			if r.Subject.Kind != authz.SubjEveryone {
				kept = append(kept, r)
				continue
			}
			denies := map[authz.Action]authz.Grant{}
			for act, g := range r.Grants {
				if g == authz.GrantDeny {
					denies[act] = g
				}
			}
			if len(denies) > 0 {
				kept = append(kept, authz.Rule{Subject: r.Subject, Grants: denies})
			}
		}
		c.Rules = kept
		out = append(out, c)
	}
	return out
}

// principalActorID returns the id to attribute an audit/notify event to: the
// principal id for a non-human caller (service account or workload), else the
// human user id. Mirrors evalOf's principal-kind branch.
func principalActorID(a *vaultv1.ActorContext) string {
	if isUserToken(a) {
		return a.GetUserId()
	}
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return a.GetPrincipalId()
	}
	return a.GetUserId()
}

func subjKindToAuthz(k vaultv1.SubjectKind) authz.SubjectKind {
	switch k {
	case vaultv1.SubjectKind_SUBJECT_KIND_USER:
		return authz.SubjUser
	case vaultv1.SubjectKind_SUBJECT_KIND_GROUP:
		return authz.SubjGroup
	default:
		return authz.SubjEveryone
	}
}

// raciRulesFor returns a folder's own rules, ordered.
func (s *Server) raciRulesFor(folderID string) []*vaultv1.RaciRule {
	var out []*vaultv1.RaciRule
	for _, r := range s.raciRules {
		if r.GetFolderId() == folderID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetOrder() < out[j].GetOrder() })
	return out
}

// raciRulesOrdered returns a copy of rules sorted by Order (used for a
// secret's own ruleset, which — unlike a folder's — is stored inline on the
// entity rather than in the shared s.raciRules slice).
func raciRulesOrdered(rules []*vaultv1.RaciRule) []*vaultv1.RaciRule {
	out := append([]*vaultv1.RaciRule(nil), rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].GetOrder() < out[j].GetOrder() })
	return out
}

// rulesetOf maps one folder to an authz CategoryRuleset (owners + rules).
func (s *Server) rulesetOf(f *vaultv1.Folder) authz.CategoryRuleset {
	owners := append([]string(nil), f.GetOwners()...)
	if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && f.GetOwnerUserId() != "" {
		owners = append(owners, f.GetOwnerUserId())
	}
	var rules []authz.Rule
	for _, r := range s.raciRulesFor(f.GetId()) {
		grants := make(map[authz.Action]authz.Grant, len(r.GetGrants()))
		for k, v := range r.GetGrants() {
			grants[authz.Action(k)] = authz.Grant(v)
		}
		rules = append(rules, authz.Rule{
			Subject: authz.RuleSubject{Kind: subjKindToAuthz(r.GetSubjectKind()), Name: r.GetSubjectName()},
			Grants:  grants,
		})
	}
	return authz.CategoryRuleset{Name: f.GetName(), Owners: owners, Rules: rules}
}

// chainFor builds the ruleset chain for a folder: the folder first, then its
// ancestors to the root (the authz package's target-first order).
func (s *Server) chainFor(folderID string) []authz.CategoryRuleset {
	var chain []authz.CategoryRuleset
	for _, f := range s.ancestorsInclusive(folderID) {
		chain = append(chain, s.rulesetOf(f))
	}
	return chain
}

// rulesetOfSecret maps a secret's own overrides to an authz
// CategoryRuleset. Secrets have no owners of their own — ownership lives on
// the folder — so a per-secret deny can never shadow the folder owner's
// auto-read/approve/author (the folder node further down the chain still
// carries Owners, and the authz package's owner short-circuit runs before any
// rule in the chain, including this one, is evaluated).
func (s *Server) rulesetOfSecret(sec *vaultv1.Secret) authz.CategoryRuleset {
	rules := make([]authz.Rule, 0, len(sec.GetRuleset()))
	for _, r := range raciRulesOrdered(sec.GetRuleset()) {
		grants := make(map[authz.Action]authz.Grant, len(r.GetGrants()))
		for k, v := range r.GetGrants() {
			grants[authz.Action(k)] = authz.Grant(v)
		}
		rules = append(rules, authz.Rule{
			Subject: authz.RuleSubject{Kind: subjKindToAuthz(r.GetSubjectKind()), Name: r.GetSubjectName()},
			Grants:  grants,
		})
	}
	return authz.CategoryRuleset{Name: sec.GetName(), Owners: nil, Rules: rules}
}

// secretChain builds the ruleset chain for a secret: the secret's own
// ruleset first (most specific), then its folder and ancestors.
func (s *Server) secretChain(sec *vaultv1.Secret) []authz.CategoryRuleset {
	chain := []authz.CategoryRuleset{s.rulesetOfSecret(sec)}
	return append(chain, s.chainFor(sec.GetFolderId())...)
}

// rulesetOfTarget maps one target to an authz CategoryRuleset: its own
// ruleset plus its OwnerUserId (personal target) as an auto-read/approve/
// author owner, mirroring rulesetOf's folder-owner handling.
func (s *Server) rulesetOfTarget(t *vaultv1.Target) authz.CategoryRuleset {
	var owners []string
	if t.GetOwnerUserId() != "" {
		owners = append(owners, t.GetOwnerUserId())
	}
	rules := make([]authz.Rule, 0, len(s.targetRulesets[t.GetId()]))
	for _, r := range raciRulesOrdered(s.targetRulesets[t.GetId()]) {
		grants := make(map[authz.Action]authz.Grant, len(r.GetGrants()))
		for k, v := range r.GetGrants() {
			grants[authz.Action(k)] = authz.Grant(v)
		}
		rules = append(rules, authz.Rule{
			Subject: authz.RuleSubject{Kind: subjKindToAuthz(r.GetSubjectKind()), Name: r.GetSubjectName()},
			Grants:  grants,
		})
	}
	return authz.CategoryRuleset{Name: t.GetName(), Owners: owners, Rules: rules}
}

// targetChain builds the ruleset chain for a target: just its own ruleset —
// unlike a folder or secret, a target has no ancestry to chain through (kept
// as its own ruleset for now; a future revision could root it
// under its connection).
func (s *Server) targetChain(t *vaultv1.Target) []authz.CategoryRuleset {
	return []authz.CategoryRuleset{s.rulesetOfTarget(t)}
}

// resolveTarget is the single access decision for an actor on a target.
func (s *Server) resolveTarget(a *vaultv1.ActorContext, t *vaultv1.Target) authz.ActionResult {
	return resolveChain(a, s.targetChain(t))
}

// canConnectTarget reports whether the actor may reveal/connect via this
// target: RACI C (Read) on the target's own ruleset. Site-admin/root
// short-circuit is inherent in authz.Resolve/decideAction (same as every
// other resolve* helper), not special-cased here.
func (s *Server) canConnectTarget(a *vaultv1.ActorContext, t *vaultv1.Target) bool {
	if t == nil {
		return false
	}
	return s.resolveTarget(a, t).Read.Allowed
}

// isHumanAdmin reports whether a is a HUMAN principal carrying is_site_admin
// or is_root. Mirrors evalOf's anti-spoof guard: those flags are gateway-
// resolved from a human identity's roles and must never be trusted from a
// non-human ActorContext — a service-account or workload caller that happens
// to carry is_site_admin=true (spoofed, or a gateway bug) must never be
// treated as admin. Any admin-authority check that consults these flags
// should go through this helper rather than reading them directly.
func isHumanAdmin(a *vaultv1.ActorContext) bool {
	return a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN && (a.GetIsSiteAdmin() || a.GetIsRoot())
}

// isTargetOwner gates editing a target's ruleset: site-admin/root (human
// only, see isHumanAdmin), or — for a personal target — its own OwnerUserId.
// A shared target (OwnerUserId empty) is admin-only to edit, mirroring
// SaveTarget/DeleteTarget's admin gate for shared targets (targets have no
// Owners list like folders do).
func (s *Server) isTargetOwner(a *vaultv1.ActorContext, t *vaultv1.Target) bool {
	if isHumanAdmin(a) {
		return true
	}
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return false
	}
	return t.GetOwnerUserId() != "" && t.GetOwnerUserId() == a.GetUserId()
}

// resolve is the single access decision for an actor on a folder.
func (s *Server) resolve(a *vaultv1.ActorContext, folderID string) authz.ActionResult {
	if s.closedToToken(a, folderID) {
		return authz.ActionResult{}
	}
	return resolveChain(a, s.chainFor(folderID))
}

// resolveSecret is the single access decision for an actor on a secret,
// evaluating the secret's own ruleset before its folder's.
func (s *Server) resolveSecret(a *vaultv1.ActorContext, sec *vaultv1.Secret) authz.ActionResult {
	if s.closedToToken(a, sec.GetFolderId()) {
		return authz.ActionResult{}
	}
	return resolveChain(a, s.secretChain(sec))
}

// closedToToken reports a folder inside another user's personal subtree, which
// a personal token may never reach, whatever the rules or the owner's standing.
func (s *Server) closedToToken(a *vaultv1.ActorContext, folderID string) bool {
	if !isUserToken(a) {
		return false
	}
	personal, owner := s.destPersonal(s.findFolder(folderID))
	return personal && owner != a.GetUserId()
}

// canRead reports whether the actor may read/reveal (RACI C) the secret.
func (s *Server) canRead(a *vaultv1.ActorContext, sec *vaultv1.Secret) bool {
	if sec == nil {
		return false
	}
	return s.resolveSecret(a, sec).Read.Allowed
}

// canManage reports whether the actor may create/edit/rotate (RACI R) in a folder.
func (s *Server) canManage(a *vaultv1.ActorContext, folderID string) bool {
	return s.resolve(a, folderID).Author.Allowed
}

// isFolderOwner gates editing a folder's ruleset. Ownership inherits DOWN the
// chain (owning a parent lets you manage descendants), plus site-admin/root and
// personal-folder ownership.
//
// Admin authority goes through isHumanAdmin, never the raw flags: folder- and
// secret-ruleset edits are the grant-GRANTING surface, so a non-human
// principal carrying a spoofed is_site_admin could otherwise rewrite a
// folder's ruleset to grant itself RACI-C and then read every secret under it.
// The same hardening applies to isTargetOwner.
func (s *Server) isFolderOwner(a *vaultv1.ActorContext, f *vaultv1.Folder) bool {
	if isHumanAdmin(a) {
		return true
	}
	// Ownership is keyed by HUMAN user id. A non-human principal carries no
	// UserId, and an empty UserId would otherwise MATCH an ancestor's empty
	// OwnerUserId (or an empty entry in Owners) and hand it ownership —
	// mirrors isTargetOwner's OwnerUserId != "" guard.
	// A user id on a non-human ActorContext (spoofed, or a token acting for its
	// user) never confers ownership on these human paths.
	uid := a.GetUserId()
	if uid == "" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return false
	}
	for _, anc := range s.ancestorsInclusive(f.GetId()) {
		if anc.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && anc.GetOwnerUserId() == uid {
			return true
		}
		for _, o := range anc.GetOwners() {
			if o == uid {
				return true
			}
		}
	}
	return false
}

func (s *Server) isSensitiveField(t *vaultv1.SecretType, key string) bool {
	if t == nil {
		return false
	}
	for _, f := range t.Fields {
		if f.Key == key {
			return f.Kind == vaultv1.FieldKind_FIELD_KIND_PASSWORD || f.Sensitive
		}
	}
	return false
}

func origin(t *vaultv1.SecretType) vaultv1.TypeOrigin {
	if t.Origin == vaultv1.TypeOrigin_TYPE_ORIGIN_UNSPECIFIED {
		return vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM
	}
	return t.Origin
}

// seedStep is one named, idempotent baseline-seed action. The baseline is
// expressed as an ORDERED list of these so future subsystems (e.g. a
// Privileged-Access-System) can slot their own steps in without touching the
// existing ones — and so seed() and the on-demand SeedBuiltins RPC share one
// source of truth. Each step is create-if-missing, so running the list twice is
// a no-op. The caller holds s.mu for write.
type seedStep struct {
	name string
	run  func(actor *vaultv1.ActorContext)
}

// baselineSeedSteps returns the ordered baseline-install steps. The final step
// ensures the ACTING admin's personal folder (from actor.UserId); every earlier
// step ignores the actor (nil is fine — e.g. seed()'s demo path passes nil).
func (s *Server) baselineSeedSteps() []seedStep {
	return []seedStep{
		{"master-personal-root", func(*vaultv1.ActorContext) { s.ensureMasterPersonalFolder() }},
		{"password-policies", func(*vaultv1.ActorContext) { s.ensureDefaultPolicies() }},
		{"security-settings", func(*vaultv1.ActorContext) { s.ensureSecuritySettings() }},
		{"builtin-types", func(*vaultv1.ActorContext) { s.ensureBuiltinTypes() }},
		{"extension-catalog", func(*vaultv1.ActorContext) { s.ensureExtensionCatalog() }},
		{"builtin-connections", func(*vaultv1.ActorContext) { s.ensureBuiltinConnections() }},
		{"admin-personal-folder", func(a *vaultv1.ActorContext) { s.ensurePersonalFolder(a.GetUserId()) }},
	}
}

// seed installs the built-in baseline into an empty in-memory vault (the demo /
// test / no-Postgres path). It runs the same ordered steps SeedBuiltins does,
// minus the per-admin personal folder (no actor). Idempotent.
func (s *Server) seed() {
	for _, step := range s.baselineSeedSteps() {
		step.run(nil)
	}
}

// ensureMasterPersonalFolder creates the master "Personal Folders" root (a
// container, not browsable by end users) if it is not already present. Each
// user's own personal folder hangs under it.
func (s *Server) ensureMasterPersonalFolder() {
	for _, f := range s.folders {
		if f.GetIsMasterPersonal() {
			return
		}
	}
	s.folders = append(s.folders, &vaultv1.Folder{
		Id: "folder-personal-root", Name: "Personal Folders",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, IsMasterPersonal: true,
	})
}

// ensureDefaultPolicies adds any missing shipped password policies.
func (s *Server) ensureDefaultPolicies() {
	i32 := func(v int32) *int32 { return &v }
	for _, p := range []*vaultv1.PasswordPolicy{
		{Id: "pwpolicy-default", Name: "Default", MinLength: 12, MaxLength: i32(64), RequireUpper: true, RequireLower: true, RequireDigit: true, RotationDays: i32(90)},
		{Id: "pwpolicy-privileged", Name: "Privileged / Admin", MinLength: 20, MaxLength: i32(48), RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true, RotationDays: i32(30), StartClass: "letter", EndLiteral: "!", ExcludeChars: "\\`"},
	} {
		if findByID(s.policies, p.Id) == nil {
			s.policies = append(s.policies, p)
		}
	}
}

// ensureSecuritySettings installs the default instance security settings if
// none exist yet (never clobbers operator-changed settings). KekRotationDays
// is seeded from KEK_ROTATION_DAYS (falling back to 90) — this env default
// applies to a FRESH instance only; once seeded, an admin who sets it to 0
// turns auto-rotation off and it stays off (no "0 -> default" coercion, see
// settingsWithDefaults).
func (s *Server) ensureSecuritySettings() {
	if s.settings != nil {
		return
	}
	s.settings = &vaultv1.SecuritySettings{
		DefaultPasswordPolicyId:        "pwpolicy-default",
		RequireMfaForSensitiveCheckout: true, AllowApiForSensitive: false,
		RequestHistoryRetentionDays: defaultRequestHistoryRetentionDays,
		KekRotationDays:             defaultKekRotationDays(),
	}
}

// ensureBuiltinTypes adds any missing built-in secret types. The full
// catalogue lives in BuiltinTypes() so cmd/seed upserts the identical set.
func (s *Server) ensureBuiltinTypes() {
	for _, t := range BuiltinTypes() {
		if s.findType(t.Id) == nil {
			s.types = append(s.types, t)
		}
	}
}

// ensureExtensionCatalog adds any missing importable extension packs.
func (s *Server) ensureExtensionCatalog() {
	for _, e := range ExtensionCatalog() {
		if findByID(s.extCatalog, e.Id) == nil {
			s.extCatalog = append(s.extCatalog, e)
		}
	}
}

// ensureBuiltinConnections adds any missing shipped connection templates.
func (s *Server) ensureBuiltinConnections() {
	for _, c := range BuiltinConnections() {
		if findByID(s.connections, c.Id) == nil {
			s.connections = append(s.connections, c)
		}
	}
}

// ensurePersonalFolder creates a user's own personal folder (under the master
// personal root) if they don't already have one. No-op for an empty or
// "system" actor (seed()'s demo path and any non-user caller), and for a store
// that hasn't installed the master personal root yet (a fresh prod store
// before /setup's SeedBuiltins runs — it must stay empty, not grow orphaned
// personal folders with a dangling parent). Reports whether it created one, so
// callers that persist can skip doing so when nothing changed. Caller holds
// s.mu for write.
func (s *Server) ensurePersonalFolder(userID string) bool {
	if userID == "" || userID == "system" {
		return false
	}
	var hasMasterRoot bool
	for _, f := range s.folders {
		if f.GetIsMasterPersonal() {
			hasMasterRoot = true
		}
		if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && !f.GetIsMasterPersonal() && f.GetOwnerUserId() == userID {
			return false
		}
	}
	if !hasMasterRoot {
		return false
	}
	s.folders = append(s.folders, &vaultv1.Folder{
		Id: s.nextID("folder"), Name: "Personal", ParentId: "folder-personal-root",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: userID,
	})
	return true
}

// SeedBuiltins installs the built-in baseline on demand (first-run /setup),
// idempotently, by running the ordered baselineSeedSteps. It ensures the acting
// admin's personal folder from the actor. Returns the TOTAL counts present
// afterwards (not just newly-added), so an idempotent re-run reports the same
// numbers. Registered as a mutating method so PersistUnary persists the result.
func (s *Server) SeedBuiltins(ctx context.Context, req *vaultv1.SeedBuiltinsRequest) (*vaultv1.SeedBuiltinsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor := req.GetActor()
	for _, step := range s.baselineSeedSteps() {
		step.run(actor)
	}
	resp := &vaultv1.SeedBuiltinsResponse{
		Types:       safeconv.Int32(len(s.types)),
		Connections: safeconv.Int32(len(s.connections)),
		Folders:     safeconv.Int32(len(s.folders)),
	}
	s.emit(ctx, actor.GetUserId(), "vault.seed_builtins", "vault", false)
	return resp, nil
}

func errNotFound(what string) error { return status.Errorf(codes.NotFound, "%s not found", what) }

// isUserToken reports a personal-token caller: evaluated as its owning user,
// but never with admin, root, break-glass or another user's personal folder,
// and never given a secret value directly.
func isUserToken(a *vaultv1.ActorContext) bool {
	return a.GetPrincipalKind() == vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
}
