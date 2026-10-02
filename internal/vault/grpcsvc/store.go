// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"fmt"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// state is the full set of collections the vault owns. The Server keeps these
// in memory at runtime (single source of truth for query logic); a Store loads
// them on boot and persists a snapshot after every mutation.
type state struct {
	types       []*vaultv1.SecretType
	folders     []*vaultv1.Folder
	rules       []*vaultv1.FolderAccessRule
	raciRules   []*vaultv1.RaciRule
	secrets     []*vaultv1.Secret
	connections []*vaultv1.Connection
	targets     []*vaultv1.Target
	// targetRulesets holds each target's own ordered RACI ruleset,
	// keyed by target id. A target has no folder ancestry, so — unlike
	// raciRules, which is a flat slice filtered by RaciRule.FolderId — this is a
	// map: the RaciRule message carries no target_id field to filter on.
	targetRulesets map[string][]*vaultv1.RaciRule
	policies       []*vaultv1.PasswordPolicy
	extCatalog     []*vaultv1.SecretType
	settings       *vaultv1.SecuritySettings
	records        map[string]crypto.Record // secretID -> sealed field set
}

// Store persists and restores the vault's state. Two implementations: memStore
// (dev/tests, process-local) and pgStore (Postgres). NOTE: pgStore persists a
// FULL snapshot on each mutation (delete-all + insert-all per table inside one
// transaction). The dataset is small and this keeps the grpcsvc handlers
// unchanged; swap for per-row upserts if the data grows. TODO(perf).
//
// Because a snapshot replaces every row, a write is only safe if it is based
// on the latest committed state and no other writer commits in between.
// Server.writeTx guarantees that through lockedStore.
type Store interface {
	// Load reads all collections. empty is true when nothing has been seeded
	// yet (a fresh database), signalling the caller to seed.
	Load(ctx context.Context) (st *state, empty bool, err error)
	Persist(ctx context.Context, st *state) error
}

// lockedStore is a Store that can run fn as one exclusive write: fn gets a
// Store bound to a transaction that holds a lock every replica sharing the
// store contends on, and the transaction commits only if fn returns nil.
type lockedStore interface {
	Locked(ctx context.Context, fn func(ctx context.Context, tx Store) error) error
}

// withStoreLock runs fn under st's write lock. A Store with no cross-process
// lock (memStore, test fakes) runs fn directly against itself; the Server's
// writeMu still serializes writers inside the process.
func withStoreLock(ctx context.Context, st Store, fn func(ctx context.Context, tx Store) error) error {
	if l, ok := st.(lockedStore); ok {
		return l.Locked(ctx, fn)
	}
	return fn(ctx, st)
}

// ---- memStore: process-local, no durability (dev default + tests) ----------

type memStore struct{}

func newMemStore() *memStore { return &memStore{} }

// Load always reports empty so New seeds a fresh in-memory dataset (identical to
// the pre-Postgres behaviour the unit tests rely on).
func (memStore) Load(context.Context) (*state, bool, error) { return nil, true, nil }

// Persist is a no-op: the Server's own slices are the runtime source of truth.
func (memStore) Persist(context.Context, *state) error { return nil }

// ---- pgStore: Postgres-backed durability ------------------------------------

// vaultWriteLockKey is the pg_advisory_xact_lock key that serializes vault
// state writes across every replica sharing the database. Any fixed
// value works as long as nothing else in the database uses it ("vault").
const vaultWriteLockKey int64 = 0x7661756c74

// writeLockTimeout bounds how long a writer waits for the vault write lock
// before failing the RPC, so a stalled holder can't hang every writer.
const writeLockTimeout = "15s"

type pgStore struct{ db *postgres.DB }

// NewPGStore returns a Postgres-backed Store over the given pool.
func NewPGStore(db *postgres.DB) Store { return &pgStore{db: db} }

// Locked runs fn in one transaction holding the vault write lock. The lock is
// transaction-scoped, so it is released on commit or rollback. Under READ
// COMMITTED every statement after the lock sees every write committed before
// it, since writers commit before they release the lock.
func (p *pgStore) Locked(ctx context.Context, fn func(ctx context.Context, tx Store) error) error {
	return p.db.RunInTx(ctx, func(tx postgres.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+writeLockTimeout+"'"); err != nil {
			return fmt.Errorf("set lock_timeout: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", vaultWriteLockKey); err != nil {
			return fmt.Errorf("acquire vault write lock: %w", err)
		}
		return fn(ctx, pgTxStore{tx: tx})
	})
}

// pgTxStore is the Store view handed to a Locked callback: Load and Persist run
// inside the lock-holding transaction.
type pgTxStore struct{ tx postgres.Tx }

func (t pgTxStore) Load(ctx context.Context) (*state, bool, error) { return loadState(ctx, t.tx) }

func (t pgTxStore) Persist(ctx context.Context, st *state) error { return persistState(ctx, t.tx, st) }

func loadCollection[T proto.Message](ctx context.Context, db postgres.Querier, table string, mk func() T) ([]T, error) {
	rows, err := db.Query(ctx, "SELECT data FROM "+table)
	if err != nil {
		return nil, fmt.Errorf("select %s: %w", table, err)
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		msg := mk()
		// DiscardUnknown so persisted records survive proto field removals
		// (the schema may drop fields between releases).
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, msg); err != nil {
			return nil, fmt.Errorf("unmarshal %s: %w", table, err)
		}
		out = append(out, msg)
	}
	return out, rows.Err()
}

func (p *pgStore) Load(ctx context.Context) (*state, bool, error) {
	return loadState(ctx, p.db.Querier())
}

func loadState(ctx context.Context, q postgres.Querier) (*state, bool, error) {
	st := &state{records: map[string]crypto.Record{}}
	for _, load := range []func(context.Context, postgres.Querier, *state) error{loadCollections, loadTargetRulesets, loadSettings, loadRecords} {
		if err := load(ctx, q, st); err != nil {
			return nil, false, err
		}
	}
	empty := len(st.types) == 0 && len(st.folders) == 0 && st.settings == nil
	return st, empty, nil
}

// loadTargetRulesets hydrates each target's own ordered RACI ruleset, keyed by
// target id. A dedicated table (rather than filtering raci_rules in memory,
// as folder rules do via RaciRule.FolderId): the RaciRule message carries no
// target_id field, so the correlation has to live in a SQL column instead.
func loadTargetRulesets(ctx context.Context, q postgres.Querier, st *state) error {
	rows, err := q.Query(ctx, "SELECT target_id, data FROM target_raci_rules")
	if err != nil {
		return fmt.Errorf("select target_raci_rules: %w", err)
	}
	defer rows.Close()
	st.targetRulesets = map[string][]*vaultv1.RaciRule{}
	for rows.Next() {
		var targetID string
		var raw []byte
		if err := rows.Scan(&targetID, &raw); err != nil {
			return err
		}
		rule := &vaultv1.RaciRule{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, rule); err != nil {
			return fmt.Errorf("unmarshal target_raci_rules: %w", err)
		}
		st.targetRulesets[targetID] = append(st.targetRulesets[targetID], rule)
	}
	return rows.Err()
}

// loadCollections hydrates every protojson-backed entity table into st.
func loadCollections(ctx context.Context, q postgres.Querier, st *state) error {
	var err error
	if st.types, err = loadCollection(ctx, q, "secret_types", func() *vaultv1.SecretType { return &vaultv1.SecretType{} }); err != nil {
		return err
	}
	if st.folders, err = loadCollection(ctx, q, "folders", func() *vaultv1.Folder { return &vaultv1.Folder{} }); err != nil {
		return err
	}
	if st.rules, err = loadCollection(ctx, q, "folder_rules", func() *vaultv1.FolderAccessRule { return &vaultv1.FolderAccessRule{} }); err != nil {
		return err
	}
	if st.raciRules, err = loadCollection(ctx, q, "raci_rules", func() *vaultv1.RaciRule { return &vaultv1.RaciRule{} }); err != nil {
		return err
	}
	if st.secrets, err = loadCollection(ctx, q, "secrets", func() *vaultv1.Secret { return &vaultv1.Secret{} }); err != nil {
		return err
	}
	if st.connections, err = loadCollection(ctx, q, "connections", func() *vaultv1.Connection { return &vaultv1.Connection{} }); err != nil {
		return err
	}
	if st.targets, err = loadCollection(ctx, q, "targets", func() *vaultv1.Target { return &vaultv1.Target{} }); err != nil {
		return err
	}
	if st.policies, err = loadCollection(ctx, q, "password_policies", func() *vaultv1.PasswordPolicy { return &vaultv1.PasswordPolicy{} }); err != nil {
		return err
	}
	if st.extCatalog, err = loadCollection(ctx, q, "extension_catalog", func() *vaultv1.SecretType { return &vaultv1.SecretType{} }); err != nil {
		return err
	}
	return nil
}

// loadSettings hydrates the singleton security-settings row (absent = nil).
func loadSettings(ctx context.Context, q postgres.Querier, st *state) error {
	var raw []byte
	switch err := q.QueryRow(ctx, "SELECT data FROM security_settings WHERE id=1").Scan(&raw); err {
	case nil:
		st.settings = &vaultv1.SecuritySettings{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, st.settings); err != nil {
			return fmt.Errorf("unmarshal settings: %w", err)
		}
	case postgres.ErrNoRows:
		st.settings = nil
	default:
		return fmt.Errorf("select settings: %w", err)
	}
	return nil
}

// loadRecords hydrates the envelope-encrypted field sets keyed by secret id.
func loadRecords(ctx context.Context, q postgres.Querier, st *state) error {
	rows, err := q.Query(ctx, "SELECT secret_id, record FROM secret_records")
	if err != nil {
		return fmt.Errorf("select records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var rec crypto.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return fmt.Errorf("unmarshal record %s: %w", id, err)
		}
		st.records[id] = rec
	}
	return rows.Err()
}

func replaceCollection[T proto.Message](ctx context.Context, tx postgres.Tx, table string, items []T, id func(T) string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM "+table); err != nil {
		return fmt.Errorf("clear %s: %w", table, err)
	}
	for _, it := range items {
		raw, err := protojson.Marshal(it)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", table, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (id, data) VALUES ($1,$2)", id(it), raw); err != nil {
			return fmt.Errorf("insert %s: %w", table, err)
		}
	}
	return nil
}

// Persist writes st as its own locked transaction. Prefer Server.writeTx, which
// also reloads under the lock first: a bare Persist of a stale snapshot still
// deletes rows a peer committed since that snapshot was taken.
func (p *pgStore) Persist(ctx context.Context, st *state) error {
	return p.Locked(ctx, func(ctx context.Context, tx Store) error { return tx.Persist(ctx, st) })
}

func persistState(ctx context.Context, tx postgres.Tx, st *state) error {
	for _, save := range []func(context.Context, postgres.Tx, *state) error{persistCollections, persistTargetRulesets, persistSettings, persistRecords} {
		if err := save(ctx, tx, st); err != nil {
			return err
		}
	}
	return nil
}

// persistTargetRulesets replaces the target_raci_rules table from st (see
// loadTargetRulesets for why this is a dedicated table/column rather than a
// filtered slice like raci_rules).
func persistTargetRulesets(ctx context.Context, tx postgres.Tx, st *state) error {
	if _, err := tx.Exec(ctx, "DELETE FROM target_raci_rules"); err != nil {
		return fmt.Errorf("clear target_raci_rules: %w", err)
	}
	for targetID, rules := range st.targetRulesets {
		for _, r := range rules {
			raw, err := protojson.Marshal(r)
			if err != nil {
				return fmt.Errorf("marshal target_raci_rules: %w", err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO target_raci_rules (id, target_id, data) VALUES ($1,$2,$3)", r.GetId(), targetID, raw); err != nil {
				return fmt.Errorf("insert target_raci_rules: %w", err)
			}
		}
	}
	return nil
}

// persistCollections replaces every protojson-backed entity table from st.
func persistCollections(ctx context.Context, tx postgres.Tx, st *state) error {
	typeID := func(t *vaultv1.SecretType) string { return t.GetId() }
	if err := replaceCollection(ctx, tx, "secret_types", st.types, typeID); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "folders", st.folders, func(f *vaultv1.Folder) string { return f.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "folder_rules", st.rules, func(r *vaultv1.FolderAccessRule) string { return r.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "raci_rules", st.raciRules, func(r *vaultv1.RaciRule) string { return r.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "secrets", st.secrets, func(s *vaultv1.Secret) string { return s.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "connections", st.connections, func(c *vaultv1.Connection) string { return c.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "targets", st.targets, func(t *vaultv1.Target) string { return t.GetId() }); err != nil {
		return err
	}
	if err := replaceCollection(ctx, tx, "password_policies", st.policies, func(pp *vaultv1.PasswordPolicy) string { return pp.GetId() }); err != nil {
		return err
	}
	return replaceCollection(ctx, tx, "extension_catalog", st.extCatalog, typeID)
}

// persistSettings replaces the singleton security-settings row (nil = cleared).
func persistSettings(ctx context.Context, tx postgres.Tx, st *state) error {
	if _, err := tx.Exec(ctx, "DELETE FROM security_settings"); err != nil {
		return err
	}
	if st.settings == nil {
		return nil
	}
	raw, err := protojson.Marshal(st.settings)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO security_settings (id, data) VALUES (1,$1)", raw)
	return err
}

// persistRecords replaces the envelope-encrypted field sets keyed by secret id.
func persistRecords(ctx context.Context, tx postgres.Tx, st *state) error {
	if _, err := tx.Exec(ctx, "DELETE FROM secret_records"); err != nil {
		return err
	}
	for id, rec := range st.records {
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO secret_records (secret_id, record) VALUES ($1,$2)", id, raw); err != nil {
			return err
		}
	}
	return nil
}
