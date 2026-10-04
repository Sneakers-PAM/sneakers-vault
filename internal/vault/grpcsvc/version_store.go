// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// VersionMeta is one ledger row's non-secret metadata plus the field keys
// present in that version's record, and the subset of those keys whose value
// changed relative to the immediately-prior version.
//
// FieldKeys is read straight from the sealed field set's map keys (no plaintext
// materialised). ChangedFieldKeys is derived by comparing per-field value HASHES
// between adjacent versions (see List) — the plaintext is opened only to hash it
// and is never returned, so history still exposes no values.
type VersionMeta struct {
	VersionNo int
	CreatedBy string
	CreatedAt time.Time
	Active    bool
	FieldKeys []string
	// ChangedFieldKeys is the sorted subset of FieldKeys (plus any keys removed
	// since the prior version) whose value differs from the immediately-prior
	// version by version_no. The oldest version reports all its keys. Empty means
	// this version changed no field values (e.g. a re-save of identical values).
	ChangedFieldKeys []string
}

// versionStore is the append-only secret version ledger (secret_versions). It
// retains every sealed crypto.Record so a rotation can stage a new version,
// prove it, then commit — never destroying the old value until the new one is
// proven, and keeping the prior version afterwards for rollback/compensation.
//
// This is NOT the hot path: the rest of the vault reads the single active record
// from secret_records. secret_versions is history/rollback and rotation staging.
// The crypto.Record is stored as JSONB (encoding/json round-trips its []byte and
// map[string]Sealed fields as base64/objects — the on-wire crypto is unchanged,
// only its storage envelope differs).
type versionStore struct{ db *postgres.DB }

func newVersionStore(db *postgres.DB) *versionStore { return &versionStore{db: db} }

// AppendActive writes the next version_no as the active record, demoting any
// prior active row, in one transaction. Returns the new version_no.
func (v *versionStore) AppendActive(ctx context.Context, secretID string, rec crypto.Record, by string) (int, error) {
	return v.append(ctx, secretID, rec, by, true, false)
}

// Stage writes the next version_no as a staged (active=false, staged=true)
// version, leaving the current active row untouched. Returns its version_no.
func (v *versionStore) Stage(ctx context.Context, secretID string, rec crypto.Record, by string) (int, error) {
	return v.append(ctx, secretID, rec, by, false, true)
}

// append inserts the next version_no with the given active/staged flags. When
// active it first demotes the prior active row (single-active invariant), all in
// one transaction so a reader never sees zero or two active rows.
func (v *versionStore) append(ctx context.Context, secretID string, rec crypto.Record, by string, active, staged bool) (int, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	var next int
	err = v.db.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		if active {
			if _, err := tx.Exec(ctx,
				`UPDATE secret_versions SET active=false WHERE secret_id=$1 AND active`, secretID); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version_no),0)+1 FROM secret_versions WHERE secret_id=$1`, secretID).Scan(&next); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_versions (secret_id, version_no, record, active, staged, created_by)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			secretID, next, raw, active, staged, by)
		return err
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// Commit flips the staged version to active and demotes the previously-active
// version, in one transaction. Idempotent by version_no: re-committing an
// already-active version is a no-op success.
func (v *versionStore) Commit(ctx context.Context, secretID string, versionNo int) error {
	return v.db.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		if _, err := tx.Exec(ctx,
			`UPDATE secret_versions SET active=false WHERE secret_id=$1 AND active AND version_no<>$2`,
			secretID, versionNo); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE secret_versions SET active=true, staged=false WHERE secret_id=$1 AND version_no=$2`,
			secretID, versionNo)
		return err
	})
}

// ReplaceStaged atomically soft-discards any prior staged (non-active) version
// and inserts rec as the new staged version, in one transaction.
// RevealForRotation uses this instead of a separate DiscardStaged+Stage pair so
// a retried reveal (or two concurrent ones) can never leave more than one staged
// row — the clear and insert either both land or neither does, and the
// secret_versions_one_staged unique index backs the single-staged invariant
// even under a race.
//
// The prior staged row is soft-discarded (staged=false, never deleted), so
// MAX(version_no) never regresses and the next version_no is strictly greater
// and never reused. This is what makes the report→version binding safe: a second
// reveal that supersedes the first always yields a higher number, so a stale
// report bound to the freed number can never match the new row and commit the
// wrong credential (a hard delete would re-hand out the just-freed number and
// defeat the binding — the stale report would then commit the newer credential
// and desync vault ahead of the target). The clear runs BEFORE INSERT so the
// unique-staged index sees a single staged=true row.
func (v *versionStore) ReplaceStaged(ctx context.Context, secretID string, rec crypto.Record, by string) (int, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	var next int
	err = v.db.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		if _, err := tx.Exec(ctx,
			`UPDATE secret_versions SET staged=false WHERE secret_id=$1 AND staged`, secretID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version_no),0)+1 FROM secret_versions WHERE secret_id=$1`, secretID).Scan(&next); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO secret_versions (secret_id, version_no, record, active, staged, created_by)
			 VALUES ($1,$2,$3,false,true,$4)`,
			secretID, next, raw, by)
		return err
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// DiscardStaged soft-discards any staged (non-active) rows for the secret by
// clearing the staged flag (never deleting), used to compensate a failed change
// where the new version must be thrown away and the old active version kept.
// Soft-clearing keeps MAX(version_no) monotonic so a freed number is never
// re-handed to a later reveal. Retained rows (staged=false, active=false) read
// as "discarded".
func (v *versionStore) DiscardStaged(ctx context.Context, secretID string) error {
	_, err := v.db.Querier().Exec(ctx,
		`UPDATE secret_versions SET staged=false WHERE secret_id=$1 AND staged`, secretID)
	return err
}

// VersionStatus reports the active/staged flags of a specific (secret_id,
// version_no) row and whether it exists at all. ReportRotation uses it to bind a
// report to the exact version a worker revealed and keys its branches off the
// (staged, active) pair only: staged=true means awaiting commit, active=true
// means already committed, and neither-flag-set means the version is inert —
// either truly absent (exists=false, never staged) or soft-discarded
// (exists=true, staged=false, active=false). Both inert cases must be treated
// identically by callers. A single query — no row means exists=false with all
// flags false.
func (v *versionStore) VersionStatus(ctx context.Context, secretID string, versionNo int) (active bool, staged bool, exists bool, err error) {
	err = v.db.Querier().QueryRow(ctx,
		`SELECT active, staged FROM secret_versions WHERE secret_id=$1 AND version_no=$2`,
		secretID, versionNo).Scan(&active, &staged)
	if errors.Is(err, postgres.ErrNoRows) {
		return false, false, false, nil
	}
	if err != nil {
		return false, false, false, err
	}
	return active, staged, true, nil
}

// DiscardVersion soft-discards exactly one version row — clearing its staged
// flag rather than deleting it — and only while it is still staged (never an
// active one). ReportRotation uses it to throw away the precise
// revealed-but-unapplied version on a FAILED/SKIPPED report without touching the
// active credential. Retaining the row (staged=false, active=false) keeps
// MAX(version_no) monotonic so the number is never reused.
//
// Returns rows-affected: 1 when this call won the discard (it cleared the staged
// flag), 0 when the row was already un-staged (a duplicate/racing report). This
// lets ReportRotation make the consecutive-failure bump atomic — only the caller
// that observes 1 bumps; the loser observes 0 and returns an idempotent ok.
func (v *versionStore) DiscardVersion(ctx context.Context, secretID string, versionNo int) (int64, error) {
	tag, err := v.db.Querier().Exec(ctx,
		`UPDATE secret_versions SET staged=false WHERE secret_id=$1 AND version_no=$2 AND staged`,
		secretID, versionNo)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ActiveRecord loads the active version's crypto.Record (used for
// rollback/verification, not the hot path). ok=false when the secret has no
// active version.
func (v *versionStore) ActiveRecord(ctx context.Context, secretID string) (crypto.Record, bool, error) {
	var raw []byte
	err := v.db.Querier().QueryRow(ctx,
		`SELECT record FROM secret_versions WHERE secret_id=$1 AND active`, secretID).Scan(&raw)
	if errors.Is(err, postgres.ErrNoRows) {
		return crypto.Record{}, false, nil
	}
	if err != nil {
		return crypto.Record{}, false, err
	}
	var rec crypto.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return crypto.Record{}, false, err
	}
	return rec, true, nil
}

// List returns every version for the secret, newest version_no first, with each
// version's non-secret metadata, the sorted set of field keys present, and the
// subset of keys whose value changed vs the immediately-prior version.
//
// FieldKeys come from the sealed record's map keys — no decryption needed.
// ChangedFieldKeys is computed by opening each field ONLY to sha256 its value
// (via crypt), then diffing those hashes against the prior version's; the
// plaintext never leaves this function, so listing still exposes no values. The
// oldest version's changed set is all its keys, and a field added or removed
// between versions counts as changed. When crypt is nil (a store built without an
// envelope) the change set falls back to the full key set.
func (v *versionStore) List(ctx context.Context, secretID string, crypt *crypto.Envelope) ([]VersionMeta, error) {
	rows, err := v.db.Querier().Query(ctx,
		`SELECT version_no, created_by, created_at, active, record
		   FROM secret_versions WHERE secret_id=$1 ORDER BY version_no DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionMeta
	// hashes[i] is the per-field value fingerprint for out[i]; index-aligned so
	// out[i]'s prior version (next-lower version_no) is out[i+1] / hashes[i+1].
	var hashes []map[string]string
	for rows.Next() {
		var m VersionMeta
		var raw []byte
		if err := rows.Scan(&m.VersionNo, &m.CreatedBy, &m.CreatedAt, &m.Active, &raw); err != nil {
			return nil, err
		}
		var rec crypto.Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(rec.Fields))
		for k := range rec.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		m.FieldKeys = keys
		fp, err := fieldFingerprints(crypt, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		hashes = append(hashes, fp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Rows are newest-first, so out[i]'s immediately-prior version is out[i+1];
	// the last (oldest) version has no prior, so all its keys read as changed.
	for i := range out {
		if crypt == nil {
			// No envelope to hash values with: report the full key set.
			out[i].ChangedFieldKeys = append([]string(nil), out[i].FieldKeys...)
			continue
		}
		var prior map[string]string
		if i+1 < len(out) {
			prior = hashes[i+1]
		}
		out[i].ChangedFieldKeys = changedFieldKeys(hashes[i], prior)
	}
	return out, nil
}

// fieldFingerprints opens every field of rec ONLY to sha256 its value, returning
// key->hex-digest. The plaintext is discarded immediately, never returned. When
// crypt is nil it returns nil, which changedFieldKeys treats as "unknown" and so
// reports the full key set as changed.
func fieldFingerprints(crypt *crypto.Envelope, rec crypto.Record) (map[string]string, error) {
	if crypt == nil {
		return nil, nil
	}
	out := make(map[string]string, len(rec.Fields))
	for k := range rec.Fields {
		val, err := crypt.Open(rec, k)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(val))
		out[k] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

// emptyFingerprint is the fingerprint of an empty value.
var emptyFingerprint = func() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}()

// changedFieldKeys returns the sorted keys whose fingerprint differs between cur
// and prior: added keys, removed keys, and keys whose value hash changed. A key
// missing on one side compares as an empty value, so adding or dropping an
// empty field is not a change. A nil prior (the oldest version) reports every
// current key as changed.
func changedFieldKeys(cur, prior map[string]string) []string {
	changed := make(map[string]struct{})
	if prior == nil {
		for k := range cur {
			changed[k] = struct{}{}
		}
	} else {
		fingerprintOf := func(m map[string]string, k string) string {
			if h, ok := m[k]; ok {
				return h
			}
			return emptyFingerprint
		}
		for _, m := range []map[string]string{cur, prior} {
			for k := range m {
				if fingerprintOf(cur, k) != fingerprintOf(prior, k) {
					changed[k] = struct{}{}
				}
			}
		}
	}
	keys := make([]string, 0, len(changed))
	for k := range changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// LoadVersion returns a specific version's sealed crypto.Record (ok=false when
// no such version exists). RevealSecretVersionField opens exactly one field from
// it, so only the requested historical value is ever materialised.
func (v *versionStore) LoadVersion(ctx context.Context, secretID string, versionNo int) (crypto.Record, bool, error) {
	var raw []byte
	err := v.db.Querier().QueryRow(ctx,
		`SELECT record FROM secret_versions WHERE secret_id=$1 AND version_no=$2`,
		secretID, versionNo).Scan(&raw)
	if errors.Is(err, postgres.ErrNoRows) {
		return crypto.Record{}, false, nil
	}
	if err != nil {
		return crypto.Record{}, false, err
	}
	var rec crypto.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return crypto.Record{}, false, err
	}
	return rec, true, nil
}

// StagedVersion returns the version_no of the current staged row for the secret
// (ok=false when none is staged). ReportRotation uses it to know which version
// to Commit.
func (v *versionStore) StagedVersion(ctx context.Context, secretID string) (int, bool, error) {
	var n int
	err := v.db.Querier().QueryRow(ctx,
		`SELECT version_no FROM secret_versions WHERE secret_id=$1 AND staged AND NOT active
		 ORDER BY version_no DESC LIMIT 1`, secretID).Scan(&n)
	if errors.Is(err, postgres.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// DeleteAll drops every version of the secret. A hard delete is meant to be
// unrecoverable, and each row holds a sealed copy of the value.
func (v *versionStore) DeleteAll(ctx context.Context, secretID string) error {
	_, err := v.db.Querier().Exec(ctx, `DELETE FROM secret_versions WHERE secret_id=$1`, secretID)
	return err
}
