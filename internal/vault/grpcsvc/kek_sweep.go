// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// DevStaticKeyRef is the KeyRef of the static dev key
// (sha256("sneakers-pam-dev-kek-seed-v1"), public in the source). Data sealed
// with the static dev key carries it. It stays in the runtime keyring as a
// decrypt-only key until VAULT_DISABLE_DEV_STATIC_KEK retires it, which is
// only allowed once no stored row references it (see CheckDevStaticRetired).
const DevStaticKeyRef = "dev-static-v1"

// Tables that hold a sealed crypto.Record (a wrapped DEK + its KeyRef) in a
// JSONB "record" column. These are the ONLY places a working KEK's output is
// persisted: kek_keyring holds working keys wrapped under the ROOT KEK (not a
// working key), and every other table is plaintext metadata. Any new table
// that stores a crypto.Record must be added here so the sweep, the KeyRef
// report, and the dev-static retirement check all cover it.
const (
	tableSecretRecords  = "secret_records"
	tableSecretVersions = "secret_versions"
)

var sealedRecordTables = []string{tableSecretRecords, tableSecretVersions}

// versionSweepBatch is how many secret_versions rows one sweep transaction
// re-wraps. A var so tests can shrink it to exercise multi-batch runs.
var versionSweepBatch = 200

var (
	errRotationPersist = errors.New("persist re-wrapped secret_records")
	errVersionSweep    = errors.New("re-wrap secret_versions")
)

// KeyRefReport counts sealed rows by KeyRef, per table.
type KeyRefReport map[string]map[string]int64

// Count returns how many rows across every table reference ref.
func (r KeyRefReport) Count(ref string) int64 {
	var n int64
	for _, byRef := range r {
		n += byRef[ref]
	}
	return n
}

// Refs returns every KeyRef referenced by at least one row, sorted.
func (r KeyRefReport) Refs() []string {
	seen := map[string]bool{}
	for _, byRef := range r {
		for ref, n := range byRef {
			if n > 0 {
				seen[ref] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// String renders the report as "table{ref=n,...} ..." for a single log field.
// Refs and counts only; never key material.
func (r KeyRefReport) String() string {
	var b strings.Builder
	for i, table := range sealedRecordTables {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(table)
		b.WriteByte('{')
		refs := make([]string, 0, len(r[table]))
		for ref := range r[table] {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for j, ref := range refs {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%s=%d", ref, r[table][ref])
		}
		b.WriteByte('}')
	}
	return b.String()
}

// KeyRefCounts reports, straight from Postgres (not this replica's memory),
// how many sealed rows reference each KeyRef in every table that stores a
// crypto.Record. Operators can run the same query by hand:
//
//	SELECT 'secret_records' AS t, record->>'KeyRef' AS ref, count(*) FROM secret_records GROUP BY 2
//	UNION ALL
//	SELECT 'secret_versions', record->>'KeyRef', count(*) FROM secret_versions GROUP BY 2;
func KeyRefCounts(ctx context.Context, db *postgres.DB) (KeyRefReport, error) {
	out := KeyRefReport{}
	for _, table := range sealedRecordTables {
		out[table] = map[string]int64{}
		rows, err := db.Querier().Query(ctx, `SELECT COALESCE(record->>'KeyRef', ''), count(*) FROM `+table+` GROUP BY 1`)
		if err != nil {
			return nil, fmt.Errorf("count KeyRefs in %s: %w", table, err)
		}
		for rows.Next() {
			var ref string
			var n int64
			if err := rows.Scan(&ref, &n); err != nil {
				rows.Close()
				return nil, fmt.Errorf("count KeyRefs in %s: %w", table, err)
			}
			out[table][ref] = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("count KeyRefs in %s: %w", table, err)
		}
	}
	return out, nil
}

// CheckDevStaticRetired is the VAULT_DISABLE_DEV_STATIC_KEK boot gate: it
// fails when any stored row still references DevStaticKeyRef, since dropping
// that key from the keyring would make those rows unreadable.
func CheckDevStaticRetired(r KeyRefReport) error {
	n := r.Count(DevStaticKeyRef)
	if n == 0 {
		return nil
	}
	var parts []string
	for _, table := range sealedRecordTables {
		if c := r[table][DevStaticKeyRef]; c > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", table, c))
		}
	}
	return fmt.Errorf("VAULT_DISABLE_DEV_STATIC_KEK is set but %d stored rows still reference %s (%s); run RotateKek (re-wraps records and versions), confirm the boot KeyRef report shows none, then set the flag",
		n, DevStaticKeyRef, strings.Join(parts, ", "))
}

// rewrapBatch re-wraps, in ONE transaction, up to limit secret_versions rows
// whose KeyRef is not activeRef: per row it unwraps the DEK under its current
// KeyRef and re-wraps it under the active working KEK (RewrapDEK — the field
// ciphertext is untouched, so values, fingerprints and history are
// unchanged), then UPDATEs only the record column. Rows are locked FOR UPDATE
// SKIP LOCKED so a concurrent sweep on another replica never double-handles
// a row. Any failure rolls the whole batch back: every row stays exactly as
// it was (still readable under its old ref), never half-written.
func (v *versionStore) rewrapBatch(ctx context.Context, crypt *crypto.Envelope, activeRef string, limit int) (int, error) {
	var n int
	err := v.db.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		var err error
		n, err = rewrapRows(ctx, tx, crypt, activeRef, limit)
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// rewrapRows is one rewrapBatch attempt inside its transaction.
func rewrapRows(ctx context.Context, tx postgres.Querier, crypt *crypto.Envelope, activeRef string, limit int) (int, error) {
	rows, err := tx.Query(ctx,
		`SELECT secret_id, version_no, record FROM secret_versions
		  WHERE record->>'KeyRef' IS DISTINCT FROM $1
		  ORDER BY secret_id, version_no
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED`, activeRef, limit)
	if err != nil {
		return 0, err
	}
	type row struct {
		secretID  string
		versionNo int
		raw       []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.secretID, &r.versionNo, &r.raw); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, r := range batch {
		var rec crypto.Record
		if err := json.Unmarshal(r.raw, &rec); err != nil {
			return 0, fmt.Errorf("version %s/%d: decode record: %w", r.secretID, r.versionNo, err)
		}
		rr, err := crypt.RewrapDEK(rec)
		if err != nil {
			return 0, fmt.Errorf("version %s/%d (ref %s): %w", r.secretID, r.versionNo, rec.KeyRef, err)
		}
		if rr.KeyRef != activeRef {
			return 0, fmt.Errorf("active KEK changed mid-sweep (%s -> %s); re-run the sweep", activeRef, rr.KeyRef)
		}
		raw, err := json.Marshal(rr)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE secret_versions SET record=$3 WHERE secret_id=$1 AND version_no=$2`,
			r.secretID, r.versionNo, raw); err != nil {
			return 0, fmt.Errorf("version %s/%d: update: %w", r.secretID, r.versionNo, err)
		}
	}
	return len(batch), nil
}

// sweepVersions re-wraps every secret_versions row not on the keyring's
// active ref, batch by batch, until none is left. Idempotent and resumable:
// it only ever selects rows not yet on the active ref, so re-running after a
// failure (or on an already-swept table) continues from where it stopped or
// does nothing. No-op without a version store (no-Postgres/demo path).
func (s *Server) sweepVersions(ctx context.Context) (int, error) {
	if s.vers == nil || s.keyring == nil {
		return 0, nil
	}
	total := 0
	for {
		n, err := s.vers.rewrapBatch(ctx, s.crypt, s.keyring.ActiveRef(), versionSweepBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
}

// versionRefs returns the distinct KeyRefs referenced by secret_versions
// (empty without a version store), so retirement never stamps a generation
// that history rows still need.
func (v *versionStore) versionRefs(ctx context.Context) (map[string]bool, error) {
	rows, err := v.db.Querier().Query(ctx, `SELECT DISTINCT COALESCE(record->>'KeyRef', '') FROM secret_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		out[ref] = true
	}
	return out, rows.Err()
}
