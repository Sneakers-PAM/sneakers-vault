// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc/codes"
)

// sweepFixture is a rotate test server whose version ledger is real Postgres,
// seeded with n secrets x 2 versions (create + update) on kek-v1.
func sweepFixture(t *testing.T, auditor Auditor, n int) (rotateFixture, map[string]map[int]string) {
	t.Helper()
	fx := newRotateTestServer(t, auditor)
	fx.s.vers = newVersionStore(verTestPool(t))
	ids, pw := seedRecordsOnV1(t, fx.s, n)
	want := map[string]map[int]string{}
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	for _, id := range ids {
		next := pw[id] + "-v2"
		if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
			Actor: carol, Id: id, Fields: map[string]string{"username": "svc", "password": next},
		}); err != nil {
			t.Fatalf("UpdateSecret: %v", err)
		}
		want[id] = map[int]string{1: pw[id], 2: next}
	}
	return fx, want
}

func versionRefCounts(t *testing.T, v *versionStore) map[string]int {
	t.Helper()
	rows, err := v.db.Querier().Query(context.Background(), `SELECT record->>'KeyRef', count(*) FROM secret_versions GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var ref string
		var n int
		if err := rows.Scan(&ref, &n); err != nil {
			t.Fatal(err)
		}
		out[ref] = n
	}
	return out
}

func assertVersionsReadable(t *testing.T, s *Server, want map[string]map[int]string) {
	t.Helper()
	for id, byVer := range want {
		for v, pw := range byVer {
			rec, ok, err := s.vers.LoadVersion(context.Background(), id, v)
			if err != nil || !ok {
				t.Fatalf("LoadVersion %s/%d: ok=%v err=%v", id, v, ok, err)
			}
			got, err := s.crypt.Open(rec, "password")
			if err != nil || got != pw {
				t.Fatalf("version %s/%d (ref %s): got %q err=%v, want %q", id, v, rec.KeyRef, got, err, pw)
			}
		}
	}
}

func withSweepBatch(t *testing.T, n int) {
	t.Helper()
	old := versionSweepBatch
	versionSweepBatch = n
	t.Cleanup(func() { versionSweepBatch = old })
}

// RotateKek re-wraps every secret_versions row (not just secret_records), in
// several batches, without touching field ciphertext; a second sweep is a no-op.
func TestRotateKek_RewrapsVersionsInBatches(t *testing.T) {
	withSweepBatch(t, 2)
	auditor := &recordingAuditor{}
	fx, want := sweepFixture(t, auditor, 3)
	s := fx.s
	ctx := context.Background()
	if got := versionRefCounts(t, s.vers); got["kek-v1"] != 6 {
		t.Fatalf("seed versions = %v, want 6 on kek-v1", got)
	}
	var id0 string
	for id := range want {
		id0 = id
		break
	}
	before, _, _ := s.vers.LoadVersion(ctx, id0, 1)

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	resp, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin})
	if err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	if resp.GetRewrapped() != 9 {
		t.Fatalf("Rewrapped = %d, want 9 (3 records + 6 versions)", resp.GetRewrapped())
	}
	if got := versionRefCounts(t, s.vers); got["kek-v2"] != 6 || len(got) != 1 {
		t.Fatalf("versions after rotate = %v, want all 6 on kek-v2", got)
	}
	after, _, _ := s.vers.LoadVersion(ctx, id0, 1)
	if string(after.WrappedDEK) == string(before.WrappedDEK) {
		t.Fatal("wrapped DEK unchanged after re-wrap")
	}
	b1, _ := json.Marshal(before.Fields)
	a1, _ := json.Marshal(after.Fields)
	if string(a1) != string(b1) {
		t.Fatal("re-wrap must not touch field ciphertext")
	}
	assertVersionsReadable(t, s, want)

	ev := auditor.find("kek.rotate")
	if ev == nil || ev.Attributes["rewrapped_versions"] != "6" || ev.Attributes["rewrapped_records"] != "3" || ev.Attributes["outcome"] != "ok" {
		t.Fatalf("audit = %+v, want 3 records + 6 versions, outcome ok", ev)
	}
	if !fx.ks.retired("kek-v1") {
		t.Fatal("kek-v1 should be retired once neither records nor versions reference it")
	}

	n, err := s.sweepVersions(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second sweep = %d, %v; want 0, nil (idempotent)", n, err)
	}
}

// A row the keyring cannot unwrap stops the sweep with an error (outcome
// version_sweep_failed), never a silent success. Batches before it are
// committed, its own batch rolls back, every good row stays readable, and a
// re-run after the bad row is dealt with finishes the job.
func TestRotateKek_VersionSweepFailure_IsReportedAndResumable(t *testing.T) {
	withSweepBatch(t, 2)
	auditor := &recordingAuditor{}
	fx, want := sweepFixture(t, auditor, 3)
	s := fx.s
	ctx := context.Background()

	bogus := crypto.Record{WrappedDEK: []byte("not-a-real-wrapped-dek-000000000"), KeyRef: "kek-v0-unknown", Fields: map[string]crypto.Sealed{}}
	raw, _ := json.Marshal(bogus)
	if _, err := s.vers.db.Querier().Exec(ctx,
		`INSERT INTO secret_versions (secret_id, version_no, record) VALUES ('zzz-bogus', 1, $1)`, raw); err != nil {
		t.Fatal(err)
	}

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	_, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin})
	if code(err) != codes.Internal {
		t.Fatalf("RotateKek with an unreadable version: want Internal, got %v", err)
	}
	if ev := auditor.find("kek.rotate"); ev == nil || ev.Attributes["outcome"] != "version_sweep_failed" {
		t.Fatalf("audit = %+v, want outcome version_sweep_failed", ev)
	}
	counts := versionRefCounts(t, s.vers)
	if counts["kek-v2"] != 6 || counts["kek-v0-unknown"] != 1 {
		t.Fatalf("after failed sweep = %v, want 6 good rows on kek-v2 and the bogus row untouched", counts)
	}
	assertVersionsReadable(t, s, want)

	if _, err := s.vers.db.Querier().Exec(ctx, `DELETE FROM secret_versions WHERE secret_id='zzz-bogus'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("RotateKek re-run: %v", err)
	}
	if got := versionRefCounts(t, s.vers); got["kek-v3"] != 6 || len(got) != 1 {
		t.Fatalf("after re-run = %v, want all 6 on kek-v3", got)
	}
	assertVersionsReadable(t, s, want)
}

// A failing row in the FIRST batch rolls that whole batch back: no row in it
// is left half-written.
func TestVersionRewrapBatch_RollsBackWholeBatchOnError(t *testing.T) {
	withSweepBatch(t, 10)
	fx, want := sweepFixture(t, nil, 2)
	s := fx.s
	ctx := context.Background()
	bogus, _ := json.Marshal(crypto.Record{WrappedDEK: []byte("x"), KeyRef: "kek-v0-unknown"})
	if _, err := s.vers.db.Querier().Exec(ctx, `INSERT INTO secret_versions (secret_id, version_no, record) VALUES ('zzz', 1, $1)`, bogus); err != nil {
		t.Fatal(err)
	}
	fx.s.keyring.Add(crypto.WorkingKey{Ref: "kek-v2", Key: bootMustKey(t)}, true)
	if _, err := s.sweepVersions(ctx); err == nil {
		t.Fatal("sweepVersions: want error for an unreadable row")
	}
	if got := versionRefCounts(t, s.vers); got["kek-v1"] != 4 {
		t.Fatalf("after rolled-back batch = %v, want all 4 good rows still on kek-v1", got)
	}
	assertVersionsReadable(t, s, want)
}

func TestKeyRefReport_CheckAndString(t *testing.T) {
	r := KeyRefReport{
		tableSecretRecords:  {"kek-v2": 3},
		tableSecretVersions: {"kek-v2": 5, DevStaticKeyRef: 2},
	}
	if err := CheckDevStaticRetired(r); err == nil {
		t.Fatal("want refusal with dev-static rows present")
	}
	if got, want := r.String(), "secret_records{kek-v2=3} secret_versions{dev-static-v1=2,kek-v2=5}"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	if fmt.Sprint(r.Refs()) != "[dev-static-v1 kek-v2]" {
		t.Fatalf("Refs = %v", r.Refs())
	}
	delete(r[tableSecretVersions], DevStaticKeyRef)
	if err := CheckDevStaticRetired(r); err != nil {
		t.Fatalf("no dev-static rows: %v", err)
	}
}
