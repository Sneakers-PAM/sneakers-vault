// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// memRewrapStore is an in-memory kek_keyring. A move batch applies all or
// none, like the database transaction it stands for.
type memRewrapStore struct {
	rows     []keyringRow
	failMove error
	moves    int // MoveRoot calls that applied
}

func (m *memRewrapStore) Load(context.Context) ([]keyringRow, error) {
	return append([]keyringRow(nil), m.rows...), nil
}

func (m *memRewrapStore) MoveRoot(_ context.Context, moves []rootMove) error {
	if m.failMove != nil {
		return m.failMove
	}
	for _, mv := range moves {
		for i := range m.rows {
			if m.rows[i].Ref == mv.Ref && m.rows[i].RootRef == mv.FromRoot {
				m.rows[i].WrappedKey, m.rows[i].RootRef = mv.WrappedKey, mv.ToRoot
			}
		}
	}
	m.moves++
	return nil
}

type rewrapFixture struct {
	cur, prev *crypto.StaticKEK
	rk        *crypto.RootKEKs
	store     *memRewrapStore
	keys      map[string][]byte
	reports   []rewrapReport
}

type rewrapReport struct {
	state   crypto.RotationState
	pending int
}

const (
	curRef  = "root-cur"
	prevRef = "root-v1"
)

// newRewrapFixture holds n working keys wrapped under the previous root.
func newRewrapFixture(t *testing.T, n int) *rewrapFixture {
	t.Helper()
	cur, _ := crypto.NewStaticKEKFromSeed("current root")
	prev, _ := crypto.NewStaticKEKFromSeed("previous root")
	f := &rewrapFixture{cur: cur, prev: prev, rk: crypto.NewRootKEKs(cur, curRef, prev), store: &memRewrapStore{}, keys: map[string][]byte{}}
	for i := 1; i <= n; i++ {
		ref := "kek-v" + string(rune('0'+i))
		raw, err := crypto.RandKey()
		if err != nil {
			t.Fatal(err)
		}
		w, _, err := prev.WrapDEK(raw)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[ref] = raw
		f.store.rows = append(f.store.rows, keyringRow{Ref: ref, WrappedKey: w, RootRef: prevRef, Active: i == n})
	}
	return f
}

func (f *rewrapFixture) run(t *testing.T) (crypto.RotationState, int) {
	t.Helper()
	f.reports = nil
	st, pending := RewrapKeyring(context.Background(), f.store, f.rk, func(s crypto.RotationState, p int) {
		f.reports = append(f.reports, rewrapReport{s, p})
	})
	return st, pending
}

// everyKeyReadsBackUnderTheCurrentRootAlone checks the stored ring against the
// original working keys.
func (f *rewrapFixture) everyKeyReadsBackUnderTheCurrentRootAlone(t *testing.T) {
	t.Helper()
	for _, r := range f.store.rows {
		if r.RootRef != curRef {
			t.Fatalf("%s is on %s, want %s", r.Ref, r.RootRef, curRef)
		}
		got, err := f.cur.UnwrapDEK(r.WrappedKey, r.RootRef)
		if err != nil || !bytes.Equal(got, f.keys[r.Ref]) {
			t.Fatalf("%s does not read back under the current root: %v", r.Ref, err)
		}
	}
}

func TestRewrap_MovesEveryWorkingKeyAndVerifies(t *testing.T) {
	f := newRewrapFixture(t, 3)
	st, pending := f.run(t)
	if st != crypto.RotationVerified || pending != 0 {
		t.Fatalf("state=%s pending=%d, want verified, 0", st, pending)
	}
	f.everyKeyReadsBackUnderTheCurrentRootAlone(t)
	if len(f.reports) == 0 || f.reports[0] != (rewrapReport{crypto.RotationInProgress, 3}) {
		t.Fatalf("reports=%v, want in-progress with 3 pending first", f.reports)
	}
	if last := f.reports[len(f.reports)-1]; last != (rewrapReport{crypto.RotationVerified, 0}) {
		t.Fatalf("last report %v, want verified, 0", last)
	}
}

func TestRewrap_NoPreviousRootIsNone(t *testing.T) {
	f := newRewrapFixture(t, 2)
	f.rk = crypto.NewRootKEKs(f.cur, curRef, nil)
	st, pending := f.run(t)
	if st != crypto.RotationNone || pending != 0 || f.store.moves != 0 {
		t.Fatalf("state=%s pending=%d moves=%d, want none, 0, 0", st, pending, f.store.moves)
	}
}

func TestRewrap_RestartIsIdempotent(t *testing.T) {
	f := newRewrapFixture(t, 3)
	f.run(t)
	before := append([]keyringRow(nil), f.store.rows...)
	moves := f.store.moves
	st, pending := f.run(t)
	if st != crypto.RotationVerified || pending != 0 {
		t.Fatalf("second start: state=%s pending=%d, want verified, 0", st, pending)
	}
	if f.store.moves != moves {
		t.Fatal("a start with every key already on the current root wrote again")
	}
	for i := range before {
		if !bytes.Equal(before[i].WrappedKey, f.store.rows[i].WrappedKey) {
			t.Fatalf("%s changed on the second start", before[i].Ref)
		}
	}
}

func TestRewrap_FinishesARingThatWasPartlyMoved(t *testing.T) {
	f := newRewrapFixture(t, 3)
	// Two keys are already on the current root, as after an earlier run.
	for i := 0; i < 2; i++ {
		w, ref, _ := f.rk.WrapDEK(f.keys[f.store.rows[i].Ref])
		f.store.rows[i].WrappedKey, f.store.rows[i].RootRef = w, ref
	}
	st, pending := f.run(t)
	if st != crypto.RotationVerified || pending != 0 {
		t.Fatalf("state=%s pending=%d, want verified, 0", st, pending)
	}
	if f.reports[0] != (rewrapReport{crypto.RotationInProgress, 1}) {
		t.Fatalf("first report %v, want in-progress with only the 1 key still on the previous root", f.reports[0])
	}
	f.everyKeyReadsBackUnderTheCurrentRootAlone(t)
}

func TestRewrap_AFailedMoveLeavesTheOldRingIntact(t *testing.T) {
	f := newRewrapFixture(t, 3)
	before := append([]keyringRow(nil), f.store.rows...)
	f.store.failMove = errors.New("connection lost")
	st, pending := f.run(t)
	if st != crypto.RotationFailed || pending != 3 {
		t.Fatalf("state=%s pending=%d, want failed, 3", st, pending)
	}
	for i := range before {
		if !bytes.Equal(before[i].WrappedKey, f.store.rows[i].WrappedKey) || before[i].RootRef != f.store.rows[i].RootRef {
			t.Fatalf("%s changed although the move failed", before[i].Ref)
		}
		if _, err := f.rk.UnwrapDEK(f.store.rows[i].WrappedKey, f.store.rows[i].RootRef); err != nil {
			t.Fatalf("the old ring no longer opens: %v", err)
		}
	}
	// The next start finishes the job.
	f.store.failMove = nil
	if st, pending := f.run(t); st != crypto.RotationVerified || pending != 0 {
		t.Fatalf("retry: state=%s pending=%d, want verified, 0", st, pending)
	}
}

func TestRewrap_AKeyThatCannotBeOpenedChangesNothing(t *testing.T) {
	f := newRewrapFixture(t, 3)
	f.store.rows[1].WrappedKey = []byte("not a wrapped key at all, just bytes of enough length....")
	before := append([]keyringRow(nil), f.store.rows...)
	st, pending := f.run(t)
	if st != crypto.RotationFailed || pending != 3 || f.store.moves != 0 {
		t.Fatalf("state=%s pending=%d moves=%d, want failed, 3, 0", st, pending, f.store.moves)
	}
	for i := range before {
		if !bytes.Equal(before[i].WrappedKey, f.store.rows[i].WrappedKey) {
			t.Fatalf("%s changed", before[i].Ref)
		}
	}
}

type failingLoad struct{ memRewrapStore }

func (failingLoad) Load(context.Context) ([]keyringRow, error) { return nil, errors.New("down") }

func TestRewrap_AnUnreadableRingIsFailedWithAtLeastOnePending(t *testing.T) {
	f := newRewrapFixture(t, 2)
	st, pending := RewrapKeyring(context.Background(), &failingLoad{}, f.rk, func(crypto.RotationState, int) {})
	if st != crypto.RotationFailed || pending < 1 {
		t.Fatalf("state=%s pending=%d, want failed with at least 1 so a zero never reads as nothing left", st, pending)
	}
}
