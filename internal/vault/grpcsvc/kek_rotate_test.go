// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"sync"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"google.golang.org/grpc/codes"
)

// fakeKeyringAdmin is an in-memory KeyringAdmin for testing RotateKek/
// sweepRewrap without a live DB. Mirrors fakeKeyringPersist (keyring_boot_test.go)
// plus Retire, kept separate so that file's fixture stays untouched.
type fakeKeyringAdmin struct {
	mu          sync.Mutex
	rows        []keyringRow
	retiredRefs []string
}

func (f *fakeKeyringAdmin) Load(_ context.Context) ([]keyringRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]keyringRow, len(f.rows))
	copy(out, f.rows)
	return out, nil
}

func (f *fakeKeyringAdmin) Active(_ context.Context) (keyringRow, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.Active {
			return r, true, nil
		}
	}
	return keyringRow{}, false, nil
}

func (f *fakeKeyringAdmin) InsertActive(_ context.Context, ref string, wrapped []byte, rootRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rows {
		f.rows[i].Active = false
	}
	// CreatedAt mirrors the real store's created_at DEFAULT now(), so a freshly
	// rotated-to generation reads as newly-created (not due again immediately)
	// to anything computing its age — e.g. the auto-rotation scheduler.
	f.rows = append(f.rows, keyringRow{Ref: ref, WrappedKey: wrapped, RootRef: rootRef, Active: true, CreatedAt: time.Now()})
	return nil
}

func (f *fakeKeyringAdmin) Retire(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retiredRefs = append(f.retiredRefs, ref)
	return nil
}

func (f *fakeKeyringAdmin) retired(ref string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.retiredRefs {
		if r == ref {
			return true
		}
	}
	return false
}

// recordingAuditor is a minimal Auditor that captures every emitted event, so
// tests can assert an audit event's action/attributes without a live audit
// service (no such test double exists yet elsewhere in this package — other
// grpcsvc tests just pass a nil Auditor, which skips emission entirely).
type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *recordingAuditor) Emit(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *recordingAuditor) find(action string) *audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.events {
		if a.events[i].Action == action {
			return &a.events[i]
		}
	}
	return nil
}

// rotateFixture bundles the pieces a rotation test needs: the server, its
// KeyringAdmin fake, and kek-v1's raw working-key material (so a test can
// construct a record sealed directly under the pre-rotation generation, the
// only legitimate way to simulate a "leftover" record for the resumability
// case — KeyringKEK itself only ever wraps under the active ref).
type rotateFixture struct {
	s     *Server
	ks    *fakeKeyringAdmin
	rawV1 []byte
	root  crypto.KEKProvider
}

// newRotateTestServer builds a Server with a real KeyringKEK on "kek-v1"
// (root via crypto.NewStaticKEKFromSeed), an in-memory KeyringAdmin fake, and
// s.crypt wired to the same keyring — the shape SetKeyring wires up at boot.
func newRotateTestServer(t *testing.T, auditor Auditor) rotateFixture {
	t.Helper()
	root, err := crypto.NewStaticKEKFromSeed("kek-rotate-test-root")
	if err != nil {
		t.Fatalf("root KEK: %v", err)
	}
	rawV1, err := crypto.RandKey()
	if err != nil {
		t.Fatalf("RandKey: %v", err)
	}
	wrappedV1, _, err := root.WrapDEK(rawV1)
	if err != nil {
		t.Fatalf("wrap v1: %v", err)
	}
	ks := &fakeKeyringAdmin{rows: []keyringRow{
		{Ref: "kek-v1", WrappedKey: wrappedV1, RootRef: "root-v1", Active: true},
	}}
	kr, err := crypto.NewKeyringKEK(root, []crypto.WorkingKey{{Ref: "kek-v1", Key: rawV1}}, "kek-v1")
	if err != nil {
		t.Fatalf("NewKeyringKEK: %v", err)
	}

	s, err := NewWithStore(context.Background(), newMemStore(), crypto.New(kr), auditor, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	s.SetKeyring(kr, ks, root, "root-v1")
	return rotateFixture{s: s, ks: ks, rawV1: rawV1, root: root}
}

// seedRecordsOnV1 creates N secrets (each with username+password fields),
// sealed under the server's active keyring generation at call time, and
// returns their ids plus the plaintext passwords keyed by id.
func seedRecordsOnV1(t *testing.T, s *Server, n int) (ids []string, plaintext map[string]string) {
	t.Helper()
	fid := newSharedFolder(t, s)
	plaintext = make(map[string]string, n)
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	for i := 0; i < n; i++ {
		pw := "P@ss-" + string(rune('a'+i))
		created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
			Actor: carol, Name: "secret", FolderId: fid, TypeId: "type-password",
			Fields: map[string]string{"username": "svc", "password": pw},
		})
		if err != nil {
			t.Fatalf("CreateSecret: %v", err)
		}
		id := created.GetSecret().GetId()
		ids = append(ids, id)
		plaintext[id] = pw
	}
	return ids, plaintext
}

func TestRotateKek_SiteAdmin_RewrapsEveryRecordAndAudits(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s := fx.s
	ctx := context.Background()

	ids, plaintext := seedRecordsOnV1(t, s, 3)
	for _, id := range ids {
		if got := s.records[id].KeyRef; got != "kek-v1" {
			t.Fatalf("seed record %s KeyRef = %q, want kek-v1", id, got)
		}
	}

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	resp, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin})
	if err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	if resp.GetActiveRef() != "kek-v2" {
		t.Fatalf("ActiveRef = %q, want kek-v2", resp.GetActiveRef())
	}
	if int(resp.GetRewrapped()) != len(ids) {
		t.Fatalf("Rewrapped = %d, want %d", resp.GetRewrapped(), len(ids))
	}
	if got := s.keyring.ActiveRef(); got != "kek-v2" {
		t.Fatalf("keyring.ActiveRef() = %q, want kek-v2", got)
	}

	for _, id := range ids {
		rec := s.records[id]
		if rec.KeyRef != "kek-v2" {
			t.Fatalf("record %s KeyRef = %q, want kek-v2", id, rec.KeyRef)
		}
		val, err := s.crypt.Open(rec, "password")
		if err != nil {
			t.Fatalf("Open after rotation: %v", err)
		}
		if val != plaintext[id] {
			t.Fatalf("record %s plaintext = %q, want %q", id, val, plaintext[id])
		}
	}

	// kek-v1 is now unreferenced by any record → retired.
	if !fx.ks.retired("kek-v1") {
		t.Fatal("kek-v1 should have been retired once no record referenced it")
	}

	ev := auditor.find("kek.rotate")
	if ev == nil {
		t.Fatal("no kek.rotate audit event emitted")
	}
	if ev.ActorUserID != "user-admin" {
		t.Fatalf("audit actor = %q, want user-admin", ev.ActorUserID)
	}
	if ev.Attributes["active_ref"] != "kek-v2" {
		t.Fatalf("audit active_ref = %q, want kek-v2", ev.Attributes["active_ref"])
	}
	if ev.Attributes["rewrapped"] != "3" {
		t.Fatalf("audit rewrapped = %q, want 3", ev.Attributes["rewrapped"])
	}
	for _, v := range ev.Attributes {
		for _, pw := range plaintext {
			if v == pw {
				t.Fatalf("audit attribute leaked a plaintext key/value: %q", v)
			}
		}
	}
}

func TestRotateKek_NonAdmin_Denied(t *testing.T) {
	auditor := &recordingAuditor{}
	fx := newRotateTestServer(t, auditor)
	s, ks := fx.s, fx.ks
	ctx := context.Background()
	ids, _ := seedRecordsOnV1(t, s, 2)

	_, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: &vaultv1.ActorContext{UserId: "user-nobody"}})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("RotateKek(non-admin): want PermissionDenied, got %v", err)
	}
	if s.keyring.ActiveRef() != "kek-v1" {
		t.Fatal("non-admin RotateKek must not rotate the active ref")
	}
	for _, id := range ids {
		if s.records[id].KeyRef != "kek-v1" {
			t.Fatalf("non-admin RotateKek must not touch record %s", id)
		}
	}
	if len(ks.rows) != 1 {
		t.Fatalf("non-admin RotateKek must not insert a new keyring generation, got %d rows", len(ks.rows))
	}
	if auditor.find("kek.rotate") != nil {
		t.Fatal("non-admin RotateKek must not emit a kek.rotate audit event")
	}
}

// TestSweepRewrap_ResumesLeftoverRecord proves resumability: a record
// that is still sealed under a retired generation (e.g. it was created in the
// window between InsertActive and the sweep, or a prior sweep failed partway
// through) is picked up and moved onto the active ref by a later sweepRewrap
// call, without disturbing already-current records, and its plaintext
// survives the round trip.
func TestSweepRewrap_ResumesLeftoverRecord(t *testing.T) {
	fx := newRotateTestServer(t, nil)
	s := fx.s
	ctx := context.Background()
	ids, plaintext := seedRecordsOnV1(t, s, 2)

	admin := &vaultv1.ActorContext{UserId: "user-admin", IsSiteAdmin: true}
	if _, err := s.RotateKek(ctx, &vaultv1.RotateKekRequest{Actor: admin}); err != nil {
		t.Fatalf("RotateKek: %v", err)
	}
	for _, id := range ids {
		if s.records[id].KeyRef != "kek-v2" {
			t.Fatalf("record %s not rewrapped by first rotation", id)
		}
	}

	// Simulate a leftover record still on kek-v1: seal fresh ciphertext for the
	// SAME plaintext directly under kek-v1's raw material (the legitimate way
	// to produce a record on a specific non-active generation — KeyringKEK
	// itself only ever wraps under whichever ref is currently active).
	leftoverID := ids[0]
	staticV1, err := crypto.NewStaticKEK(fx.rawV1)
	if err != nil {
		t.Fatalf("NewStaticKEK(rawV1): %v", err)
	}
	envV1 := crypto.New(staticV1)
	resealed, err := envV1.Seal(map[string]string{"username": "svc", "password": plaintext[leftoverID]})
	if err != nil {
		t.Fatalf("Seal under kek-v1: %v", err)
	}
	resealed.KeyRef = "kek-v1" // StaticKEK stamps its own dev ref; override to the real one.
	s.records[leftoverID] = resealed

	other := ids[1]
	otherBefore := s.records[other]

	n, err := s.sweepRewrap(ctx)
	if err != nil {
		t.Fatalf("sweepRewrap (resume): %v", err)
	}
	if n != 1 {
		t.Fatalf("sweepRewrap (resume) rewrapped = %d, want 1", n)
	}
	if s.records[leftoverID].KeyRef != "kek-v2" {
		t.Fatalf("leftover record KeyRef = %q, want kek-v2 after resumed sweep", s.records[leftoverID].KeyRef)
	}
	val, err := s.crypt.Open(s.records[leftoverID], "password")
	if err != nil {
		t.Fatalf("Open after resumed sweep: %v", err)
	}
	if val != plaintext[leftoverID] {
		t.Fatalf("resumed record plaintext = %q, want %q", val, plaintext[leftoverID])
	}
	// The already-current record must be untouched (same ciphertext) by the
	// resumed sweep — idempotent, only the leftover was rewrapped.
	other2 := s.records[other]
	if string(other2.WrappedDEK) != string(otherBefore.WrappedDEK) {
		t.Fatal("resumed sweep must not re-touch a record already on the active ref")
	}
}
