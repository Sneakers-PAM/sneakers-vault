// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func rootFromSeed(t *testing.T, seed string) KEKProvider {
	t.Helper()
	k, err := NewStaticKEKFromSeed(seed) // helper below; or NewStaticKEK(sha256 seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyringKEK_WrapsUnderActive_UnwrapsByRef(t *testing.T) {
	root := rootFromSeed(t, "root-seed")
	k1 := WorkingKey{Ref: "kek-v1", Key: mustKey(t)}
	k2 := WorkingKey{Ref: "kek-v2", Key: mustKey(t)}
	kr, err := NewKeyringKEK(root, []WorkingKey{k1, k2}, "kek-v2")
	if err != nil {
		t.Fatal(err)
	}
	dek := mustKey(t)
	wrapped, ref, err := kr.WrapDEK(dek)
	if err != nil || ref != "kek-v2" {
		t.Fatalf("wrap ref=%q err=%v", ref, err)
	}
	got, err := kr.UnwrapDEK(wrapped, "kek-v2")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap mismatch err=%v", err)
	}
}

func TestKeyringKEK_UnknownRef_FailsClosed(t *testing.T) {
	kr, _ := NewKeyringKEK(rootFromSeed(t, "r"), []WorkingKey{{Ref: "kek-v1", Key: mustKey(t)}}, "kek-v1")
	w, _, _ := kr.WrapDEK(mustKey(t))
	if _, err := kr.UnwrapDEK(w, "kek-v9"); err == nil {
		t.Fatal("expected error for unknown ref")
	}
}

func TestEnvelope_RewrapDEK_PreservesPlaintext(t *testing.T) {
	root := rootFromSeed(t, "r")
	kr, _ := NewKeyringKEK(root, []WorkingKey{{Ref: "kek-v1", Key: mustKey(t)}}, "kek-v1")
	e := New(kr)
	rec, err := e.Seal(map[string]string{"password": "s3cr3t", "user": "ada"})
	if err != nil {
		t.Fatal(err)
	}
	kr.Add(WorkingKey{Ref: "kek-v2", Key: mustKey(t)}, true)
	rr, err := e.RewrapDEK(rec)
	if err != nil {
		t.Fatal(err)
	}
	if rr.KeyRef != "kek-v2" {
		t.Fatalf("keyRef=%q want kek-v2", rr.KeyRef)
	}
	// field ciphertext bytes unchanged (only the DEK wrapping changed)
	if !bytes.Equal(rr.Fields["password"].Ciphertext, rec.Fields["password"].Ciphertext) {
		t.Fatal("field ciphertext must not change on rewrap")
	}
	pt, err := e.Open(rr, "password")
	if err != nil || pt != "s3cr3t" {
		t.Fatalf("open after rewrap: %q err=%v", pt, err)
	}
}

func TestKeyringKEK_ConcurrentAddAndWrap(t *testing.T) {
	root := rootFromSeed(t, "root-seed")
	kr, err := NewKeyringKEK(root, []WorkingKey{{Ref: "kek-v0", Key: mustKey(t)}}, "kek-v0")
	if err != nil {
		t.Fatal(err)
	}

	const rotations = 200
	const readers = 8

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Concurrent readers hammering WrapDEK/UnwrapDEK/ActiveRef while
	// rotation is in flight.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ref := kr.ActiveRef()
				wrapped, wref, err := kr.WrapDEK([]byte("some-dek-material-32-bytes-long!"))
				if err != nil {
					continue
				}
				_, _ = kr.UnwrapDEK(wrapped, wref)
				_ = ref
			}
		}()
	}

	// Rotator adding new active working keys concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rotations; i++ {
			kr.Add(WorkingKey{Ref: fmt.Sprintf("kek-v%d", i+1), Key: mustKey(t)}, true)
		}
		close(stop)
	}()

	wg.Wait()
}

func TestKeyringKEK_Has(t *testing.T) {
	kr, err := NewKeyringKEK(rootFromSeed(t, "r"), []WorkingKey{{Ref: "kek-v1", Key: mustKey(t)}}, "kek-v1")
	if err != nil {
		t.Fatal(err)
	}
	if !kr.Has("kek-v1") {
		t.Fatal("Has(kek-v1) = false, want true")
	}
	if kr.Has("kek-v2") {
		t.Fatal("Has(kek-v2) = true, want false (not yet added)")
	}
	kr.Add(WorkingKey{Ref: "kek-v2", Key: mustKey(t)}, false)
	if !kr.Has("kek-v2") {
		t.Fatal("Has(kek-v2) = false after Add, want true")
	}
}

func TestKeyringKEK_SetActive(t *testing.T) {
	kr, err := NewKeyringKEK(rootFromSeed(t, "r"), []WorkingKey{{Ref: "kek-v1", Key: mustKey(t)}}, "kek-v1")
	if err != nil {
		t.Fatal(err)
	}
	kr.Add(WorkingKey{Ref: "kek-v2", Key: mustKey(t)}, false)
	if got := kr.ActiveRef(); got != "kek-v1" {
		t.Fatalf("ActiveRef before SetActive = %q, want kek-v1", got)
	}
	if err := kr.SetActive("kek-v2"); err != nil {
		t.Fatalf("SetActive(kek-v2): %v", err)
	}
	if got := kr.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef after SetActive = %q, want kek-v2", got)
	}
	wrapped, ref, err := kr.WrapDEK(mustKey(t))
	if err != nil || ref != "kek-v2" {
		t.Fatalf("WrapDEK after SetActive: ref=%q err=%v", ref, err)
	}
	if _, err := kr.UnwrapDEK(wrapped, "kek-v2"); err != nil {
		t.Fatalf("UnwrapDEK after SetActive: %v", err)
	}
}

func TestKeyringKEK_SetActive_UnknownRef_FailsClosedAndLeavesActiveUnchanged(t *testing.T) {
	kr, err := NewKeyringKEK(rootFromSeed(t, "r"), []WorkingKey{{Ref: "kek-v1", Key: mustKey(t)}}, "kek-v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.SetActive("kek-v9"); err == nil {
		t.Fatal("SetActive(unknown ref) = nil error, want error")
	}
	if got := kr.ActiveRef(); got != "kek-v1" {
		t.Fatalf("ActiveRef after failed SetActive = %q, want unchanged kek-v1", got)
	}
}

// TestKeyringKEK_ConcurrentHasSetActiveAddAndWrap extends the existing
// concurrent Add/Wrap/Unwrap race coverage to Has and SetActive, so -race
// exercises every KeyringKEK method sharing the RWMutex together.
func TestKeyringKEK_ConcurrentHasSetActiveAddAndWrap(t *testing.T) {
	root := rootFromSeed(t, "root-seed")
	kr, err := NewKeyringKEK(root, []WorkingKey{{Ref: "kek-v0", Key: mustKey(t)}}, "kek-v0")
	if err != nil {
		t.Fatal(err)
	}

	const rotations = 100
	const readers = 8

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ref := kr.ActiveRef()
				_ = kr.Has(ref)
				wrapped, wref, err := kr.WrapDEK([]byte("some-dek-material-32-bytes-long!"))
				if err != nil {
					continue
				}
				_, _ = kr.UnwrapDEK(wrapped, wref)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rotations; i++ {
			ref := fmt.Sprintf("kek-v%d", i+1)
			kr.Add(WorkingKey{Ref: ref, Key: mustKey(t)}, false)
			_ = kr.SetActive(ref)
		}
		close(stop)
	}()

	wg.Wait()
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	b, err := randBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
