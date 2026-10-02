// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import "testing"

func newEnvelope(t *testing.T) *Envelope {
	t.Helper()
	kek, err := NewRandomKEK()
	if err != nil {
		t.Fatalf("NewRandomKEK: %v", err)
	}
	return New(kek)
}

func TestSealOpenRoundTrip(t *testing.T) {
	e := newEnvelope(t)
	in := map[string]string{"password": "Xk7$mVq2!pLd9", "username": "svc_deploy"}
	rec, err := e.Seal(in)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for k, want := range in {
		got, err := e.Open(rec, k)
		if err != nil {
			t.Fatalf("Open(%q): %v", k, err)
		}
		if got != want {
			t.Fatalf("Open(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestSealStoresNoPlaintext(t *testing.T) {
	e := newEnvelope(t)
	rec, err := e.Seal(map[string]string{"password": "supersecret"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if string(rec.Fields["password"].Ciphertext) == "supersecret" {
		t.Fatal("ciphertext equals plaintext")
	}
	for _, b := range [][]byte{rec.WrappedDEK, rec.Fields["password"].Ciphertext} {
		if string(b) == "supersecret" {
			t.Fatal("plaintext found in record")
		}
	}
}

func TestOpenUnknownField(t *testing.T) {
	e := newEnvelope(t)
	rec, _ := e.Seal(map[string]string{"a": "1"})
	if _, err := e.Open(rec, "missing"); err != ErrFieldNotFound {
		t.Fatalf("want ErrFieldNotFound, got %v", err)
	}
}

func TestTamperedCiphertextFailsAuth(t *testing.T) {
	e := newEnvelope(t)
	rec, _ := e.Seal(map[string]string{"a": "value"})
	rec.Fields["a"].Ciphertext[0] ^= 0xFF // flip a bit
	if _, err := e.Open(rec, "a"); err == nil {
		t.Fatal("expected GCM auth failure on tampered ciphertext")
	}
}

func TestWrongKEKCannotOpen(t *testing.T) {
	e1 := newEnvelope(t)
	rec, _ := e1.Seal(map[string]string{"a": "value"})
	e2 := newEnvelope(t) // different random KEK
	if _, err := e2.Open(rec, "a"); err == nil {
		t.Fatal("expected failure opening with a different KEK")
	}
}

func TestOpenAll(t *testing.T) {
	e := newEnvelope(t)
	in := map[string]string{"a": "1", "b": "2", "c": "3"}
	rec, _ := e.Seal(in)
	got, err := e.OpenAll(rec)
	if err != nil {
		t.Fatalf("OpenAll: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("OpenAll returned %d fields, want %d", len(got), len(in))
	}
	for k, v := range in {
		if got[k] != v {
			t.Fatalf("OpenAll[%q] = %q, want %q", k, got[k], v)
		}
	}
}
