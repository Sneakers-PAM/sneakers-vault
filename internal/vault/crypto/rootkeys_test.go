// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func staticKEK(t *testing.T, seed string) *StaticKEK {
	t.Helper()
	k, err := NewStaticKEKFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRootRef_IsStableDistinctAndHidesTheKey(t *testing.T) {
	a, b := RootRef(bytes.Repeat([]byte{1}, 32)), RootRef(bytes.Repeat([]byte{2}, 32))
	if a == b || a != RootRef(bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("refs %q %q: want stable per key and different across keys", a, b)
	}
	if !strings.HasPrefix(a, "root-") || len(a) > 24 {
		t.Fatalf("ref %q: want a short root- name", a)
	}
}

func TestRootKEKs_WrapsUnderTheCurrentRoot(t *testing.T) {
	cur, prev := staticKEK(t, "current"), staticKEK(t, "previous")
	rk := NewRootKEKs(cur, "root-cur", prev)
	wrapped, ref, err := rk.WrapDEK([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil || ref != "root-cur" {
		t.Fatalf("ref=%q err=%v, want root-cur", ref, err)
	}
	if _, err := prev.UnwrapDEK(wrapped, ""); err == nil {
		t.Fatal("a key wrapped by the rotating root opened under the previous root")
	}
	if _, err := cur.UnwrapDEK(wrapped, ""); err != nil {
		t.Fatalf("not under the current root: %v", err)
	}
}

func TestRootKEKs_UnwrapsByTheRefItNames(t *testing.T) {
	cur, prev := staticKEK(t, "current"), staticKEK(t, "previous")
	rk := NewRootKEKs(cur, "root-cur", prev)
	dek := []byte("0123456789abcdef0123456789abcdef")

	onCur, _, _ := cur.WrapDEK(dek)
	onPrev, _, _ := prev.WrapDEK(dek)
	for name, c := range map[string]struct {
		wrapped []byte
		ref     string
	}{"current": {onCur, "root-cur"}, "legacy ref": {onPrev, "root-v1"}, "previous ref": {onPrev, "root-old"}} {
		got, err := rk.UnwrapDEK(c.wrapped, c.ref)
		if err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
	// A key labelled as on the current root but wrapped by the previous one is
	// not silently opened by the other key.
	if _, err := rk.UnwrapDEK(onPrev, "root-cur"); err == nil {
		t.Fatal("a mislabelled key opened")
	}
}

func TestRootKEKs_WithoutAPreviousEveryRefOpensUnderTheCurrentRoot(t *testing.T) {
	cur := staticKEK(t, "current")
	rk := NewRootKEKs(cur, "root-cur", nil)
	dek := []byte("0123456789abcdef0123456789abcdef")
	w, _, _ := cur.WrapDEK(dek)
	if got, err := rk.UnwrapDEK(w, "root-v1"); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("the unrotated ref root-v1 must still open: %v", err)
	}
	other, _, _ := staticKEK(t, "other").WrapDEK(dek)
	if _, err := rk.UnwrapDEK(other, "root-v1"); err == nil {
		t.Fatal("a key from another root opened")
	}
}

func TestRootKEKs_OnCurrent(t *testing.T) {
	rk := NewRootKEKs(staticKEK(t, "c"), "root-cur", staticKEK(t, "p"))
	if !rk.OnCurrent("root-cur") || rk.OnCurrent("root-v1") {
		t.Fatal("OnCurrent must be true only for the current root's ref")
	}
	if rk.Previous() == nil || NewRootKEKs(staticKEK(t, "c"), "root-cur", nil).Previous() != nil {
		t.Fatal("Previous reports whether a previous root is held")
	}
}
