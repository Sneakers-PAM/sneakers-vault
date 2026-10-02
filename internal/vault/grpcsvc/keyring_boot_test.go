// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// fakeKeyringPersist is an in-memory keyringPersist for testing BuildKeyring
// without a live DB.
type fakeKeyringPersist struct {
	rows          []keyringRow
	insertActiveN int
}

func (f *fakeKeyringPersist) Load(_ context.Context) ([]keyringRow, error) {
	out := make([]keyringRow, len(f.rows))
	copy(out, f.rows)
	return out, nil
}

func (f *fakeKeyringPersist) Active(_ context.Context) (keyringRow, bool, error) {
	for _, r := range f.rows {
		if r.Active {
			return r, true, nil
		}
	}
	return keyringRow{}, false, nil
}

func (f *fakeKeyringPersist) InsertActive(_ context.Context, ref string, wrapped []byte, rootRef string) error {
	f.insertActiveN++
	for i := range f.rows {
		f.rows[i].Active = false
	}
	f.rows = append(f.rows, keyringRow{Ref: ref, WrappedKey: wrapped, RootRef: rootRef, Active: true})
	return nil
}

func bootMustKey(t *testing.T) []byte {
	t.Helper()
	k, err := crypto.RandKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBuildKeyring_EmptyRing_SeedsActiveKekV1(t *testing.T) {
	ctx := context.Background()
	root, err := crypto.NewStaticKEKFromSeed("boot-test-root-seed-1")
	if err != nil {
		t.Fatal(err)
	}
	legacy := crypto.WorkingKey{Ref: "legacy-v1", Key: bootMustKey(t)}
	ks := &fakeKeyringPersist{}

	kr, err := BuildKeyring(ctx, ks, root, "root-v1", legacy)
	if err != nil {
		t.Fatalf("BuildKeyring: %v", err)
	}

	if ks.insertActiveN != 1 {
		t.Fatalf("InsertActive called %d times, want 1", ks.insertActiveN)
	}
	if got := kr.ActiveRef(); got != "kek-v1" {
		t.Fatalf("ActiveRef = %q, want kek-v1", got)
	}
}

func TestBuildKeyring_NonEmptyRing_NoSeed(t *testing.T) {
	ctx := context.Background()
	root, err := crypto.NewStaticKEKFromSeed("boot-test-root-seed-2")
	if err != nil {
		t.Fatal(err)
	}
	legacy := crypto.WorkingKey{Ref: "legacy-v1", Key: bootMustKey(t)}

	raw := bootMustKey(t)
	wrapped, rootRef, err := root.WrapDEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	ks := &fakeKeyringPersist{rows: []keyringRow{
		{Ref: "kek-v2", WrappedKey: wrapped, RootRef: rootRef, Active: true},
	}}

	kr, err := BuildKeyring(ctx, ks, root, "root-v1", legacy)
	if err != nil {
		t.Fatalf("BuildKeyring: %v", err)
	}

	if ks.insertActiveN != 0 {
		t.Fatalf("InsertActive called %d times, want 0", ks.insertActiveN)
	}
	if got := kr.ActiveRef(); got != "kek-v2" {
		t.Fatalf("ActiveRef = %q, want kek-v2", got)
	}
}

func TestBuildKeyring_LegacyKeyRecognized(t *testing.T) {
	ctx := context.Background()
	root, err := crypto.NewStaticKEKFromSeed("boot-test-root-seed-3")
	if err != nil {
		t.Fatal(err)
	}

	legacyKey := bootMustKey(t)
	legacyStatic, err := crypto.NewStaticKEK(legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	dek := bootMustKey(t)
	wrapped, _, err := legacyStatic.WrapDEK(dek)
	if err != nil {
		t.Fatal(err)
	}

	legacy := crypto.WorkingKey{Ref: "dev-static-v1", Key: legacyKey}
	ks := &fakeKeyringPersist{}

	kr, err := BuildKeyring(ctx, ks, root, "root-v1", legacy)
	if err != nil {
		t.Fatalf("BuildKeyring: %v", err)
	}

	got, err := kr.UnwrapDEK(wrapped, "dev-static-v1")
	if err != nil {
		t.Fatalf("UnwrapDEK via legacy ref: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("legacy-wrapped record did not round-trip through the built ring")
	}
}
