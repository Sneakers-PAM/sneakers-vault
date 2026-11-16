// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

func b64Key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolveRootKEK_SingleRootKeepsItsRef(t *testing.T) {
	root, ref, err := resolveRootKEKFrom("qa", envMap(map[string]string{"VAULT_ROOT_KEK": b64Key(1)}))
	if err != nil || ref != "root-v1" || root.Previous() != nil {
		t.Fatalf("ref=%q previous=%v err=%v, want root-v1 and no previous", ref, root.Previous(), err)
	}
}

func TestResolveRootKEK_PreviousRootGivesTheCurrentOneItsOwnRef(t *testing.T) {
	root, ref, err := resolveRootKEKFrom("qa", envMap(map[string]string{"VAULT_ROOT_KEK": b64Key(2), "VAULT_ROOT_KEK_PREVIOUS": b64Key(1)}))
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.RootRef(bytes.Repeat([]byte{2}, 32)); ref != want || root.CurrentRef() != want {
		t.Fatalf("ref=%q, want %q", ref, want)
	}
	if root.Previous() == nil {
		t.Fatal("the previous root was not loaded")
	}
	// A key wrapped under the previous root opens through the pair; one wrapped
	// under the current root carries the new ref.
	prev, _ := crypto.NewStaticKEK(bytes.Repeat([]byte{1}, 32))
	dek := bytes.Repeat([]byte{9}, 32)
	old, _, _ := prev.WrapDEK(dek)
	if got, err := root.UnwrapDEK(old, "root-v1"); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("a key on the previous root did not open: %v", err)
	}
}

func TestResolveRootKEK_PreviousNeedsACurrentRoot(t *testing.T) {
	for _, environment := range []string{"dev", "qa", "production"} {
		_, _, err := resolveRootKEKFrom(environment, envMap(map[string]string{"VAULT_ROOT_KEK_PREVIOUS": b64Key(1)}))
		if err == nil || !strings.Contains(err.Error(), "VAULT_ROOT_KEK_PREVIOUS") {
			t.Fatalf("%s: err=%v, want a refusal naming VAULT_ROOT_KEK_PREVIOUS", environment, err)
		}
	}
}

func TestResolveRootKEK_BadPreviousStopsTheStartWithoutShowingTheKey(t *testing.T) {
	bad := map[string]string{
		"not base64":      "!!! not base64 !!!",
		"wrong length":    base64.StdEncoding.EncodeToString([]byte("too short")),
		"same as current": b64Key(2),
	}
	for name, prev := range bad {
		_, _, err := resolveRootKEKFrom("qa", envMap(map[string]string{"VAULT_ROOT_KEK": b64Key(2), "VAULT_ROOT_KEK_PREVIOUS": prev}))
		if err == nil || !strings.Contains(err.Error(), "VAULT_ROOT_KEK_PREVIOUS") {
			t.Fatalf("%s: err=%v, want a refusal naming VAULT_ROOT_KEK_PREVIOUS", name, err)
		}
		if strings.Contains(err.Error(), prev) || strings.Contains(err.Error(), b64Key(2)) {
			t.Fatalf("%s: the error shows a key: %v", name, err)
		}
	}
}

func TestResolveRootKEK_DevSeedStillWorks(t *testing.T) {
	root, ref, err := resolveRootKEKFrom("dev", envMap(nil))
	if err != nil || ref != "dev-root-v1" || root.Previous() != nil {
		t.Fatalf("ref=%q err=%v, want the dev root", ref, err)
	}
}
