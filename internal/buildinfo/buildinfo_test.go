// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package buildinfo

import "testing"

func TestInfo_StampedValuesWin(t *testing.T) {
	oldV, oldC := Version, Commit
	Version, Commit = "v1.2.3", "abc123"
	t.Cleanup(func() { Version, Commit = oldV, oldC })
	if v, c := Info(); v != "v1.2.3" || c != "abc123" {
		t.Fatalf("Info() = %q, %q, want v1.2.3, abc123", v, c)
	}
}

func TestInfo_UnstampedFallsBack(t *testing.T) {
	oldV, oldC := Version, Commit
	Version, Commit = "", ""
	t.Cleanup(func() { Version, Commit = oldV, oldC })
	v, c := Info()
	if v != "dev" || c == "" {
		t.Fatalf("Info() = %q, %q, want dev and a commit (or unknown)", v, c)
	}
}
