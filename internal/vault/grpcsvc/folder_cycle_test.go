// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// A parent cycle must never make an ancestor walk spin. The move guards reject
// cycles, but persisted data is not guaranteed to be acyclic, and an unbounded
// walk that appends per step can exhaust memory when a guard is missing.
// Each walk must visit a folder at most once.
func TestAncestorWalksTerminateOnParentCycle(t *testing.T) {
	s := newServer(t)
	s.folders = append(s.folders,
		&vaultv1.Folder{Id: "cyc-a", Name: "A", ParentId: "cyc-b"},
		&vaultv1.Folder{Id: "cyc-b", Name: "B", ParentId: "cyc-a"},
		&vaultv1.Folder{Id: "cyc-self", Name: "Self", ParentId: "cyc-self"},
	)

	if got := len(s.ancestorsInclusive("cyc-a")); got != 2 {
		t.Fatalf("ancestorsInclusive over a 2-cycle: want 2 folders, got %d", got)
	}
	if got := len(s.ancestorsInclusive("cyc-self")); got != 1 {
		t.Fatalf("ancestorsInclusive over a self-parent: want 1 folder, got %d", got)
	}
	if got := len(s.chainFor("cyc-a")); got != 2 {
		t.Fatalf("chainFor over a 2-cycle: want 2 rulesets, got %d", got)
	}
	if _, err := s.GetInheritedFolderRules(context.Background(), &vaultv1.GetInheritedFolderRulesRequest{FolderId: "cyc-a"}); err != nil {
		t.Fatalf("GetInheritedFolderRules over a 2-cycle: %v", err)
	}
}
