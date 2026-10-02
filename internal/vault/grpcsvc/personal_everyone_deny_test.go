// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// An everyone deny on a child still applies to a machine inside a personal
// subtree, where a parent grant from the owner would otherwise reach it.
func TestPersonalSubtreeEveryoneDenyStillBlocksMachines(t *testing.T) {
	s := newServer(t)
	seedPersonalFolder(s, "user-carol")
	grantGroup(t, s, orgCarol, "folder-personal-carol", "C")
	child := &vaultv1.Folder{Id: "folder-carol-locked", Name: "Locked", ParentId: "folder-personal-carol",
		Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "user-carol"}
	s.folders = append(s.folders, child)
	injectEveryoneRule(s, child.GetId(), map[string]string{"C": "deny"})
	sa := agentGroupActor("sa-1")
	if !s.principalFolderAccess(sa, "folder-personal-carol").Read.Allowed {
		t.Fatal("setup: the owner's group grant should reach the parent")
	}
	if s.principalFolderAccess(sa, child.GetId()).Read.Allowed {
		t.Fatal("an everyone deny on the child must still block the machine")
	}
	tok := tokenActor("user-ada", false, "g-agents")
	if s.principalFolderAccess(tok, child.GetId()).Read.Allowed {
		t.Fatal("another user's token must not reach the child")
	}
}
