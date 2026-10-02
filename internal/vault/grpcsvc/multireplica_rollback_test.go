// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func personalFolderOf(s *Server, userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.folders {
		if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && f.GetOwnerUserId() == userID && !f.GetIsMasterPersonal() {
			return true
		}
	}
	return false
}

// A refused mutating RPC rolls its transaction back; the replica that served it
// must drop whatever the handler changed in memory before refusing, or it
// serves state no other replica has.
func TestMultiReplicaRefusedWriteLeavesNoMemoryChange(t *testing.T) {
	ctx, _, a, b := setupLostWrite(t)
	operator := &vaultv1.ActorContext{UserId: "user-operator"}
	parent := viaInterceptor(ctx, t, a, "CreateFolder", func() (any, error) {
		return a.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: operator, Name: "ops-only"})
	}).(*vaultv1.CreateFolderResponse).GetFolder().GetId()
	time.Sleep(600 * time.Millisecond)

	newcomer := &vaultv1.ActorContext{UserId: "user-newcomer"}
	_, err := a.PersistUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/CreateFolder"},
		func(context.Context, any) (any, error) {
			return a.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: newcomer, Name: "sneaky", ParentId: parent})
		})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CreateFolder under another's folder: want PermissionDenied, got %v", err)
	}
	time.Sleep(600 * time.Millisecond)

	if personalFolderOf(a, "user-newcomer") != personalFolderOf(b, "user-newcomer") {
		t.Fatalf("replicas disagree after a refused write: A=%v B=%v", personalFolderOf(a, "user-newcomer"), personalFolderOf(b, "user-newcomer"))
	}
	if personalFolderOf(a, "user-newcomer") {
		t.Fatal("replica A kept a personal folder from a refused write")
	}
}
