// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// failingPersistStore serves a fixed committed state and fails every Persist.
type failingPersistStore struct{ committed *state }

func (f failingPersistStore) Load(context.Context) (*state, bool, error) {
	return f.committed, false, nil
}

func (failingPersistStore) Persist(context.Context, *state) error {
	return errors.New("postgres unavailable")
}

// TestPersistUnaryPersistFailureFailsTheRPC: a mutation that could not be
// persisted must fail the RPC (it used to be logged while the caller was told
// it succeeded), and memory must be re-synced so reads don't serve it.
func TestPersistUnaryPersistFailureFailsTheRPC(t *testing.T) {
	s := newServer(t)
	s.store = failingPersistStore{committed: s.snapshot()}
	before := len(s.folders)

	_, err := s.PersistUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/sneakers.vault.v1.VaultService/CreateFolder"},
		func(ctx context.Context, _ any) (any, error) {
			return s.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: &vaultv1.ActorContext{UserId: "user-operator"}, Name: "never-saved"})
		})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("persist failure: want Unavailable, got %v", err)
	}
	if got := len(s.folders); got != before {
		t.Fatalf("unpersisted folder still served from memory: want %d folders, got %d", before, got)
	}
}
