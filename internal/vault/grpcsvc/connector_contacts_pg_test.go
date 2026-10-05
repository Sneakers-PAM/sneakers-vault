// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid"
	"google.golang.org/grpc/metadata"
)

func connectorContactsServer(t *testing.T, workerID string) *Server {
	t.Helper()
	_, pool := organizeFreshDB(t)
	s := newServer(t)
	s.SetHeartbeat(pool, acceptVerifier{principal: workloadid.Principal{WorkerID: workerID}})
	s.SetRotation(pool, nil)
	return s
}

func withBuild(version, commit string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(metadataVersion, version, metadataCommit, commit))
}

func listConnectors(t *testing.T, s *Server) []*vaultv1.ConnectorContact {
	t.Helper()
	res, err := s.ListConnectors(context.Background(), &vaultv1.ListConnectorsRequest{})
	if err != nil {
		t.Fatalf("ListConnectors: %v", err)
	}
	return res.GetConnectors()
}

// A pull call carrying the build metadata records the connector's build and
// last contact, and ListConnectors returns them.
func TestPullCallRecordsConnectorBuild_Postgres(t *testing.T) {
	s := connectorContactsServer(t, "worker-a")
	before := time.Now().Add(-time.Second)
	if _, err := s.ClaimDueHeartbeats(withBuild("v0.1.0", "abc1234"), &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "t"}}); err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	got := listConnectors(t, s)
	if len(got) != 1 {
		t.Fatalf("connectors = %v, want one", got)
	}
	c := got[0]
	if c.GetWorkerId() != "worker-a" || c.GetVersion() != "v0.1.0" || c.GetCommit() != "abc1234" {
		t.Fatalf("connector = %v", c)
	}
	at, err := time.Parse(time.RFC3339Nano, c.GetLastContactAt())
	if err != nil || at.Before(before) {
		t.Fatalf("last_contact_at = %q (%v), want after %v", c.GetLastContactAt(), err, before)
	}
}

// A later call without the metadata moves the last contact forward and keeps
// the build the connector last sent; a call with a new build replaces it.
func TestPullCallWithoutBuildKeepsLastBuild_Postgres(t *testing.T) {
	s := connectorContactsServer(t, "worker-b")
	id := &vaultv1.WorkerIdentity{Token: "t"}
	if _, err := s.ClaimDueRotations(withBuild("v0.1.0", "abc1234"), &vaultv1.ClaimDueRotationsRequest{Identity: id}); err != nil {
		t.Fatalf("ClaimDueRotations: %v", err)
	}
	first := listConnectors(t, s)[0].GetLastContactAt()
	time.Sleep(10 * time.Millisecond)
	if _, err := s.ClaimDueHeartbeats(context.Background(), &vaultv1.ClaimDueHeartbeatsRequest{Identity: id}); err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	c := listConnectors(t, s)[0]
	if c.GetVersion() != "v0.1.0" || c.GetCommit() != "abc1234" {
		t.Fatalf("build lost on a call without metadata: %v", c)
	}
	if c.GetLastContactAt() <= first {
		t.Fatalf("last contact %q did not move past %q", c.GetLastContactAt(), first)
	}
	if _, err := s.ClaimDueHeartbeats(withBuild("v0.2.0", "def5678"), &vaultv1.ClaimDueHeartbeatsRequest{Identity: id}); err != nil {
		t.Fatalf("ClaimDueHeartbeats: %v", err)
	}
	if c := listConnectors(t, s)[0]; c.GetVersion() != "v0.2.0" || c.GetCommit() != "def5678" {
		t.Fatalf("build not replaced: %v", c)
	}
}

// A rejected worker identity records nothing.
func TestRejectedWorkerRecordsNoContact_Postgres(t *testing.T) {
	s := connectorContactsServer(t, "worker-c")
	s.wid = rejectVerifier{}
	if _, err := s.ClaimDueHeartbeats(withBuild("v0.1.0", "abc1234"), &vaultv1.ClaimDueHeartbeatsRequest{Identity: &vaultv1.WorkerIdentity{Token: "bad"}}); err == nil {
		t.Fatal("expected the identity to be rejected")
	}
	if got := listConnectors(t, s); len(got) != 0 {
		t.Fatalf("connectors = %v, want none", got)
	}
}
