// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

func (okPinger) Querier() postgres.Querier { return nil }

func TestDependencies_OnlyTheDatabaseIsRequired(t *testing.T) {
	conn, err := grpc.NewClient("peer.example.test:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	want := map[string]bool{"postgres": true, "vault": false, "audit": false}
	got := dependencies(okPinger{}, conn, conn)
	if len(got) != len(want) {
		t.Fatalf("dependencies = %d, want %d", len(got), len(want))
	}
	for _, d := range got {
		if req, ok := want[d.Name]; !ok || req != d.Required {
			t.Errorf("%s: required=%v, want %v (known %v)", d.Name, d.Required, req, ok)
		}
	}
}
