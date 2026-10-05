// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

func TestDependencies_OnlyTheDatabaseIsRequired(t *testing.T) {
	conn, err := grpc.NewClient("peer.example.test:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ping := func(context.Context) error { return nil }
	want := map[string]bool{"postgres": true, "audit": false, "notify": false, "valkey": false}
	got := dependencies(okPinger{}, conn, conn, ping)
	if len(got) != len(want) {
		t.Fatalf("dependencies = %d, want %d", len(got), len(want))
	}
	for _, d := range got {
		if req, ok := want[d.Name]; !ok || req != d.Required {
			t.Errorf("%s: required=%v, want %v (known %v)", d.Name, d.Required, req, ok)
		}
	}
	for _, d := range dependencies(okPinger{}, conn, conn, nil) {
		if d.Name == "valkey" {
			t.Error("valkey listed without a client")
		}
	}
}
