// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	workloadauth "github.com/Bugs5382/go-workload-identity"
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
	ping := func(context.Context) error { return nil }
	verifier, err := workloadauth.NewVerifier(workloadauth.Config{
		Issuer: "https://issuer.example.test", Audience: "sneakers",
		AllowedServiceAccounts: []string{"sneakers/sneakers-gateway"},
	}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"postgres": true, "audit": false, "notify": false, "valkey": false, "workload-identity": true}
	got := dependencies(okPinger{}, conn, conn, ping, verifier)
	if len(got) != len(want) {
		t.Fatalf("dependencies = %d, want %d", len(got), len(want))
	}
	for _, d := range got {
		if req, ok := want[d.Name]; !ok || req != d.Required {
			t.Errorf("%s: required=%v, want %v (known %v)", d.Name, d.Required, req, ok)
		}
	}
	for _, d := range dependencies(okPinger{}, conn, conn, nil, nil) {
		if d.Name == "valkey" {
			t.Error("valkey listed without a client")
		}
		if d.Name == "workload-identity" {
			t.Error("workload-identity listed without a verifier")
		}
	}
}
