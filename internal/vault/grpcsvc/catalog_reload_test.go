// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/alicebob/miniredis/v2"
)

// TestCatalogReloadViaRedis proves that a NEW built-in
// secret type landing in Postgres via raw SQL — exactly how the prod-safe
// cmd/seed-catalog binary's internal/vault/catalogseed upsert reaches secret_types,
// entirely outside this Server's gRPC surface — becomes visible via
// ListSecretTypes once ANY publisher (the seed process, not just a peer vault)
// sends an invalidation on the shared Redis channel. This is the SAME
// mechanism secrets already use for HA read-consistency
// (TestPublishTriggersReloadViaRedis): no new vault-side subscriber or reload
// path was needed, because reload() already re-hydrates the FULL state —
// types/connections/extCatalog included — from the store.
func TestCatalogReloadViaRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	store := &sharedStore{}
	serverB := newSharedServer(t, store) // dev boot: seeds the baseline catalog and persists it

	rcB, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rcB.Close() }()
	serverB.SetInvalidation(rcB, DefaultInvalidateChannel)
	serverB.invDebounceD = 2 * time.Millisecond // fast reload for the test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serverB.RunInvalidationSubscriber(ctx)

	const newTypeID = "type-reload-newtype"
	seeded := cloneState(store.st)
	seeded.types = append(seeded.types, &vaultv1.SecretType{Id: newTypeID, Name: "Reload New Type"})
	if err := store.Persist(context.Background(), seeded); err != nil {
		t.Fatalf("simulate seed persist: %v", err)
	}

	hasNewType := func() bool {
		resp, err := serverB.ListSecretTypes(context.Background(), &vaultv1.ListSecretTypesRequest{})
		if err != nil {
			t.Fatalf("ListSecretTypes: %v", err)
		}
		for _, ty := range resp.GetTypes() {
			if ty.GetId() == newTypeID {
				return true
			}
		}
		return false
	}

	if hasNewType() {
		t.Fatal("precondition failed: serverB already sees the seeded type without reloading")
	}

	// Publish the way internal/vault/catalogseed.PublishReload does: a fresh Redis
	// client on the same channel, standing in for the separate seed process —
	// NOT serverB's own publishInvalidate — proving any publisher on this
	// channel triggers the reload, not only a peer vault replica.
	rcSeed, err := bredis.Connect(context.Background(), bredis.WithAddr(mr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rcSeed.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if perr := rcSeed.Redis().Publish(context.Background(), DefaultInvalidateChannel, []byte(`{"origin":"seed-catalog"}`)).Err(); perr != nil {
			t.Fatalf("publish: %v", perr)
		}
		if hasNewType() {
			return // success
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("serverB never reloaded the catalog change published by the seed")
}
