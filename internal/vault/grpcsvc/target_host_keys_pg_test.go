// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// Real Postgres 17: pins saved through the snapshot store come back, in order,
// on a restarted vault; they live in target_ssh_host_keys with their
// fingerprints, not in the target's JSON document.
func TestTargetHostKeysPersistAcrossRestart_Postgres(t *testing.T) {
	_, pool := organizeFreshDB(t)
	ctx := context.Background()
	kek, err := crypto.NewRandomKEK()
	if err != nil {
		t.Fatal(err)
	}
	env := crypto.New(kek)
	s, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	conn := callPersisted(t, s, "SaveConnection", &vaultv1.SaveConnectionRequest{
		Actor: hostKeyAdmin, Connection: &vaultv1.Connection{Name: "SSH", Protocol: "ssh", Port: 22},
	}, s.SaveConnection).GetConnection().GetId()
	k1, fp1 := genHostKey(t)
	k2, fp2 := genECDSAHostKey(t)
	id := callPersisted(t, s, "SaveTarget", &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "app01", Hostname: "app01.example.org", ConnectionId: conn, SshHostKeys: []string{k1, k2},
	}}, s.SaveTarget).GetTarget().GetId()

	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := listedTarget(t, s2, hostKeyAdmin, id).GetSshHostKeys(); strings.Join(got, "|") != k1+"|"+k2 {
		t.Fatalf("host keys after restart = %q", got)
	}

	rows, err := pool.Querier().Query(ctx, "SELECT fingerprint FROM target_ssh_host_keys WHERE target_id=$1 ORDER BY ordinal", id)
	if err != nil {
		t.Fatal(err)
	}
	var fps []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			t.Fatal(err)
		}
		fps = append(fps, fp)
	}
	rows.Close()
	if strings.Join(fps, ",") != fp1+","+fp2 {
		t.Fatalf("stored fingerprints = %v", fps)
	}
	var doc string
	if err := pool.Querier().QueryRow(ctx, "SELECT data::text FROM targets WHERE id=$1", id).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "sshHostKeys") {
		t.Fatalf("pins duplicated in the target document: %s", doc)
	}

	// Clearing the pins (as an admin) removes the rows.
	callPersisted(t, s2, "SaveTarget", &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Id: id, Name: "app01", Hostname: "app01.example.org", ConnectionId: conn,
	}}, s2.SaveTarget)
	var n int
	if err := pool.Querier().QueryRow(ctx, "SELECT count(*) FROM target_ssh_host_keys").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rows after clearing pins = %d", n)
	}
}
