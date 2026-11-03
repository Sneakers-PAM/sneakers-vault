// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
)

// Real Postgres 17: TLS certificate pins saved through the snapshot store come
// back, in order, on a restarted vault; they live in target_tls_cert_pins, not
// in the target's JSON document.
func TestTargetTLSPinsPersistAcrossRestart_Postgres(t *testing.T) {
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
		Actor: hostKeyAdmin, Connection: &vaultv1.Connection{Name: "LDAPS", Protocol: "ldap", Port: 636, UseTls: true},
	}, s.SaveConnection).GetConnection().GetId()
	p1, p2 := genCertPin(t), genCertPin(t)
	id := callPersisted(t, s, "SaveTarget", &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Name: "dc01", Hostname: "dc01.corp.example.org", ConnectionId: conn, TlsCertPins: []string{p1, p2},
	}}, s.SaveTarget).GetTarget().GetId()

	s2, err := NewWithStore(ctx, NewPGStore(pool), env, nil, "dev")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := listedTarget(t, s2, hostKeyAdmin, id).GetTlsCertPins(); !slices.Equal(got, []string{p1, p2}) {
		t.Fatalf("pins after restart = %q", got)
	}
	var doc string
	if err := pool.Querier().QueryRow(ctx, "SELECT data::text FROM targets WHERE id=$1", id).Scan(&doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc, "tlsCertPins") || strings.Contains(doc, p1) {
		t.Fatalf("pins duplicated in the target document: %s", doc)
	}

	callPersisted(t, s2, "SaveTarget", &vaultv1.SaveTargetRequest{Actor: hostKeyAdmin, Target: &vaultv1.Target{
		Id: id, Name: "dc01", Hostname: "dc01.corp.example.org", ConnectionId: conn,
	}}, s2.SaveTarget)
	var n int
	if err := pool.Querier().QueryRow(ctx, "SELECT count(*) FROM target_tls_cert_pins").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rows after clearing pins = %d", n)
	}
}
