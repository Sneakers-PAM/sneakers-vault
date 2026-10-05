// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import "testing"

func TestConn_IsTheDialledConnection(t *testing.T) {
	t.Setenv("VAULT_ADDR", "vault.example.test:9091")
	c, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Conn() == nil || c.Conn() != c.conn {
		t.Fatal("Conn must return the client's connection")
	}
}
