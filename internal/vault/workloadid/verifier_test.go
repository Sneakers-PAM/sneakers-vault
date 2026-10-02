// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package workloadid

import "testing"

func TestDevVerifier(t *testing.T) {
	v := NewDevVerifier("dev-connector-token")
	if _, err := v.Verify("dev-connector-token"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if _, err := v.Verify("wrong"); err == nil {
		t.Fatal("bad token accepted")
	}
}
