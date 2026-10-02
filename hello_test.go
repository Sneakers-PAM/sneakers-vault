// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
package sneakersvault

import "testing"

func TestHello(t *testing.T) {
	got := Hello("world")
	want := "Hello, world!"
	if got != want {
		t.Errorf("Hello() = %q, want %q", got, want)
	}
}
