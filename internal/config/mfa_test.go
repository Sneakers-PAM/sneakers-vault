// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestMFAMaxAge(t *testing.T) {
	for v, want := range map[string]time.Duration{"": DefaultMFAMaxAge, "1m": time.Minute, "15m": 15 * time.Minute, "1h": time.Hour} {
		got, err := MFAMaxAge(func(string) string { return v })
		if err != nil || got != want {
			t.Fatalf("%q: %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"5", "300", "soon", "0s", "-1m", "59s", "2h"} {
		if _, err := MFAMaxAge(func(string) string { return v }); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}
