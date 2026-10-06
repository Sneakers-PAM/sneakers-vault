// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestMFAMaxAge(t *testing.T) {
	if DefaultMFAMaxAge != 30*time.Minute {
		t.Fatalf("default window %v, want 30m", DefaultMFAMaxAge)
	}
	for v, want := range map[string]time.Duration{"": DefaultMFAMaxAge, "0": 0, "0s": 0, "1m": time.Minute, "15m": 15 * time.Minute, "1h": time.Hour, "4h": 4 * time.Hour} {
		got, err := MFAMaxAge(func(string) string { return v })
		if err != nil || got != want {
			t.Fatalf("%q: %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"5", "300", "soon", "-1m", "4h1s", "5h"} {
		if _, err := MFAMaxAge(func(string) string { return v }); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestMFAFresh(t *testing.T) {
	now := time.Unix(1790000000, 0)
	at := func(ago time.Duration) int64 { return now.Add(-ago).Unix() }
	cases := []struct {
		name   string
		at     int64
		window time.Duration
		want   bool
	}{
		{"never verified", 0, time.Hour, false},
		{"inside the default window", at(29 * time.Minute), DefaultMFAMaxAge, true},
		{"past the default window", at(31 * time.Minute), DefaultMFAMaxAge, false},
		{"zero window covers the action just stepped up for", at(5 * time.Second), 0, true},
		{"zero window asks again for the next action", at(2 * time.Minute), 0, false},
		{"far in the future", now.Add(time.Minute).Unix(), time.Hour, false},
	}
	for _, c := range cases {
		if got := MFAFresh(c.at, now, c.window); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
