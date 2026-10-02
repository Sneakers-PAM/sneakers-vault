// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package safeconv provides audited, overflow-safe narrowing of wide integers
// into fixed-width protobuf scalar types. A raw int32(...) at a call site trips
// the gosec G115 (CWE-190) gate; centralizing one clamped, //nosec-justified
// conversion keeps services consistent.
package safeconv

import "math"

// Int32 clamps n into the int32 range.
func Int32(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n) // #nosec G115 -- bounds-checked immediately above
}
