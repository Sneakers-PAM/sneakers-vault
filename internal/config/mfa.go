// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"time"
)

// MFAMaxAgeEnv names the one setting for how recent a user's MFA must be for
// every MFA-freshness check in the vault and the workflow: after one step-up,
// no further prompt until the window ends.
const MFAMaxAgeEnv = "MFA_MAX_AGE"

// DefaultMFAMaxAge applies when MFA_MAX_AGE is unset.
const DefaultMFAMaxAge = 30 * time.Minute

// MaxMFAMaxAge is the longest window MFA_MAX_AGE accepts.
const MaxMFAMaxAge = 4 * time.Hour

// MFAMaxAge parses MFA_MAX_AGE: a Go duration from 0 to 4h, default 30m. 0
// means every sensitive action needs its own step-up. A bad value is an error
// so the service stops at boot.
func MFAMaxAge(getenv func(string) string) (time.Duration, error) {
	v := getenv(MFAMaxAgeEnv)
	if v == "" {
		return DefaultMFAMaxAge, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || d > MaxMFAMaxAge {
		return 0, fmt.Errorf("%s=%q: want a duration from 0 to 4h", MFAMaxAgeEnv, v)
	}
	return d, nil
}

// mfaClockSkew tolerates an MFA time slightly ahead of this service's clock.
// With a 0 window it is also how long one step-up covers the action it was
// made for.
const mfaClockSkew = 30 * time.Second

// MFAFresh reports whether an MFA verified at verifiedAtUnix (0 = never)
// still covers an action at now, for the given MFA_MAX_AGE window.
func MFAFresh(verifiedAtUnix int64, now time.Time, window time.Duration) bool {
	if verifiedAtUnix <= 0 {
		return false
	}
	age := now.Sub(time.Unix(verifiedAtUnix, 0))
	return age >= -mfaClockSkew && age <= max(window, mfaClockSkew)
}
