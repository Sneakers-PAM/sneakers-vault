// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"time"
)

// MFAMaxAgeEnv names the one setting for how recent a user's MFA must be for
// every MFA-freshness check in the vault and the workflow.
const MFAMaxAgeEnv = "MFA_MAX_AGE"

// DefaultMFAMaxAge applies when MFA_MAX_AGE is unset.
const DefaultMFAMaxAge = 5 * time.Minute

// MFAMaxAge parses MFA_MAX_AGE: a Go duration from 1m to 1h, default 5m. A
// bad value is an error so the service stops at boot.
func MFAMaxAge(getenv func(string) string) (time.Duration, error) {
	v := getenv(MFAMaxAgeEnv)
	if v == "" {
		return DefaultMFAMaxAge, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute || d > time.Hour {
		return 0, fmt.Errorf("%s=%q: want a duration from 1m to 1h", MFAMaxAgeEnv, v)
	}
	return d, nil
}
