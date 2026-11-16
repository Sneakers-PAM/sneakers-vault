// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"time"
)

// UseApprovalLifetimeEnv names the setting for how long an approved secret
// use stays redeemable, counted from the approval.
const UseApprovalLifetimeEnv = "SECRET_USE_APPROVAL_LIFETIME"

// DefaultUseApprovalLifetime applies when the setting is unset.
const DefaultUseApprovalLifetime = 10 * time.Minute

// MaxUseApprovalLifetime is the longest lifetime the setting accepts.
const MaxUseApprovalLifetime = time.Hour

// UseApprovalLifetime parses SECRET_USE_APPROVAL_LIFETIME: a Go duration above
// 0 and up to 1h, default 10m. A bad value is an error so the service stops at
// boot.
func UseApprovalLifetime(getenv func(string) string) (time.Duration, error) {
	v := getenv(UseApprovalLifetimeEnv)
	if v == "" {
		return DefaultUseApprovalLifetime, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > MaxUseApprovalLifetime {
		return 0, fmt.Errorf("%s=%q: want a duration above 0 and up to 1h", UseApprovalLifetimeEnv, v)
	}
	return d, nil
}
