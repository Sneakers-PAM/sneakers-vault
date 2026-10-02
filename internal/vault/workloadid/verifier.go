// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package workloadid verifies connector-worker identity before the vault
// releases a credential. The dev verifier is a shared-token seam for local
// compose. The OIDC verifier checks Kubernetes projected ServiceAccount
// tokens against the cluster issuer's JWKS and is the one used in prod.
package workloadid

import (
	"crypto/subtle"
	"errors"
)

type Principal struct{ WorkerID string }

// ErrUnavailable means the verifier cannot judge any token right now (for
// the OIDC verifier: no issuer key set has ever loaded). Callers must fail
// closed and report it as unavailable, not as a rejected token.
var ErrUnavailable = errors.New("workloadid: verifier unavailable")

type WorkloadIdentityVerifier interface {
	Verify(token string) (Principal, error)
}

type devVerifier struct{ token string }

// NewDevVerifier accepts exactly one shared dev token. NEVER use in prod.
func NewDevVerifier(token string) WorkloadIdentityVerifier { return &devVerifier{token: token} }

func (d *devVerifier) Verify(token string) (Principal, error) {
	if d.token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(d.token)) != 1 {
		return Principal{}, errors.New("workloadid: token rejected")
	}
	return Principal{WorkerID: "dev-connector"}, nil
}
