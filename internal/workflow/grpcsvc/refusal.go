// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorDomain is the google.rpc.ErrorInfo domain of every workflow refusal.
const errorDomain = "sneakers.workflow"

// Stable refusal reasons, carried in the ErrorInfo of a refused call so the
// gateway can say why.
const (
	ReasonCheckoutNoAccess     = "CHECKOUT_NO_ACCESS"
	ReasonCheckoutTypeDisabled = "CHECKOUT_TYPE_DISABLED"
	// ReasonCheckoutLeaseHeld carries metadata holder_user_id.
	ReasonCheckoutLeaseHeld = "CHECKOUT_LEASE_HELD"
	ReasonCheckinNotHolder  = "CHECKIN_NOT_HOLDER"
	// ReasonRequestNotPending refuses to resolve a request that's already
	// approved or denied.
	ReasonRequestNotPending = "REQUEST_NOT_PENDING"
)

// refuse builds a status with an ErrorInfo detail for reason.
func refuse(code codes.Code, reason, msg string, md map[string]string) error {
	st := status.New(code, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Domain: errorDomain, Reason: reason, Metadata: md}); err == nil {
		return d.Err()
	}
	return st.Err()
}
