// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"strconv"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Stable refusal reasons for a SELECT field's value. The ErrorInfo metadata
// carries "field" (the key) and "allowed" (the options, joined by "|").
const (
	ReasonFieldValueNotAllowed = "FIELD_VALUE_NOT_ALLOWED"
	ReasonFieldValueRequired   = "FIELD_VALUE_REQUIRED"
)

// matchOption returns the option v stands for: the exact option, else the one
// option it equals ignoring case. ok is false when there is none, or when a
// case-insensitive match could be more than one option.
func matchOption(options []string, v string) (string, bool) {
	var found string
	n := 0
	for _, o := range options {
		if o == v {
			return o, true
		}
		if strings.EqualFold(o, v) {
			found = o
			n++
		}
	}
	return found, n == 1
}

func selectRefusal(f *vaultv1.SecretFieldDef, reason string) error {
	quoted := make([]string, len(f.GetOptions()))
	for i, o := range f.GetOptions() {
		quoted[i] = strconv.Quote(o)
	}
	msg := "field " + strconv.Quote(f.GetKey()) + " must be one of: " + strings.Join(quoted, ", ")
	if reason == ReasonFieldValueRequired {
		msg = "field " + strconv.Quote(f.GetKey()) + " is required; choose one of: " + strings.Join(quoted, ", ")
	}
	st := status.New(codes.InvalidArgument, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{
		Domain: errorDomain, Reason: reason,
		Metadata: map[string]string{"field": f.GetKey(), "allowed": strings.Join(f.GetOptions(), "|")},
	}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// requiredRefusal refuses an empty value for a required field, named the same
// way selectRefusal names a bad SELECT value: for a SELECT with options
// declared, the message also lists them (selectRefusal's existing
// ReasonFieldValueRequired wording); for every other kind — TEXT, PASSWORD,
// MULTILINE and so on — there's nothing to list, so it just says the field is
// required.
func requiredRefusal(f *vaultv1.SecretFieldDef) error {
	if f.GetKind() == vaultv1.FieldKind_FIELD_KIND_SELECT && len(f.GetOptions()) > 0 {
		return selectRefusal(f, ReasonFieldValueRequired)
	}
	msg := "field " + strconv.Quote(f.GetKey()) + " is required"
	st := status.New(codes.InvalidArgument, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{
		Domain: errorDomain, Reason: ReasonFieldValueRequired,
		Metadata: map[string]string{"field": f.GetKey()},
	}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// checkSelectValue checks one field's value: required first (every kind, not
// only SELECT — #163), then, for a SELECT with options declared, that the
// value is one of them. Returns it in the option's canonical case for a
// SELECT, else unchanged. An empty value passes unless the field is
// required; a SELECT with no options declared constrains nothing beyond that.
func checkSelectValue(f *vaultv1.SecretFieldDef, v string) (string, error) {
	if v == "" {
		if f.GetRequired() {
			return "", requiredRefusal(f)
		}
		return "", nil
	}
	if f.GetKind() != vaultv1.FieldKind_FIELD_KIND_SELECT || len(f.GetOptions()) == 0 {
		return v, nil
	}
	o, ok := matchOption(f.GetOptions(), v)
	if !ok {
		return "", selectRefusal(f, ReasonFieldValueNotAllowed)
	}
	return o, nil
}

// checkSelectFieldsForCreate checks every field of st against fields — a
// missing or empty required one included, whatever its kind, plus a SELECT's
// options. It returns a copy with SELECT case variants replaced by the
// canonical option; fields itself is never changed.
func checkSelectFieldsForCreate(st *vaultv1.SecretType, fields map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	for _, f := range st.GetFields() {
		v, err := checkSelectValue(f, fields[f.GetKey()])
		if err != nil {
			return nil, err
		}
		if _, sent := fields[f.GetKey()]; sent {
			out[f.GetKey()] = v
		}
	}
	return out, nil
}

// checkSelectFieldsInPatch checks only the fields present in patch, so a
// stored value that predates the check (a required field already empty, or a
// SELECT value outside today's options) never blocks a change to another
// field — it only refuses a NEW empty value for a required field, or a NEW
// SELECT value outside the options, in the fields this save actually sends.
// It returns a canonical copy of patch.
func checkSelectFieldsInPatch(st *vaultv1.SecretType, patch map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(patch))
	for _, k := range sortedKeys(patch) {
		v := patch[k]
		if f := fieldDef(st, k); f != nil {
			c, err := checkSelectValue(f, v)
			if err != nil {
				return nil, err
			}
			v = c
		}
		out[k] = v
	}
	return out, nil
}
