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

// checkSelectValue checks one SELECT field's value and returns it in the
// option's canonical case. An empty value passes unless the field is
// required. A SELECT with no options declared constrains nothing.
func checkSelectValue(f *vaultv1.SecretFieldDef, v string) (string, error) {
	if f.GetKind() != vaultv1.FieldKind_FIELD_KIND_SELECT || len(f.GetOptions()) == 0 {
		return v, nil
	}
	if v == "" {
		if f.GetRequired() {
			return "", selectRefusal(f, ReasonFieldValueRequired)
		}
		return "", nil
	}
	o, ok := matchOption(f.GetOptions(), v)
	if !ok {
		return "", selectRefusal(f, ReasonFieldValueNotAllowed)
	}
	return o, nil
}

// checkSelectFieldsForCreate checks every SELECT field of st against fields,
// a missing required one included. It returns a copy with case variants
// replaced by the canonical option; fields itself is never changed.
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

// checkSelectFieldsInPatch checks only the SELECT fields present in patch, so
// a stored value that predates the check never blocks a change to another
// field. It returns a canonical copy of patch.
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
