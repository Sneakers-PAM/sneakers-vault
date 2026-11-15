// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// #163: create and update refuse an empty value for a required field of ANY
// kind, not only SELECT (#155/#154 already refused a missing required
// SELECT). type-web-password has required TEXT (url, username) and PASSWORD
// (password) fields plus an optional MULTILINE (notes); type-secure-note has
// a required MULTILINE (note).

func webPasswordFields(over map[string]string) map[string]string {
	all := map[string]string{"url": "https://app.example.org", "username": "app", "password": "Init1alP@ss-2026"}
	for k, v := range over {
		all[k] = v
	}
	return all
}

func TestCreateRefusesAnEmptyRequiredTextField(t *testing.T) {
	fx := newSelectFixture(t)
	_, err := fx.create("type-web-password", webPasswordFields(map[string]string{"url": ""}))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "url", nil)
}

func TestCreateRefusesAMissingRequiredTextField(t *testing.T) {
	fx := newSelectFixture(t)
	fields := webPasswordFields(nil)
	delete(fields, "username")
	_, err := fx.create("type-web-password", fields)
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "username", nil)
}

func TestCreateRefusesAnEmptyRequiredPasswordField(t *testing.T) {
	fx := newSelectFixture(t)
	_, err := fx.create("type-web-password", webPasswordFields(map[string]string{"password": ""}))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "password", nil)
}

func TestCreateRefusesAnEmptyRequiredMultilineField(t *testing.T) {
	fx := newSelectFixture(t)
	_, err := fx.create("type-secure-note", map[string]string{"note": ""})
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "note", nil)
	_, err = fx.create("type-secure-note", map[string]string{})
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "note", nil)
}

func TestCreateAcceptsAnEmptyOptionalField(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-web-password", webPasswordFields(map[string]string{"notes": ""}))
	if err != nil {
		t.Fatalf("empty optional notes: %v", err)
	}
	if got := fx.fields(t, id)["notes"]; got != "" {
		t.Fatalf("notes = %q, want empty", got)
	}
}

func TestCreateForPrincipalRefusesAnEmptyRequiredField(t *testing.T) {
	fx := newSelectFixture(t)
	_, err := fx.createAsPrincipal("type-web-password", webPasswordFields(map[string]string{"username": ""}))
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "username", nil)
}

func TestUpdateRefusesClearingARequiredField(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-web-password", webPasswordFields(nil))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Name: "renamed", Fields: map[string]string{"url": ""},
	})
	wantSelectRefusal(t, err, ReasonFieldValueRequired, "url", nil)
	if got := fx.findName(id); got != "sel" {
		t.Fatalf("a refused update renamed the secret to %q", got)
	}
	if got := fx.fields(t, id)["url"]; got != "https://app.example.org" {
		t.Fatalf("url = %q after a refused clear, want the original value kept", got)
	}
}

func TestUpdateAcceptsClearingAnOptionalField(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-web-password", webPasswordFields(map[string]string{"notes": "n1"}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Fields: map[string]string{"notes": ""},
	}); err != nil {
		t.Fatalf("clearing an optional field: %v", err)
	}
}

// An update that doesn't mention a required field at all (editing something
// else) must not be blocked by it — only a save that SENDS it empty is
// refused. This is what keeps an update to one field from forcing every
// other required field into the request.
func TestUpdateUntouchedRequiredFieldIsNotRevalidated(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-web-password", webPasswordFields(nil))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Name: "renamed-only",
	}); err != nil {
		t.Fatalf("rename without touching fields: %v", err)
	}
	if got := fx.findName(id); got != "renamed-only" {
		t.Fatalf("name = %q, want renamed-only", got)
	}
}

// An existing secret that already missed a required field before this check
// existed keeps reading, revealing and is completable by an update that
// fills the field in — the same back-compat story as #155/#154 for SELECT.
func TestExistingIncompleteSecret_StaysReadableAndIsCompletableByUpdate(t *testing.T) {
	fx := newSelectFixture(t)
	id, err := fx.create("type-web-password", webPasswordFields(nil))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fx.storeRaw(t, id, webPasswordFields(map[string]string{"url": ""}))

	if got := fx.fields(t, id)["url"]; got != "" {
		t.Fatalf("read back url = %q, want the stored empty value", got)
	}
	if _, err := fx.s.RevealSecretField(context.Background(), &vaultv1.RevealSecretFieldRequest{
		Actor: orgCarol, Id: id, FieldKey: "password",
	}); err != nil {
		t.Fatalf("reveal on an incomplete secret: %v", err)
	}

	// An update that doesn't touch url still goes through (matches sneakers
	// -web#324's rendering: the secret keeps opening and working).
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Fields: map[string]string{"notes": "n2"},
	}); err != nil {
		t.Fatalf("update of another field on an incomplete secret: %v", err)
	}
	if got := fx.fields(t, id)["url"]; got != "" {
		t.Fatalf("url = %q after an unrelated update, want still empty", got)
	}

	// Filling the missing field in now passes.
	if _, err := fx.s.UpdateSecret(context.Background(), &vaultv1.UpdateSecretRequest{
		Actor: orgCarol, Id: id, Fields: map[string]string{"url": "https://fixed.example.org"},
	}); err != nil {
		t.Fatalf("fill in the missing field: %v", err)
	}
	if got := fx.fields(t, id)["url"]; got != "https://fixed.example.org" {
		t.Fatalf("url = %q after filling it in, want the new value", got)
	}
}
