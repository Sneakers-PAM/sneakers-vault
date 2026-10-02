// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"strings"
	"testing"
	"unicode"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

func i32p(v int32) *int32 { return &v }

func TestGeneratePasswordDefaultLength(t *testing.T) {
	pw, err := GeneratePassword(nil)
	if err != nil {
		t.Fatalf("GeneratePassword(nil): %v", err)
	}
	if len([]rune(pw)) != 20 {
		t.Fatalf("default length = %d, want 20", len([]rune(pw)))
	}
}

func TestGeneratePasswordMinLength(t *testing.T) {
	pw, err := GeneratePassword(&vaultv1.PasswordPolicy{MinLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(pw)) < 32 {
		t.Fatalf("len = %d, want >= 32", len([]rune(pw)))
	}
}

func TestGeneratePasswordLengthBounds(t *testing.T) {
	p := &vaultv1.PasswordPolicy{MinLength: 8, MaxLength: i32p(12)}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatal(err)
		}
		n := len([]rune(pw))
		if n < 8 || n > 12 {
			t.Fatalf("len = %d, want 8..12", n)
		}
	}
}

func hasClass(s string, pred func(rune) bool) bool {
	for _, r := range s {
		if pred(r) {
			return true
		}
	}
	return false
}

func isSymbol(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

func TestGeneratePasswordRequiredClasses(t *testing.T) {
	p := &vaultv1.PasswordPolicy{MinLength: 16, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatal(err)
		}
		if !hasClass(pw, unicode.IsUpper) {
			t.Fatalf("missing upper: %q", pw)
		}
		if !hasClass(pw, unicode.IsLower) {
			t.Fatalf("missing lower: %q", pw)
		}
		if !hasClass(pw, unicode.IsDigit) {
			t.Fatalf("missing digit: %q", pw)
		}
		if !hasClass(pw, isSymbol) {
			t.Fatalf("missing symbol: %q", pw)
		}
	}
}

func TestGeneratePasswordExcludeChars(t *testing.T) {
	excluded := "0O1lI"
	p := &vaultv1.PasswordPolicy{MinLength: 24, RequireUpper: true, RequireLower: true, RequireDigit: true, ExcludeChars: excluded}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(pw, excluded) {
			t.Fatalf("excluded char present: %q", pw)
		}
	}
}

func TestGeneratePasswordStartClass(t *testing.T) {
	p := &vaultv1.PasswordPolicy{MinLength: 16, RequireDigit: true, RequireLower: true, StartClass: "letter"}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatal(err)
		}
		first := []rune(pw)[0]
		if !unicode.IsLetter(first) {
			t.Fatalf("start rune %q not a letter in %q", first, pw)
		}
	}
	// digit start class
	pd := &vaultv1.PasswordPolicy{MinLength: 16, RequireLower: true, StartClass: "digit"}
	pw, err := GeneratePassword(pd)
	if err != nil {
		t.Fatal(err)
	}
	if !unicode.IsDigit([]rune(pw)[0]) {
		t.Fatalf("digit start class: first rune %q", []rune(pw)[0])
	}
}

func TestGeneratePasswordEndLiteral(t *testing.T) {
	p := &vaultv1.PasswordPolicy{MinLength: 16, RequireUpper: true, RequireLower: true, EndLiteral: "!"}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(pw, "!") {
			t.Fatalf("missing end literal: %q", pw)
		}
	}
}

func TestGeneratePasswordThousandSamplesSatisfyAndVary(t *testing.T) {
	p := &vaultv1.PasswordPolicy{
		MinLength: 20, MaxLength: i32p(28),
		RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true,
		ExcludeChars: "0O1lI", StartClass: "letter", EndLiteral: "#",
	}
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		pw, err := GeneratePassword(p)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		n := len([]rune(pw))
		if n < 20 || n > 28 {
			t.Fatalf("len %d out of bounds: %q", n, pw)
		}
		if !unicode.IsLetter([]rune(pw)[0]) {
			t.Fatalf("start not letter: %q", pw)
		}
		if !strings.HasSuffix(pw, "#") {
			t.Fatalf("no end literal: %q", pw)
		}
		if strings.ContainsAny(pw, "0O1lI") {
			t.Fatalf("excluded char: %q", pw)
		}
		if !hasClass(pw, unicode.IsUpper) || !hasClass(pw, unicode.IsLower) ||
			!hasClass(pw, unicode.IsDigit) || !hasClass(pw[:len(pw)-1], isSymbol) {
			t.Fatalf("missing required class: %q", pw)
		}
		seen[pw] = true
	}
	if len(seen) < 990 {
		t.Fatalf("entropy sanity: only %d distinct of 1000", len(seen))
	}
}

// TestGeneratePasswordImpossiblePolicyErrors: excluding every digit while
// requiring a digit is unsatisfiable and must error rather than loop forever.
func TestGeneratePasswordImpossiblePolicyErrors(t *testing.T) {
	p := &vaultv1.PasswordPolicy{MinLength: 12, RequireDigit: true, ExcludeChars: "0123456789"}
	if _, err := GeneratePassword(p); err == nil {
		t.Fatal("expected error for unsatisfiable digit policy")
	}
}
