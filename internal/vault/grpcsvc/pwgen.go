// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// Character classes for generated passwords. The symbol set is intentionally
// conservative (no quotes/backslash/space) to survive shell/LDAP/AD handling.
const (
	classUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	classLower  = "abcdefghijklmnopqrstuvwxyz"
	classDigit  = "0123456789"
	classSymbol = "!@#$%^&*()-_=+[]{};:,.?/"
)

// defaultPasswordLen is used when a policy sets no minimum (or no policy given).
const defaultPasswordLen = 20

// GeneratePassword produces a policy-compliant password using crypto/rand only.
// It honors min/max length (default 20), the require_* class flags, exclude_chars,
// start_class (first character's class) and end_literal (required suffix).
//
// It builds the password by construction rather than rejection-sampling: one
// rune per required class is seeded into the body up front (pickRune from that
// class's set), then the rest is filled and the whole body shuffled — so every
// required class is guaranteed present without ever generating-and-checking-
// and-retrying a candidate. The generated value MUST NEVER be logged or
// audited.
//
//nolint:gocognit,gocyclo // pre-existing complexity
func GeneratePassword(p *vaultv1.PasswordPolicy) (string, error) {
	minLen := defaultPasswordLen
	maxLen := 0 // 0 = no maximum
	var reqUpper, reqLower, reqDigit, reqSymbol bool
	var exclude, startClass, endLiteral string
	if p != nil {
		if p.GetMinLength() > 0 {
			minLen = int(p.GetMinLength())
		}
		if p.MaxLength != nil && p.GetMaxLength() > 0 {
			maxLen = int(p.GetMaxLength())
		}
		reqUpper, reqLower = p.GetRequireUpper(), p.GetRequireLower()
		reqDigit, reqSymbol = p.GetRequireDigit(), p.GetRequireSymbol()
		exclude, startClass, endLiteral = p.GetExcludeChars(), p.GetStartClass(), p.GetEndLiteral()
	}

	upper := stripExcluded(classUpper, exclude)
	lower := stripExcluded(classLower, exclude)
	digit := stripExcluded(classDigit, exclude)
	symbol := stripExcluded(classSymbol, exclude)

	// Required classes must each contribute at least one rune; error if excludes
	// emptied a required class (unsatisfiable) rather than looping forever.
	type reqClass struct {
		name string
		set  []rune
	}
	var required []reqClass
	addReq := func(on bool, name, set string) error {
		if !on {
			return nil
		}
		if len(set) == 0 {
			return fmt.Errorf("pwgen: required %s class is empty after exclude_chars", name)
		}
		required = append(required, reqClass{name, []rune(set)})
		return nil
	}
	if err := addReq(reqUpper, "upper", upper); err != nil {
		return "", err
	}
	if err := addReq(reqLower, "lower", lower); err != nil {
		return "", err
	}
	if err := addReq(reqDigit, "digit", digit); err != nil {
		return "", err
	}
	if err := addReq(reqSymbol, "symbol", symbol); err != nil {
		return "", err
	}

	// The fill pool is the union of required classes; when none are required, all
	// four classes (whichever survive exclude_chars).
	var pool []rune
	if len(required) > 0 {
		for _, c := range required {
			pool = append(pool, c.set...)
		}
	} else {
		pool = append(pool, []rune(upper)...)
		pool = append(pool, []rune(lower)...)
		pool = append(pool, []rune(digit)...)
		pool = append(pool, []rune(symbol)...)
	}
	if len(pool) == 0 {
		return "", fmt.Errorf("pwgen: no characters available (all excluded)")
	}

	// Resolve the start-class pool (first character). Empty startClass or "any"
	// means the start rune is drawn from the full pool like any other.
	startPool, err := startClassPool(startClass, upper, lower, digit, symbol)
	if err != nil {
		return "", err
	}

	literalRunes := []rune(endLiteral)
	fixed := len(literalRunes)
	if len(startPool) > 0 {
		fixed++ // one reserved position for the start rune
	}

	// Minimum length needed to fit the fixed positions plus one rune per required
	// class. A start rune that already matches a required class saves a seed slot,
	// but we conservatively size for all seeds (they land in the body).
	needBody := len(required)
	requiredMin := fixed + needBody
	lowerBound := minLen
	if lowerBound < requiredMin {
		lowerBound = requiredMin
	}
	upperBound := lowerBound
	if maxLen > 0 {
		if maxLen < requiredMin {
			return "", fmt.Errorf("pwgen: max_length %d too small for policy constraints (need %d)", maxLen, requiredMin)
		}
		if maxLen < lowerBound {
			// min>max: clamp to max (max wins as the hard ceiling).
			lowerBound = maxLen
		}
		upperBound = maxLen
	}

	L, err := randInt(upperBound - lowerBound + 1)
	if err != nil {
		return "", err
	}
	total := lowerBound + L

	bodyLen := total - fixed
	if bodyLen < needBody {
		bodyLen = needBody
	}

	// Build the body: one guaranteed rune per required class, then random fill.
	body := make([]rune, 0, bodyLen)
	for _, c := range required {
		r, err := pickRune(c.set)
		if err != nil {
			return "", err
		}
		body = append(body, r)
	}
	for len(body) < bodyLen {
		r, err := pickRune(pool)
		if err != nil {
			return "", err
		}
		body = append(body, r)
	}
	if err := shuffle(body); err != nil {
		return "", err
	}

	var out []rune
	if len(startPool) > 0 {
		startRune, err := pickRune(startPool)
		if err != nil {
			return "", err
		}
		out = append(out, startRune)
	}
	out = append(out, body...)
	out = append(out, literalRunes...)
	return string(out), nil
}

// startClassPool maps a start_class value to its candidate runes. "" and "any"
// return nil (no dedicated start position — the first rune is just part of the
// body). "letter" spans upper+lower. Unknown values are rejected.
func startClassPool(class, upper, lower, digit, symbol string) ([]rune, error) {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case "", "any":
		return nil, nil
	case "letter", "alpha":
		set := []rune(upper + lower)
		if len(set) == 0 {
			return nil, fmt.Errorf("pwgen: start_class letter is empty after exclude_chars")
		}
		return set, nil
	case "upper":
		if len(upper) == 0 {
			return nil, fmt.Errorf("pwgen: start_class upper is empty after exclude_chars")
		}
		return []rune(upper), nil
	case "lower":
		if len(lower) == 0 {
			return nil, fmt.Errorf("pwgen: start_class lower is empty after exclude_chars")
		}
		return []rune(lower), nil
	case "digit", "number":
		if len(digit) == 0 {
			return nil, fmt.Errorf("pwgen: start_class digit is empty after exclude_chars")
		}
		return []rune(digit), nil
	case "symbol":
		if len(symbol) == 0 {
			return nil, fmt.Errorf("pwgen: start_class symbol is empty after exclude_chars")
		}
		return []rune(symbol), nil
	default:
		return nil, fmt.Errorf("pwgen: unknown start_class %q", class)
	}
}

func stripExcluded(set, exclude string) string {
	if exclude == "" {
		return set
	}
	var b strings.Builder
	for _, r := range set {
		if !strings.ContainsRune(exclude, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// randInt returns a uniform int in [0,n) using crypto/rand. n<=1 yields 0.
func randInt(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func pickRune(set []rune) (rune, error) {
	i, err := randInt(len(set))
	if err != nil {
		return 0, err
	}
	return set[i], nil
}

// shuffle is a crypto/rand Fisher-Yates shuffle in place.
func shuffle(rs []rune) error {
	for i := len(rs) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return err
		}
		rs[i], rs[j] = rs[j], rs[i]
	}
	return nil
}
