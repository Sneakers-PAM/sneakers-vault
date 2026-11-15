// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TLS certificate pins (Sneakers-PAM/sneakers-connector#75): the SHA-256
// fingerprints of the certificates the connector accepts for a target's TLS
// connections, stored bare as 64 lowercase hex digits.

// maxTLSPinsPerTarget matches the SSH host key limit: room for a leaf and a
// CA, each across a renewal, and more.
const maxTLSPinsPerTarget = 16

// sha256HexLen is a SHA-256 digest written in hex.
const sha256HexLen = 64

// normalizeTLSPins validates a target's TLS certificate pins and returns them
// as bare lowercase hex, with repeats dropped. Each entry is 64 hex digits,
// optionally prefixed "sha256:" (any case) and with colons between bytes, as
// openssl prints them. Errors name the entry by position only, never echo it.
func normalizeTLSPins(in []string) ([]string, error) {
	if len(in) > maxTLSPinsPerTarget {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d TLS certificate pins per target", maxTLSPinsPerTarget)
	}
	out := make([]string, 0, len(in))
	for i, raw := range in {
		pos := i + 1
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, status.Errorf(codes.InvalidArgument, "TLS certificate pin %d is empty", pos)
		}
		if len(entry) > len("sha256:") && strings.EqualFold(entry[:len("sha256:")], "sha256:") {
			entry = entry[len("sha256:"):]
		}
		entry = strings.ToLower(strings.ReplaceAll(entry, ":", ""))
		if len(entry) != sha256HexLen {
			return nil, status.Errorf(codes.InvalidArgument, "TLS certificate pin %d is not a SHA-256 fingerprint (64 hex digits)", pos)
		}
		if _, err := hex.DecodeString(entry); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "TLS certificate pin %d is not a SHA-256 fingerprint (64 hex digits)", pos)
		}
		if !slices.Contains(out, entry) {
			out = append(out, entry)
		}
	}
	return out, nil
}

// applyTLSPins validates the requested pins against the stored ones, gates a
// change to a person who may pin them, and returns the canonical list plus
// the audit attributes of the change (nil when the pins are unchanged).
// ownerUserID is the target's owner: empty for a shared one. The rule is the
// SSH host key rule (sneakers-web#318): a site admin on any target, or the
// owner of a personal target; never a token.
func applyTLSPins(actor *vaultv1.ActorContext, ownerUserID string, before, requested []string) ([]string, map[string]string, error) {
	pins, err := normalizeTLSPins(requested)
	if err != nil {
		return nil, nil, err
	}
	added, removed := hostKeyDiff(before, pins)
	if len(added) == 0 && len(removed) == 0 {
		return pins, nil, nil
	}
	if !isHumanUser(actor) {
		// Pinning decides which server a credential may be sent to, so it
		// stays with a person, an admin's token included.
		return nil, nil, refuse(ReasonTLSPinsPersonOnly,
			"TLS certificate pins are set by a person in the web app. "+
				"An agent's token can't change them, even an admin's.")
	}
	if !mayPinHostKeys(actor, ownerUserID) {
		return nil, nil, refuse(ReasonTLSPinsNotOwner,
			"TLS certificate pins on a personal target are set by its owner, and on a shared target by a site admin.")
	}
	return pins, map[string]string{
		"added":   strings.Join(added, ","),
		"removed": strings.Join(removed, ","),
	}, nil
}

// targetPins is what a target save does to its SSH host key and TLS
// certificate pins: the canonical lists and each change's audit attributes.
type targetPins struct {
	keys, tlsPins        []string
	keyChange, tlsChange map[string]string
}

// applyTargetPins runs applyHostKeys and applyTLSPins for SaveTarget, logging
// a refusal. stored is the saved target (its id, owner and pins), or for a
// new target one carrying only the owner it will get.
func (s *Server) applyTargetPins(ctx context.Context, actor *vaultv1.ActorContext, stored, in *vaultv1.Target) (targetPins, error) {
	var p targetPins
	var err error
	refused := func(what string) (targetPins, error) {
		s.lg(ctx).Warn("target save refused: "+what, log.F("target_id", stored.GetId()),
			log.F("actor_user_id", actor.GetUserId()), log.F("reason", status.Convert(err).Message()))
		return targetPins{}, err
	}
	if p.keys, p.keyChange, err = applyHostKeys(actor, stored.GetOwnerUserId(), stored.GetSshHostKeys(), in.GetSshHostKeys()); err != nil {
		return refused("SSH host keys")
	}
	if p.tlsPins, p.tlsChange, err = applyTLSPins(actor, stored.GetOwnerUserId(), stored.GetTlsCertPins(), in.GetTlsCertPins()); err != nil {
		return refused("TLS certificate pins")
	}
	return p, nil
}

// auditTLSPinChange records a pin change as target.tls_cert_pins.change, with
// the fingerprints added and removed. A nil change records nothing.
func (s *Server) auditTLSPinChange(ctx context.Context, actor *vaultv1.ActorContext, targetID string, change map[string]string) {
	if change == nil {
		return
	}
	s.lg(ctx).Info("target TLS certificate pins changed", log.F("target_id", targetID), log.F("actor_user_id", actor.GetUserId()),
		log.F("added", change["added"]), log.F("removed", change["removed"]))
	s.emitAttrs(ctx, actor.GetUserId(), "target.tls_cert_pins.change", targetID, false, change)
}

// ---- persistence ------------------------------------------------------------

// loadTargetTLSPins hydrates each target's TLS pins from target_tls_cert_pins,
// in saved order.
func loadTargetTLSPins(ctx context.Context, q postgres.Querier, st *state) error {
	rows, err := q.Query(ctx, "SELECT target_id, fingerprint FROM target_tls_cert_pins ORDER BY target_id, ordinal")
	if err != nil {
		return fmt.Errorf("select target_tls_cert_pins: %w", err)
	}
	defer rows.Close()
	byTarget := map[string][]string{}
	for rows.Next() {
		var targetID, fp string
		if err := rows.Scan(&targetID, &fp); err != nil {
			return err
		}
		byTarget[targetID] = append(byTarget[targetID], fp)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range st.targets {
		t.TlsCertPins = byTarget[t.GetId()]
	}
	return nil
}

// persistTargetTLSPins replaces target_tls_cert_pins from st.
func persistTargetTLSPins(ctx context.Context, tx postgres.Tx, st *state) error {
	if _, err := tx.Exec(ctx, "DELETE FROM target_tls_cert_pins"); err != nil {
		return fmt.Errorf("clear target_tls_cert_pins: %w", err)
	}
	for _, t := range st.targets {
		for pos, fp := range t.GetTlsCertPins() {
			if _, err := tx.Exec(ctx,
				"INSERT INTO target_tls_cert_pins (target_id, ordinal, fingerprint) VALUES ($1,$2,$3)",
				t.GetId(), pos, fp); err != nil {
				return fmt.Errorf("insert target_tls_cert_pins: %w", err)
			}
		}
	}
	return nil
}
