// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"slices"
	"strings"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// maxHostKeysPerTarget bounds a target's pin list: a host presents one key per
// algorithm, so a handful covers key rollover with room to spare.
const maxHostKeysPerTarget = 16

// maxHostKeyEntryLen is longer than any real public key line (an RSA-16384 key
// is under 3 KiB) and keeps a pasted blob from bloating every snapshot.
const maxHostKeyEntryLen = 8 << 10

// normalizeHostKeys validates a target's SSH host key pins and returns them in
// canonical "type base64[ comment]" form with duplicates (same key) dropped,
// plus each key's SHA256 fingerprint. Errors name the entry by position only,
// never echo it, since a mistaken paste could be a private key.
func normalizeHostKeys(in []string) (keys, fps []string, err error) {
	if len(in) > maxHostKeysPerTarget {
		return nil, nil, status.Errorf(codes.InvalidArgument, "at most %d SSH host keys per target", maxHostKeysPerTarget)
	}
	for i, raw := range in {
		pos := i + 1
		entry := strings.TrimSpace(raw)
		switch {
		case entry == "":
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d is empty", pos)
		case len(entry) > maxHostKeyEntryLen:
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d is too long", pos)
		case strings.Contains(entry, "PRIVATE KEY"):
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d is a private key; pin the host's public key", pos)
		case strings.ContainsAny(entry, "\r\n"):
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d holds more than one line; send one key per entry", pos)
		}
		pub, comment, options, rest, perr := ssh.ParseAuthorizedKey([]byte(entry))
		switch {
		case perr != nil:
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d is not an OpenSSH public key", pos)
		case len(options) > 0:
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d carries options; send the bare key", pos)
		case len(rest) > 0:
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d holds more than one key", pos)
		}
		if _, isCert := pub.(*ssh.Certificate); isCert {
			return nil, nil, status.Errorf(codes.InvalidArgument, "SSH host key %d is a certificate; pin the host key itself", pos)
		}
		fp := ssh.FingerprintSHA256(pub)
		if slices.Contains(fps, fp) {
			continue
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if comment != "" {
			line += " " + comment
		}
		keys = append(keys, line)
		fps = append(fps, fp)
	}
	return keys, fps, nil
}

// hostKeyFingerprints returns the SHA256 fingerprints of already-validated
// pins. An entry that no longer parses is skipped: it was validated on save.
func hostKeyFingerprints(keys []string) []string {
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err == nil {
			fps = append(fps, ssh.FingerprintSHA256(pub))
		}
	}
	return fps
}

// hostKeyDiff lists the fingerprints in after but not before (added) and in
// before but not after (removed), in their list order.
func hostKeyDiff(before, after []string) (added, removed []string) {
	for _, fp := range after {
		if !slices.Contains(before, fp) {
			added = append(added, fp)
		}
	}
	for _, fp := range before {
		if !slices.Contains(after, fp) {
			removed = append(removed, fp)
		}
	}
	return added, removed
}

// applyHostKeys validates the requested pins against the stored ones, gates a
// change to site admins, and returns the canonical list plus the audit
// attributes of the change (nil when the pins are unchanged).
func applyHostKeys(actor *vaultv1.ActorContext, before, requested []string) ([]string, map[string]string, error) {
	keys, afterFPs, err := normalizeHostKeys(requested)
	if err != nil {
		return nil, nil, err
	}
	added, removed := hostKeyDiff(hostKeyFingerprints(before), afterFPs)
	if len(added) == 0 && len(removed) == 0 {
		return keys, nil, nil
	}
	if !isHumanAdmin(actor) {
		return nil, nil, status.Error(codes.PermissionDenied, "SSH host keys are set by a site admin")
	}
	return keys, map[string]string{
		"added":   strings.Join(added, ","),
		"removed": strings.Join(removed, ","),
	}, nil
}

// ---- persistence ------------------------------------------------------------

// loadTargetHostKeys hydrates each target's pins from target_ssh_host_keys, in
// saved order. The pins live in their own table, with fingerprints, rather than
// in the target's JSON document.
func loadTargetHostKeys(ctx context.Context, q postgres.Querier, st *state) error {
	rows, err := q.Query(ctx, "SELECT target_id, public_key FROM target_ssh_host_keys ORDER BY target_id, ordinal")
	if err != nil {
		return fmt.Errorf("select target_ssh_host_keys: %w", err)
	}
	defer rows.Close()
	byTarget := map[string][]string{}
	for rows.Next() {
		var targetID, key string
		if err := rows.Scan(&targetID, &key); err != nil {
			return err
		}
		byTarget[targetID] = append(byTarget[targetID], key)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range st.targets {
		t.SshHostKeys = byTarget[t.GetId()]
	}
	return nil
}

// persistTargetHostKeys replaces target_ssh_host_keys from st.
func persistTargetHostKeys(ctx context.Context, tx postgres.Tx, st *state) error {
	if _, err := tx.Exec(ctx, "DELETE FROM target_ssh_host_keys"); err != nil {
		return fmt.Errorf("clear target_ssh_host_keys: %w", err)
	}
	for _, t := range st.targets {
		for pos, key := range t.GetSshHostKeys() {
			fps := hostKeyFingerprints([]string{key})
			if len(fps) != 1 {
				return fmt.Errorf("target %s: SSH host key %d does not parse", t.GetId(), pos+1)
			}
			if _, err := tx.Exec(ctx,
				"INSERT INTO target_ssh_host_keys (target_id, ordinal, public_key, fingerprint) VALUES ($1,$2,$3,$4)",
				t.GetId(), pos, key, fps[0]); err != nil {
				return fmt.Errorf("insert target_ssh_host_keys: %w", err)
			}
		}
	}
	return nil
}

// targetsWithoutHostKeys returns copies of targets with the pins cleared, for
// the targets table's JSON documents (the pins are stored separately).
func targetsWithoutHostKeys(targets []*vaultv1.Target) []*vaultv1.Target {
	out := make([]*vaultv1.Target, len(targets))
	for i, t := range targets {
		if len(t.GetSshHostKeys()) == 0 {
			out[i] = t
			continue
		}
		cp := proto.Clone(t).(*vaultv1.Target)
		cp.SshHostKeys = nil
		out[i] = cp
	}
	return out
}
