// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// targetConnections returns t's ordered connection list: the stored list when
// set, or — for a target saved before this field existed — a synthesized
// one-item list built from the legacy connection_id, marked default. Read
// paths use this instead of t.GetConnections() directly, so an old target is
// never seen as having no connection.
func targetConnections(t *vaultv1.Target) []*vaultv1.TargetConnection {
	if len(t.GetConnections()) > 0 {
		return t.GetConnections()
	}
	if t.GetConnectionId() == "" {
		return nil
	}
	return []*vaultv1.TargetConnection{{ConnectionId: t.GetConnectionId(), IsDefault: true}}
}

// defaultConnectionID returns the connection id of t's default connection, the
// one a session starts on unless the caller names another.
func defaultConnectionID(t *vaultv1.Target) string {
	cs := targetConnections(t)
	for _, c := range cs {
		if c.GetIsDefault() {
			return c.GetConnectionId()
		}
	}
	if len(cs) > 0 {
		return cs[0].GetConnectionId()
	}
	return ""
}

// withResolvedConnections fills in t's connections list and legacy
// connection_id alias for a response: the stored or synthesized list, and the
// default entry's connection id. Callers hand it a clone, never the stored
// target, since it mutates the struct it's given.
func withResolvedConnections(t *vaultv1.Target) *vaultv1.Target {
	t.Connections = targetConnections(t)
	t.ConnectionId = defaultConnectionID(t) //nolint:staticcheck // the deprecated field is the intentional alias this keeps in sync
	return t
}

// retarget returns a copy of base with the default moved to the entry whose
// connection id is connID, which must already be present in base.
func retarget(base []*vaultv1.TargetConnection, connID string) []*vaultv1.TargetConnection {
	out := make([]*vaultv1.TargetConnection, len(base))
	for i, c := range base {
		out[i] = &vaultv1.TargetConnection{ConnectionId: c.GetConnectionId(), IsDefault: c.GetConnectionId() == connID}
	}
	return out
}

// legacyConnectionList builds the connections list a save request implies
// when it names no list at all, just the legacy connection_id: a one-item
// default list on a create, or — on an edit whose target already carries
// connID — that target's own list with the default moved to connID, so the
// legacy path can't silently drop a target's other connections. A
// connID existing doesn't have replaces the list wholesale, same as a create.
func legacyConnectionList(existing *vaultv1.Target, connID string) ([]*vaultv1.TargetConnection, error) {
	if connID == "" {
		return nil, status.Error(codes.InvalidArgument, "target name, hostname, and connection are required")
	}
	if existing != nil {
		for _, c := range targetConnections(existing) {
			if c.GetConnectionId() == connID {
				return retarget(targetConnections(existing), connID), nil
			}
		}
	}
	return []*vaultv1.TargetConnection{{ConnectionId: connID, IsDefault: true}}, nil
}

// normalizeTargetConnections validates a save request's connection list
// against the known connections and returns the canonical ordered list to
// store: every id resolved to a live Connection, no two entries sharing a
// connector protocol, and exactly one marked default.
//
// When the request's connections list is empty, it falls back to the legacy
// connection_id alias: on a create, that becomes a one-item list; on an edit
// (existing non-nil), it just moves the default to that id within existing's
// current list when existing already has it, so an old caller that only
// knows connection_id can't silently drop a target's other connections. A
// connection_id that existing doesn't have replaces the list wholesale, same
// as a create — the caller is pointing the target at a connection it never
// had.
func normalizeTargetConnections(conns []*vaultv1.Connection, existing, in *vaultv1.Target) ([]*vaultv1.TargetConnection, error) {
	given := in.GetConnections()
	if len(given) == 0 {
		var err error
		given, err = legacyConnectionList(existing, in.GetConnectionId())
		if err != nil {
			return nil, err
		}
	}
	out := make([]*vaultv1.TargetConnection, 0, len(given))
	protocols := make(map[string]string, len(given)) // protocol -> connection id that claimed it
	defaults := 0
	for _, c := range given {
		conn := findByID(conns, c.GetConnectionId())
		if conn == nil {
			return nil, errNotFound("connection")
		}
		if owner, dup := protocols[conn.GetProtocol()]; dup {
			return nil, status.Errorf(codes.InvalidArgument,
				"target connections %s and %s both use the %s protocol", owner, c.GetConnectionId(), conn.GetProtocol())
		}
		protocols[conn.GetProtocol()] = c.GetConnectionId()
		isDefault := c.GetIsDefault()
		if len(given) == 1 {
			// A single connection is always the target's default, whatever
			// the request set.
			isDefault = true
		}
		if isDefault {
			defaults++
		}
		out = append(out, &vaultv1.TargetConnection{ConnectionId: c.GetConnectionId(), IsDefault: isDefault})
	}
	if defaults != 1 {
		return nil, status.Error(codes.InvalidArgument, "a target must have exactly one default connection")
	}
	return out, nil
}

// resolveTargetConnections normalizes a save request's connections (see
// normalizeTargetConnections) and returns the list alongside its default
// entry's connection id, for callers that need both.
func resolveTargetConnections(conns []*vaultv1.Connection, existing, in *vaultv1.Target) ([]*vaultv1.TargetConnection, string, error) {
	out, err := normalizeTargetConnections(conns, existing, in)
	if err != nil {
		return nil, "", err
	}
	var defaultConnID string
	for _, c := range out {
		if c.GetIsDefault() {
			defaultConnID = c.GetConnectionId()
		}
	}
	return out, defaultConnID, nil
}
