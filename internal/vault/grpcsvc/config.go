// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ---- Connections ------------------------------------------------------------

func (s *Server) ListConnections(_ context.Context, _ *vaultv1.ListConnectionsRequest) (*vaultv1.ListConnectionsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*vaultv1.Connection, 0, len(s.connections))
	for _, c := range s.connections {
		cp := proto.Clone(c).(*vaultv1.Connection)
		cp.TargetCount = s.countTargetsFor(c.GetId())
		out = append(out, cp)
	}
	return &vaultv1.ListConnectionsResponse{Connections: out}, nil
}

func (s *Server) countTargetsFor(connID string) int32 {
	var n int32
	for _, t := range s.targets {
		for _, c := range targetConnections(t) {
			if c.GetConnectionId() == connID {
				n++
				break
			}
		}
	}
	return n
}

func (s *Server) countSecretsFor(targetID string) int32 {
	var n int32
	for _, sec := range s.secrets {
		if sec.GetTargetId() == targetID {
			n++
		}
	}
	return n
}

func (s *Server) SaveConnection(ctx context.Context, req *vaultv1.SaveConnectionRequest) (*vaultv1.SaveConnectionResponse, error) {
	in := req.GetConnection()
	if in == nil || in.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "connection name is required")
	}
	// Connections are shared infrastructure, managed in the admin app only.
	if err := s.requireSiteAdmin(ctx, req.GetActor(), "SaveConnection"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.GetId() == "" {
		if id := in.GetPrivilegedSecretId(); id != "" && findByID(s.secrets, id) == nil {
			return nil, errNotFound("privileged secret")
		}
		in.Id = s.nextID("conn")
		s.connections = append(s.connections, in)
	} else {
		existing := findByID(s.connections, in.GetId())
		if existing == nil {
			return nil, errNotFound("connection")
		}
		existing.Name, existing.Protocol, existing.Port = in.GetName(), in.GetProtocol(), in.GetPort()
		existing.UseTls, existing.Description = in.GetUseTls(), in.GetDescription()
		// The gateway's ConnectionInput has no linkage fields, so every edit from
		// the admin app arrives with them empty; empty must keep the stored value.
		if id := in.GetTargetId(); id != "" {
			existing.TargetId = id
		}
		if id := in.GetPrivilegedSecretId(); id != "" && id != existing.GetPrivilegedSecretId() {
			if findByID(s.secrets, id) == nil {
				return nil, errNotFound("privileged secret")
			}
			s.emitAttrs(ctx, req.GetActor().GetUserId(), "connection.privileged_secret.change", existing.GetId(), false,
				map[string]string{"from": existing.GetPrivilegedSecretId(), "to": id})
			existing.PrivilegedSecretId = id
		}
		in = existing
	}
	s.emit(ctx, req.GetActor().GetUserId(), "connection.save", in.GetId(), false)
	return &vaultv1.SaveConnectionResponse{Connection: in}, nil
}

func (s *Server) DeleteConnection(ctx context.Context, req *vaultv1.DeleteConnectionRequest) (*vaultv1.DeleteConnectionResponse, error) {
	if !isHumanAdmin(req.GetActor()) {
		return nil, status.Error(codes.PermissionDenied, "connections are managed by a site admin")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		for _, c := range targetConnections(t) {
			if c.GetConnectionId() == req.GetId() {
				return &vaultv1.DeleteConnectionResponse{Removed: false}, nil
			}
		}
	}
	s.connections = removeByID(s.connections, req.GetId())
	s.emit(ctx, req.GetActor().GetUserId(), "connection.delete", req.GetId(), false)
	return &vaultv1.DeleteConnectionResponse{Removed: true}, nil
}

// ---- Targets ----------------------------------------------------------------

// ListTargets returns shared targets (owner_user_id empty) plus only the
// actor's OWN personal targets; a site-admin/root sees every target. Another
// user's personal targets are never listed for a normal user.
func (s *Server) ListTargets(_ context.Context, req *vaultv1.ListTargetsRequest) (*vaultv1.ListTargetsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	actor := req.GetActor()
	admin := isHumanAdmin(actor)
	out := make([]*vaultv1.Target, 0, len(s.targets))
	for _, t := range s.targets {
		if !admin && t.GetOwnerUserId() != "" && t.GetOwnerUserId() != actor.GetUserId() {
			continue
		}
		cp := proto.Clone(t).(*vaultv1.Target)
		cp.SecretCount = s.countSecretsFor(t.GetId())
		out = append(out, withResolvedConnections(cp))
	}
	return &vaultv1.ListTargetsResponse{Targets: out}, nil
}

func (s *Server) SaveTarget(ctx context.Context, req *vaultv1.SaveTargetRequest) (*vaultv1.SaveTargetResponse, error) {
	in := req.GetTarget()
	if in == nil || in.GetName() == "" || in.GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "target name, hostname, and connection are required")
	}
	actor := req.GetActor()
	admin := isHumanAdmin(actor)
	// A target is personal to the user who makes it; a principal with no user
	// (a service account) would otherwise publish a shared one.
	if !actsAsUser(actor) {
		return nil, status.Error(codes.PermissionDenied, "targets are created by a user or that user's token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var hostKeyChange map[string]string
	if in.GetId() == "" {
		conns, defaultConnID, err := resolveTargetConnections(s.connections, nil, in)
		if err != nil {
			return nil, err
		}
		keys, change, err := applyHostKeys(actor, nil, in.GetSshHostKeys())
		if err != nil {
			s.lg(ctx).Warn("target save refused: SSH host keys", log.F("actor_user_id", actor.GetUserId()), log.F("reason", status.Convert(err).Message()))
			return nil, err
		}
		in.SshHostKeys, hostKeyChange = keys, change
		in.Id = s.nextID("target")
		in.Connections, in.ConnectionId = conns, defaultConnID //nolint:staticcheck // the deprecated field is the intentional alias this keeps in sync
		// A non-admin's target is personal (owned by the actor); an admin's is
		// shared (owner left empty). The caller cannot spoof another owner.
		if admin {
			in.OwnerUserId = ""
		} else {
			in.OwnerUserId = actor.GetUserId()
		}
		s.targets = append(s.targets, in)
	} else {
		existing := findByID(s.targets, in.GetId())
		if existing == nil {
			return nil, errNotFound("target")
		}
		// Editing a personal target is restricted to its owner or a site-admin/root;
		// the owner is preserved (never reassigned via an edit).
		if !admin && existing.GetOwnerUserId() != actor.GetUserId() {
			return nil, status.Error(codes.PermissionDenied, "not permitted to edit this target")
		}
		conns, defaultConnID, err := resolveTargetConnections(s.connections, existing, in)
		if err != nil {
			return nil, err
		}
		keys, change, err := applyHostKeys(actor, existing.GetSshHostKeys(), in.GetSshHostKeys())
		if err != nil {
			s.lg(ctx).Warn("target save refused: SSH host keys", log.F("target_id", existing.GetId()),
				log.F("actor_user_id", actor.GetUserId()), log.F("reason", status.Convert(err).Message()))
			return nil, err
		}
		existing.SshHostKeys, hostKeyChange = keys, change
		existing.Name, existing.Hostname = in.GetName(), in.GetHostname()
		existing.Connections, existing.ConnectionId = conns, defaultConnID //nolint:staticcheck // the deprecated field is the intentional alias this keeps in sync
		existing.Description = in.GetDescription()
		existing.Kind, existing.Domain, existing.Realm = in.GetKind(), in.GetDomain(), in.GetRealm()
		in = existing
	}
	s.emit(ctx, req.GetActor().GetUserId(), "target.save", in.GetId(), false)
	if hostKeyChange != nil {
		s.lg(ctx).Info("target SSH host keys changed", log.F("target_id", in.GetId()), log.F("actor_user_id", actor.GetUserId()),
			log.F("added", hostKeyChange["added"]), log.F("removed", hostKeyChange["removed"]))
		s.emitAttrs(ctx, actor.GetUserId(), "target.host_keys.change", in.GetId(), false, hostKeyChange)
	}
	return &vaultv1.SaveTargetResponse{Target: in}, nil
}

func (s *Server) DeleteTarget(ctx context.Context, req *vaultv1.DeleteTargetRequest) (*vaultv1.DeleteTargetResponse, error) {
	actor := req.GetActor()
	admin := isHumanAdmin(actor)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := findByID(s.targets, req.GetId()); existing != nil &&
		!admin && (!actsAsUser(actor) || existing.GetOwnerUserId() == "" || existing.GetOwnerUserId() != actor.GetUserId()) {
		return nil, status.Error(codes.PermissionDenied, "not permitted to delete this target")
	}
	for _, sec := range s.secrets {
		if sec.TargetId == req.GetId() {
			return &vaultv1.DeleteTargetResponse{Removed: false}, nil
		}
	}
	s.targets = removeByID(s.targets, req.GetId())
	// Drop the target's own RACI ruleset too — otherwise its grants
	// linger in memory (and get re-persisted on the next snapshot) even though
	// the target they were scoped to no longer exists.
	delete(s.targetRulesets, req.GetId())
	s.emit(ctx, req.GetActor().GetUserId(), "target.delete", req.GetId(), false)
	return &vaultv1.DeleteTargetResponse{Removed: true}, nil
}

// actsAsUser reports a caller that stands for a user: a person, or that
// person's own token. A service account or workload never does, whatever user
// id its ActorContext carries.
func actsAsUser(a *vaultv1.ActorContext) bool {
	if a.GetUserId() == "" {
		return false
	}
	k := a.GetPrincipalKind()
	return k == vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || k == vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
}

// ---- tiny generic helpers ---------------------------------------------------

type ided interface{ GetId() string }

func findByID[T ided](xs []T, id string) T {
	for _, x := range xs {
		if x.GetId() == id {
			return x
		}
	}
	var zero T
	return zero
}

func removeByID[T ided](xs []T, id string) []T {
	out := xs[:0]
	for _, x := range xs {
		if x.GetId() != id {
			out = append(out, x)
		}
	}
	return out
}
