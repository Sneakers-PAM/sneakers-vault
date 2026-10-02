// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) ListSecretTypes(_ context.Context, _ *vaultv1.ListSecretTypesRequest) (*vaultv1.ListSecretTypesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &vaultv1.ListSecretTypesResponse{Types: append([]*vaultv1.SecretType(nil), s.types...)}, nil
}

func (s *Server) CreateSecretType(ctx context.Context, req *vaultv1.CreateSecretTypeRequest) (*vaultv1.CreateSecretTypeResponse, error) {
	if req.GetType() == nil || req.GetType().GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "type name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := req.GetType()
	created := &vaultv1.SecretType{
		Id:        s.nextID("type-custom"),
		Name:      t.GetName(),
		Fields:    t.GetFields(),
		Heartbeat: t.GetHeartbeat(),
		Checkout:  t.GetCheckout(),
		Rotation:  t.GetRotation(),
		Origin:    vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM, // created types are always custom
	}
	s.types = append(s.types, created)
	s.emit(ctx, req.GetActor().GetUserId(), "secret_type.create", created.Id, false)
	return &vaultv1.CreateSecretTypeResponse{Type: created}, nil
}

func (s *Server) UpdateSecretType(ctx context.Context, req *vaultv1.UpdateSecretTypeRequest) (*vaultv1.UpdateSecretTypeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findType(req.GetId())
	if t == nil {
		return nil, errNotFound("secret type")
	}
	if origin(t) != vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM {
		return nil, status.Error(codes.FailedPrecondition, "only custom types can be edited")
	}
	in := req.GetType()
	if in.GetName() != "" {
		t.Name = in.GetName()
	}
	if in.GetFields() != nil {
		t.Fields = in.GetFields()
	}
	t.Heartbeat = in.GetHeartbeat()
	t.Checkout = in.GetCheckout()
	t.Rotation = in.GetRotation()
	s.emit(ctx, req.GetActor().GetUserId(), "secret_type.update", t.Id, false)
	return &vaultv1.UpdateSecretTypeResponse{Type: t}, nil
}

func (s *Server) DeleteSecretType(ctx context.Context, req *vaultv1.DeleteSecretTypeRequest) (*vaultv1.DeleteSecretTypeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findType(req.GetId())
	if t == nil {
		return &vaultv1.DeleteSecretTypeResponse{Removed: false}, nil
	}
	if origin(t) == vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
		return nil, status.Error(codes.FailedPrecondition, "built-in types cannot be removed")
	}
	if s.secretTypeUsage(req.GetId()) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "type is in use by a secret")
	}
	s.types = removeType(s.types, req.GetId())
	s.emit(ctx, req.GetActor().GetUserId(), "secret_type.delete", req.GetId(), false)
	return &vaultv1.DeleteSecretTypeResponse{Removed: true}, nil
}

func (s *Server) CloneSecretType(ctx context.Context, req *vaultv1.CloneSecretTypeRequest) (*vaultv1.CloneSecretTypeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.findType(req.GetId())
	if src == nil {
		return nil, errNotFound("secret type")
	}
	clone := &vaultv1.SecretType{
		Id:        s.nextID("type-custom"),
		Name:      src.Name + " (copy)",
		Fields:    append([]*vaultv1.SecretFieldDef(nil), src.Fields...),
		Heartbeat: src.Heartbeat,
		Checkout:  src.Checkout,
		Origin:    vaultv1.TypeOrigin_TYPE_ORIGIN_CUSTOM,
	}
	s.types = append(s.types, clone)
	s.emit(ctx, req.GetActor().GetUserId(), "secret_type.clone", clone.Id, false)
	return &vaultv1.CloneSecretTypeResponse{Type: clone}, nil
}

func (s *Server) secretTypeUsage(id string) int {
	n := 0
	for _, sec := range s.secrets {
		if sec.TypeId == id {
			n++
		}
	}
	return n
}

func removeType(in []*vaultv1.SecretType, id string) []*vaultv1.SecretType {
	out := in[:0]
	for _, t := range in {
		if t.Id != id {
			out = append(out, t)
		}
	}
	return out
}
