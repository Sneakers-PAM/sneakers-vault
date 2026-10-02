// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ListAvailableExtensions returns catalogued packs not yet installed as types.
func (s *Server) ListAvailableExtensions(_ context.Context, _ *vaultv1.ListAvailableExtensionsRequest) (*vaultv1.ListAvailableExtensionsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*vaultv1.SecretType, 0, len(s.extCatalog))
	for _, e := range s.extCatalog {
		if s.findType(e.GetId()) == nil {
			out = append(out, proto.Clone(e).(*vaultv1.SecretType))
		}
	}
	return &vaultv1.ListAvailableExtensionsResponse{Extensions: out}, nil
}

// ImportExtension installs a catalogued pack by id as an EXTENSION-origin type.
func (s *Server) ImportExtension(ctx context.Context, req *vaultv1.ImportExtensionRequest) (*vaultv1.ImportExtensionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findType(req.GetId()) != nil {
		return nil, status.Error(codes.AlreadyExists, "extension already installed")
	}
	ext := findByID(s.extCatalog, req.GetId())
	if ext == nil {
		return nil, errNotFound("extension")
	}
	t := proto.Clone(ext).(*vaultv1.SecretType)
	t.Origin = vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION
	s.types = append(s.types, t)
	s.emit(ctx, req.GetActor().GetUserId(), "extension.import", t.GetId(), false)
	return &vaultv1.ImportExtensionResponse{Type: t}, nil
}

// extPack is the JSON shape of a pasted extension pack (mirrors the UI SecretType).
type extPack struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Vendor    string `json:"vendor"`
	Heartbeat bool   `json:"heartbeat"`
	Checkout  bool   `json:"checkout"`
	Fields    []struct {
		Key          string   `json:"key"`
		Label        string   `json:"label"`
		Kind         string   `json:"kind"`
		Options      []string `json:"options"`
		DefaultValue string   `json:"defaultValue"`
		Required     bool     `json:"required"`
		Sensitive    bool     `json:"sensitive"`
	} `json:"fields"`
}

func kindFromString(s string) vaultv1.FieldKind {
	switch s {
	case "multiline":
		return vaultv1.FieldKind_FIELD_KIND_MULTILINE
	case "password":
		return vaultv1.FieldKind_FIELD_KIND_PASSWORD
	case "boolean":
		return vaultv1.FieldKind_FIELD_KIND_BOOLEAN
	case "select":
		return vaultv1.FieldKind_FIELD_KIND_SELECT
	case "file":
		return vaultv1.FieldKind_FIELD_KIND_FILE
	default:
		return vaultv1.FieldKind_FIELD_KIND_TEXT
	}
}

// ImportExtensionFromJson validates a pasted pack and installs it as an
// EXTENSION-origin type, so an import can never masquerade as an editable custom.
func (s *Server) ImportExtensionFromJson(ctx context.Context, req *vaultv1.ImportExtensionFromJsonRequest) (*vaultv1.ImportExtensionFromJsonResponse, error) {
	var p extPack
	if err := json.Unmarshal([]byte(req.GetJson()), &p); err != nil {
		return nil, status.Error(codes.InvalidArgument, "not valid JSON")
	}
	if p.Name == "" || len(p.Fields) == 0 {
		return nil, status.Error(codes.InvalidArgument, `extension pack must have a "name" and a non-empty "fields" array`)
	}
	fields := make([]*vaultv1.SecretFieldDef, 0, len(p.Fields))
	for _, f := range p.Fields {
		if f.Key == "" || f.Label == "" || f.Kind == "" {
			return nil, status.Error(codes.InvalidArgument, "each field needs a key, label, and kind")
		}
		fields = append(fields, &vaultv1.SecretFieldDef{
			Key: f.Key, Label: f.Label, Kind: kindFromString(f.Kind), Options: f.Options,
			DefaultValue: f.DefaultValue, Required: f.Required, Sensitive: f.Sensitive,
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := p.ID
	if id == "" {
		id = s.nextID("ext-import")
	}
	if s.findType(id) != nil {
		return nil, status.Error(codes.AlreadyExists, "a type with this id is already installed")
	}
	vendor := p.Vendor
	if vendor == "" {
		vendor = "Imported"
	}
	t := &vaultv1.SecretType{
		Id: id, Name: p.Name, Fields: fields, Heartbeat: p.Heartbeat, Checkout: p.Checkout,
		Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION, Vendor: vendor,
	}
	s.types = append(s.types, t)
	s.emit(ctx, req.GetActor().GetUserId(), "extension.import", t.GetId(), false)
	return &vaultv1.ImportExtensionFromJsonResponse{Type: t}, nil
}
