// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
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
	if err := s.requireSiteAdmin(ctx, req.GetActor(), "ImportExtension"); err != nil {
		return nil, err
	}
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

// tokenClientMCP is identity's client_kind for an MCP agent token.
const tokenClientMCP = "mcp"

// extensionImportSource says where a token's import came from, for the audit
// record: the MCP for an MCP agent token, the machine API for any other.
func extensionImportSource(a *vaultv1.ActorContext) string {
	if a.GetTokenClientKind() == tokenClientMCP {
		return "mcp"
	}
	return "machine_api"
}

// ImportExtensionForPrincipal installs a catalogued pack for a personal token
// whose owner is a site admin or root. The owner's role is the one the gateway
// resolved from identity; the token's own admin flags still count for nothing.
// A type-catalogue change by a token is admin authority used outside a person's
// session, so it lands in the tamper-evident tier and fails closed: no record,
// no activation. Pasted packs stay off this path (ImportExtensionFromJson).
func (s *Server) ImportExtensionForPrincipal(ctx context.Context, req *vaultv1.ImportExtensionForPrincipalRequest) (*vaultv1.ImportExtensionForPrincipalResponse, error) {
	actor := req.GetActor()
	if err := requireNonHuman(actor, "extension import"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lg(ctx)
	ext := findByID(s.extCatalog, req.GetId())
	if !isUserToken(actor) || actor.GetUserId() == "" || !actor.GetTokenOwnerIsSiteAdmin() {
		// The id is the caller's text until the catalogue knows it.
		subject := "vault"
		if ext != nil {
			subject = ext.GetId()
		}
		return nil, s.deny(ctx, actor, "ImportExtensionForPrincipal", subject, ReasonNotSiteAdmin, "this needs a site admin")
	}
	if s.findType(req.GetId()) != nil {
		l.Debug("principal extension import refused: already installed", log.F("extension_id", req.GetId()), log.F("user_id", actor.GetUserId()))
		return nil, status.Error(codes.AlreadyExists, "extension already installed")
	}
	if ext == nil {
		l.Debug("principal extension import refused: not catalogued", log.F("user_id", actor.GetUserId()), log.F("token_id", actor.GetTokenId()))
		return nil, errNotFound("extension")
	}
	source := extensionImportSource(actor)
	if err := s.emitTierErr(ctx, audit.TierAudit, principalActorID(actor), "extension.import.principal", ext.GetId(), false, principalAttrs(actor, map[string]string{
		"name": ext.GetName(), "source": source,
	})); err != nil {
		l.Error(err, "principal extension import stopped: no audit record", log.F("extension_id", ext.GetId()), log.F("user_id", actor.GetUserId()))
		return nil, status.Errorf(codes.Internal, "record extension import audit: %v", err)
	}
	t := proto.Clone(ext).(*vaultv1.SecretType)
	t.Origin = vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION
	s.types = append(s.types, t)
	l.Info("principal activated an extension pack", log.F("extension_id", t.GetId()), log.F("user_id", actor.GetUserId()),
		log.F("token_id", actor.GetTokenId()), log.F("source", source))
	return &vaultv1.ImportExtensionForPrincipalResponse{Type: t}, nil
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
	if err := s.requireSiteAdmin(ctx, req.GetActor(), "ImportExtensionFromJson"); err != nil {
		return nil, err
	}
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
