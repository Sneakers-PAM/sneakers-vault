// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The gRPC metadata keys a connector stamps its build into on every pull call.
const (
	metadataVersion = "sneakers-version"
	metadataCommit  = "sneakers-commit"
	// maxBuildLen caps a metadata value before it is stored; a build stamp is a
	// short version or commit, never more.
	maxBuildLen = 128
)

// connectorStore keeps one row per connector worker: its build and when the
// vault last heard from it.
type connectorStore struct{ db postgres.Querier }

func newConnectorStore(db postgres.Querier) *connectorStore { return &connectorStore{db: db} }

// Touch records a verified contact from workerID. An empty version or commit
// keeps the value the worker last sent.
func (c *connectorStore) Touch(ctx context.Context, workerID, version, commit string) error {
	_, err := c.db.Exec(ctx,
		`INSERT INTO connector_contacts (worker_id, version, commit, last_contact_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (worker_id) DO UPDATE SET
		   version = COALESCE(NULLIF(EXCLUDED.version, ''), connector_contacts.version),
		   commit = COALESCE(NULLIF(EXCLUDED.commit, ''), connector_contacts.commit),
		   last_contact_at = EXCLUDED.last_contact_at`,
		workerID, version, commit)
	return err
}

// List returns every connector the vault has heard from, by worker id.
func (c *connectorStore) List(ctx context.Context) ([]*vaultv1.ConnectorContact, error) {
	rows, err := c.db.Query(ctx,
		`SELECT worker_id, version, commit, last_contact_at FROM connector_contacts ORDER BY worker_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*vaultv1.ConnectorContact
	for rows.Next() {
		var (
			cc vaultv1.ConnectorContact
			at time.Time
		)
		if err := rows.Scan(&cc.WorkerId, &cc.Version, &cc.Commit, &at); err != nil {
			return nil, err
		}
		cc.LastContactAt = at.UTC().Format(time.RFC3339Nano)
		out = append(out, &cc)
	}
	return out, rows.Err()
}

// buildFromMetadata reads the connector's build stamp from the incoming call.
func buildFromMetadata(ctx context.Context) (version, commit string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}
	first := func(key string) string {
		v := md.Get(key)
		if len(v) == 0 {
			return ""
		}
		if len(v[0]) > maxBuildLen {
			return v[0][:maxBuildLen]
		}
		return v[0]
	}
	return first(metadataVersion), first(metadataCommit)
}

// recordConnectorContact stores a verified worker's build and contact time. A
// failure is logged and never fails the pull call: diagnostics must not stop
// heartbeats or rotations.
func (s *Server) recordConnectorContact(ctx context.Context, workerID string) {
	if s.contacts == nil {
		return
	}
	version, commit := buildFromMetadata(ctx)
	if err := s.contacts.Touch(ctx, workerID, version, commit); err != nil {
		s.lg(ctx).Warn("record connector contact failed", log.F("worker_id", workerID), log.F("error", err.Error()))
		return
	}
	log.Trace(s.lg(ctx), "connector contact recorded",
		log.F("worker_id", workerID), log.F("version", version), log.F("commit", commit))
}

// ListConnectors returns each connector's build and last contact for the
// gateway's diagnostics.
func (s *Server) ListConnectors(ctx context.Context, _ *vaultv1.ListConnectorsRequest) (*vaultv1.ListConnectorsResponse, error) {
	if s.contacts == nil {
		return nil, status.Error(codes.Unavailable, "connector records not configured")
	}
	list, err := s.contacts.List(ctx)
	if err != nil {
		s.lg(ctx).Error(err, "list connectors failed")
		return nil, status.Error(codes.Internal, "list connectors failed")
	}
	s.lg(ctx).Debug("connectors listed", log.F("count", len(list)))
	return &vaultv1.ListConnectorsResponse{Connectors: list}, nil
}
