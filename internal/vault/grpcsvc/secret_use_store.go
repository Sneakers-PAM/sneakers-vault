// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"sync"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var errUseNotFound = errors.New("secret use not found")

// useStore keeps secret use handles and use grants outside the snapshot state:
// handles are short-lived and grants change independently of the vault tree.
type useStore interface {
	PutUse(ctx context.Context, u *vaultv1.SecretUse) error
	GetUse(ctx context.Context, id string) (*vaultv1.SecretUse, error)
	PendingUses(ctx context.Context, userID string) ([]*vaultv1.SecretUse, error)
	PutGrant(ctx context.Context, g *vaultv1.UseGrant) error
	GetGrant(ctx context.Context, id string) (*vaultv1.UseGrant, error)
	GrantsFor(ctx context.Context, userID string) ([]*vaultv1.UseGrant, error)
}

type memUseStore struct {
	mu     sync.Mutex
	uses   map[string]*vaultv1.SecretUse
	grants map[string]*vaultv1.UseGrant
}

func newMemUseStore() *memUseStore {
	return &memUseStore{uses: map[string]*vaultv1.SecretUse{}, grants: map[string]*vaultv1.UseGrant{}}
}

func (m *memUseStore) PutUse(_ context.Context, u *vaultv1.SecretUse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uses[u.GetId()] = proto.Clone(u).(*vaultv1.SecretUse)
	return nil
}

func (m *memUseStore) GetUse(_ context.Context, id string) (*vaultv1.SecretUse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.uses[id]
	if !ok {
		return nil, errUseNotFound
	}
	return proto.Clone(u).(*vaultv1.SecretUse), nil
}

func (m *memUseStore) PendingUses(_ context.Context, userID string) ([]*vaultv1.SecretUse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*vaultv1.SecretUse
	for _, u := range m.uses {
		if u.GetUserId() == userID && u.GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
			out = append(out, proto.Clone(u).(*vaultv1.SecretUse))
		}
	}
	return out, nil
}

func (m *memUseStore) PutGrant(_ context.Context, g *vaultv1.UseGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.GetId()] = proto.Clone(g).(*vaultv1.UseGrant)
	return nil
}

func (m *memUseStore) GetGrant(_ context.Context, id string) (*vaultv1.UseGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, errUseNotFound
	}
	return proto.Clone(g).(*vaultv1.UseGrant), nil
}

func (m *memUseStore) GrantsFor(_ context.Context, userID string) ([]*vaultv1.UseGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*vaultv1.UseGrant
	for _, g := range m.grants {
		if g.GetUserId() == userID {
			out = append(out, proto.Clone(g).(*vaultv1.UseGrant))
		}
	}
	return out, nil
}

type pgUseStore struct{ db postgres.Querier }

// SetSecretUses installs the shared use-handle and use-grant store. Called from
// cmd/vault once the pool is open.
func (s *Server) SetSecretUses(db *postgres.DB) { s.uses = &pgUseStore{db: db.Querier()} }

func (p *pgUseStore) PutUse(ctx context.Context, u *vaultv1.SecretUse) error {
	raw, err := protojson.Marshal(u)
	if err != nil {
		return err
	}
	// Finished handles are only history; drop them a day after they expire.
	if _, err := p.db.Exec(ctx, `DELETE FROM secret_uses WHERE expires_at < now() - interval '1 day'`); err != nil {
		return err
	}
	_, err = p.db.Exec(ctx,
		`INSERT INTO secret_uses (id, user_id, state, expires_at, data) VALUES ($1,$2,$3,to_timestamp($4),$5)
		 ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state, expires_at=EXCLUDED.expires_at, data=EXCLUDED.data`,
		u.GetId(), u.GetUserId(), int32(u.GetState()), u.GetExpiresAtUnix(), raw)
	return err
}

func (p *pgUseStore) GetUse(ctx context.Context, id string) (*vaultv1.SecretUse, error) {
	var raw []byte
	if err := p.db.QueryRow(ctx, `SELECT data FROM secret_uses WHERE id=$1`, id).Scan(&raw); err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, errUseNotFound
		}
		return nil, err
	}
	u := &vaultv1.SecretUse{}
	return u, protojson.Unmarshal(raw, u)
}

func (p *pgUseStore) PendingUses(ctx context.Context, userID string) ([]*vaultv1.SecretUse, error) {
	rows, err := p.db.Query(ctx, `SELECT data FROM secret_uses WHERE user_id=$1 AND state=$2`, userID, int32(vaultv1.SecretUseState_SECRET_USE_STATE_PENDING))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*vaultv1.SecretUse
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		u := &vaultv1.SecretUse{}
		if err := protojson.Unmarshal(raw, u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *pgUseStore) PutGrant(ctx context.Context, g *vaultv1.UseGrant) error {
	raw, err := protojson.Marshal(g)
	if err != nil {
		return err
	}
	_, err = p.db.Exec(ctx,
		`INSERT INTO secret_use_grants (id, user_id, data) VALUES ($1,$2,$3)
		 ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data`, g.GetId(), g.GetUserId(), raw)
	return err
}

func (p *pgUseStore) GetGrant(ctx context.Context, id string) (*vaultv1.UseGrant, error) {
	var raw []byte
	if err := p.db.QueryRow(ctx, `SELECT data FROM secret_use_grants WHERE id=$1`, id).Scan(&raw); err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, errUseNotFound
		}
		return nil, err
	}
	g := &vaultv1.UseGrant{}
	return g, protojson.Unmarshal(raw, g)
}

func (p *pgUseStore) GrantsFor(ctx context.Context, userID string) ([]*vaultv1.UseGrant, error) {
	rows, err := p.db.Query(ctx, `SELECT data FROM secret_use_grants WHERE user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*vaultv1.UseGrant
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		g := &vaultv1.UseGrant{}
		if err := protojson.Unmarshal(raw, g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
