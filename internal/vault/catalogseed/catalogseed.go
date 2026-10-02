// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package catalogseed idempotently upserts the vault's built-in secret-type
// catalogue (secret_types, extension_catalog, connections) into Postgres. It
// is the ONE shared implementation behind both:
//   - cmd/seed's `catalog` subcommand (the dev/test seeding tool, which also
//     ships bulk/per-type/requests), and
//   - cmd/seed-catalog (a separate, minimal binary with NO bulk/fake-data
//     capability, safe to ship to prod).
//
// This package depends ONLY on grpcsvc's built-in catalogue accessors, the
// go-seed idempotent-upsert runner, and a pgx pool — never on the bulk/
// per-type/requests seeding code — so anything built on top of it (like
// cmd/seed-catalog) inherits that same, narrower dependency surface.
package catalogseed

import (
	"context"
	"fmt"

	log "github.com/Bugs5382/go-log"
	seed "github.com/Bugs5382/go-seed"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
)

// rowStep is a pgx-backed analogue of go-seed's SQL RowSpec (whose Executor is
// database/sql only): an idempotent Apply plus an Assert that the expected rows
// landed. Keeps everything on the app's proven pgx pool.
func rowStep(name, apply string, applyArgs []any, count string, countArgs []any, want int) seed.Step[*pgxpool.Pool] {
	if want < 1 {
		want = 1
	}
	return seed.Step[*pgxpool.Pool]{
		Name: name,
		Apply: func(ctx context.Context, db *pgxpool.Pool) error {
			_, err := db.Exec(ctx, apply, applyArgs...)
			return err
		},
		Assert: func(ctx context.Context, db *pgxpool.Pool) error {
			var n int
			if err := db.QueryRow(ctx, count, countArgs...).Scan(&n); err != nil {
				return err
			}
			if n < want {
				return fmt.Errorf("expected at least %d row(s), found %d", want, n)
			}
			return nil
		},
	}
}

// Run upserts the vault's full built-in secret-type catalogue into the
// secret_types table (plus the extension_catalog and connections) using go-seed:
// idempotent upserts, each proven by a row-count assertion. It exists so an
// EXISTING vault (whose Postgres was seeded before newer built-in types shipped)
// picks up the additions — the vault only runs seed() on a fresh, empty database,
// so it never back-fills on its own. After running this, restart the vault so it
// hydrates the new types. Re-running is safe, and it is PROD-SAFE: it only ever
// touches the real built-in catalogue, never bulk/fake data.
func Run(ctx context.Context, pool *pgxpool.Pool) error {
	logger := log.New("vault-seed")

	// Single source of truth for both catalogues — shared with the vault's own
	// seed() so an upsert here matches what a fresh vault installs/registers.
	// In each table the data column is protojson of the SecretType, identical to
	// the format pgStore.Load reads back via protojson.Unmarshal (store.go).
	types := grpcsvc.BuiltinTypes()    // installed, usable built-in types
	exts := grpcsvc.ExtensionCatalog() // registered importable packs (not installed)

	runner := seed.New(pool)
	// Built-in types become usable secret types (secret_types).
	for _, t := range types {
		raw, err := protojson.Marshal(t)
		if err != nil {
			return fmt.Errorf("marshal secret type %s: %w", t.GetId(), err)
		}
		runner.Add(rowStep(
			"secret_type:"+t.GetId(),
			`INSERT INTO secret_types (id, data) VALUES ($1, $2::jsonb)
			 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`,
			[]any{t.GetId(), raw},
			`SELECT count(*) FROM secret_types WHERE id=$1`, []any{t.GetId()}, 1,
		))
	}
	// Extension packs are only registered as importable (extension_catalog); they
	// are NOT installed as usable types until an admin imports one.
	for _, e := range exts {
		raw, err := protojson.Marshal(e)
		if err != nil {
			return fmt.Errorf("marshal extension %s: %w", e.GetId(), err)
		}
		runner.Add(rowStep(
			"extension:"+e.GetId(),
			`INSERT INTO extension_catalog (id, data) VALUES ($1, $2::jsonb)
			 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`,
			[]any{e.GetId(), raw},
			`SELECT count(*) FROM extension_catalog WHERE id=$1`, []any{e.GetId()}, 1,
		))
	}

	// Default connections (SSH/WinRM/LDAPS): the protocol templates a target
	// binds to. Without one no target can be created, so they ship seeded.
	conns := grpcsvc.BuiltinConnections()
	for _, c := range conns {
		raw, err := protojson.Marshal(c)
		if err != nil {
			return fmt.Errorf("marshal connection %s: %w", c.GetId(), err)
		}
		runner.Add(rowStep(
			"connection:"+c.GetId(),
			`INSERT INTO connections (id, data) VALUES ($1, $2::jsonb)
			 ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`,
			[]any{c.GetId(), raw},
			`SELECT count(*) FROM connections WHERE id=$1`, []any{c.GetId()}, 1,
		))
	}

	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	logger.Info().Int("types", len(types)).Int("extensions", len(exts)).Int("connections", len(conns)).Msg("vault secret-type seed complete")
	return nil
}
