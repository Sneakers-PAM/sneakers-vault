// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/crypto"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/grpcsvc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// preflightRootKEK resolves the root KEK and proves it can open the existing
// keyring BEFORE any migration runs, so a missing or wrong VAULT_ROOT_KEK
// exits without touching the schema. Once a migration is applied an image
// built before it may no longer boot, so an image revert is not a rollback:
// the KEK must be validated first.
//
// Two cases, keyed on whether the kek_keyring table exists yet (the
// 0001_baseline migration creates it):
//   - no kek_keyring table (an empty database): there is nothing to
//     unwrap-check, so only the KEK's presence and format (base64, 32 bytes)
//     are validated here; the keyring is built (first generation seeded)
//     after migrating.
//   - kek_keyring present: every persisted working-KEK generation is
//     unwrapped under the resolved root. Any failure means the operator supplied a different
//     root than the one that wrapped the ring, and boot fails closed.
//
// dsn should be the direct (session) connection used for migrations. The
// check runs in the simple query protocol so it also works through a
// transaction-pooling connection pooler when MIGRATE_DSN is unset.
func preflightRootKEK(ctx context.Context, dsn, environment string) (crypto.KEKProvider, string, error) {
	root, rootRef, err := resolveRootKEK(environment)
	if err != nil {
		return nil, "", err
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, "", fmt.Errorf("root KEK preflight: parse dsn: %w", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("root KEK preflight: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if err := verifyKeyringUnwraps(ctx, conn, root); err != nil {
		return nil, "", err
	}
	return root, rootRef, nil
}

// verifyKeyringUnwraps unwraps every kek_keyring generation under root. A
// database without the kek_keyring table yet passes trivially. Only refs appear in
// errors, never key material; the unwrapped bytes are discarded immediately.
func verifyKeyringUnwraps(ctx context.Context, conn *pgx.Conn, root crypto.KEKProvider) error {
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.kek_keyring') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("root KEK preflight: probe kek_keyring: %w", err)
	}
	if !exists {
		return nil
	}
	rows, err := conn.Query(ctx, `SELECT ref, wrapped_key, root_ref FROM public.kek_keyring ORDER BY ref`)
	if err != nil {
		return fmt.Errorf("root KEK preflight: load kek_keyring: %w", err)
	}
	type gen struct {
		ref, rootRef string
		wrapped      []byte
	}
	var gens []gen
	for rows.Next() {
		var g gen
		if err := rows.Scan(&g.ref, &g.wrapped, &g.rootRef); err != nil {
			rows.Close()
			return fmt.Errorf("root KEK preflight: scan kek_keyring: %w", err)
		}
		gens = append(gens, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("root KEK preflight: read kek_keyring: %w", err)
	}
	for _, g := range gens {
		raw, err := root.UnwrapDEK(g.wrapped, g.rootRef)
		if err != nil {
			return fmt.Errorf("root KEK preflight: VAULT_ROOT_KEK cannot unwrap keyring generation %s (wrapped under root %s); refusing to migrate or boot: %w", g.ref, g.rootRef, err)
		}
		clear(raw)
	}
	return nil
}

// migrateAfterPreflight is the boot ordering main relies on: validate the
// root KEK against the current schema first, and only then apply pending
// migrations. On any preflight error no migration is attempted.
func migrateAfterPreflight(ctx context.Context, migrateDSN, migrationsDir, environment string) (crypto.KEKProvider, string, error) {
	root, rootRef, err := preflightRootKEK(ctx, migrateDSN, environment)
	if err != nil {
		return nil, "", err
	}
	if err := postgres.Migrate(migrateDSN, migrationsDir); err != nil {
		return nil, "", fmt.Errorf("migrate: %w", err)
	}
	return root, rootRef, nil
}

// devStaticDisabled parses VAULT_DISABLE_DEV_STATIC_KEK. Unset means false; an
// unparseable value is an error rather than a silent default, so a typo never
// leaves the public dev-static key loaded when the operator meant to drop it.
func devStaticDisabled() (bool, error) {
	v := os.Getenv("VAULT_DISABLE_DEV_STATIC_KEK")
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("VAULT_DISABLE_DEV_STATIC_KEK=%q: want true or false", v)
	}
	return b, nil
}

// keyringBoot is the post-migrate half of the KEK boot sequence.
type keyringBoot struct {
	envelope *crypto.Envelope
	keyring  *crypto.KeyringKEK
	store    grpcsvc.KeyringAdmin
	report   grpcsvc.KeyRefReport
	// unreadable lists KeyRefs referenced by stored rows that the built
	// keyring cannot unwrap (should always be empty).
	unreadable []string
}

// bootKeyring counts stored rows by KeyRef (from Postgres, across every table
// that holds a wrapped DEK), and — when disableDevStatic is set — refuses to
// boot while any row still references dev-static-v1. Otherwise it builds the
// keyring, loading the dev-static key (decrypt-only) unless disabled, and
// reports any referenced KeyRef the keyring cannot unwrap.
func bootKeyring(ctx context.Context, pool *pgxpool.Pool, root crypto.KEKProvider, rootRef string, disableDevStatic bool) (keyringBoot, error) {
	report, err := grpcsvc.KeyRefCounts(ctx, pool)
	if err != nil {
		return keyringBoot{}, err
	}
	if disableDevStatic {
		if err := grpcsvc.CheckDevStaticRetired(report); err != nil {
			return keyringBoot{report: report}, err
		}
	}
	envelope, kr, ks, err := buildEnvelope(ctx, pool, root, rootRef, !disableDevStatic)
	if err != nil {
		return keyringBoot{report: report}, err
	}
	kb := keyringBoot{envelope: envelope, keyring: kr, store: ks, report: report}
	for _, ref := range report.Refs() {
		if !kr.Has(ref) {
			kb.unreadable = append(kb.unreadable, ref)
		}
	}
	return kb, nil
}

// kekRotationPrincipals reads VAULT_KEK_ROTATION_PRINCIPALS, the SYSTEM
// principals allowed to call RotateKek. Unset or empty disables the path. A
// malformed entry is a boot error, not a silent drop, so a typo never leaves
// the operator's rotation principal unexpectedly denied or a non-system id
// allowlisted.
func kekRotationPrincipals() ([]string, error) {
	return grpcsvc.ParseKekRotationPrincipals(os.Getenv(grpcsvc.KekRotationPrincipalsEnv))
}
