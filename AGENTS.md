# AGENTS.md - sneakers-vault

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Two Sneakers services built from one repository: the vault (`sneakers.vault.v1.VaultService`,
secrets with envelope encryption, folders, RACI access rules, versions, heartbeat and rotation
state) and the workflow service (`sneakers.workflow.v1.WorkflowService`, check-out leases and
approvals). They run as separate processes with separate Postgres databases and ship as two
images. Before changing the vault, know that its crypto and key ring (`internal/vault/crypto`,
the `kek_*` files in `internal/vault/grpcsvc`) decide whether stored secrets can ever be opened
again: change them only with tests that prove old records still open, and never log key material
or values.

## Layout

- `cmd/vault/`, `cmd/workflow/` - the two service entrypoints.
- `cmd/workflow-purge/` - the one-shot history purge; `cmd/seed-catalog/` - the built-in catalogue
  upsert; `cmd/seed/` - dev demo data.
- `internal/vault/` - the vault: `grpcsvc` (the service, its Postgres store and the tests;
  `*_pg_test.go` and `main_pg_test.go` need Postgres), `crypto` (envelope and key ring), `authz`
  (the RACI engine), `workloadid` (connector identity), `certsvc`, `catalogseed`, and the audit and
  notify clients.
- `internal/workflow/` - the workflow service: `grpcsvc` (service, saga, store) and `vaultclient`.
- `internal/config/`, `internal/server/` - the env loader and the gRPC server bootstrap both use,
  with the health service and readiness checks from `github.com/Bugs5382/go-buildinfo`.
- `internal/workloadauth/` - service-to-service authentication (workload token verifier, per-method
  allow-list interceptors, caller credentials). Self-contained and copied byte for byte into the
  other services; change it here first. See docs/workload-auth.md.
- `proto/` - both APIs; `gen/go/` - the generated Go (committed, checked current in CI).
- `migrations/vault/`, `migrations/workflow/` - each service's Postgres schema, forward only.
- `docs/` - configuration, API, runbook, worker identity and type changes.

## Build, test, lint

- Build: `task build`
- Test: `task test`; set `TEST_DATABASE_DSN` (vault) and `WORKFLOW_PG_DSN` (workflow) to run the
  Postgres integration tests (see README.md), otherwise they are skipped.
- Lint: `task lint`, plus `buf lint` for the protos (after `scripts/proto-generate.sh` has
  fetched the audit and notify protos).
- Generated code: `scripts/proto-generate.sh`, with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`. The audit and notify client stubs in
  `gen/go/thirdparty/` come from the commits pinned in `proto-refs.env` (see docs/api.md,
  "Calling other services").
- Images: `docker build --target vault .` (or `workflow`, `seed-catalog`, `seed`).
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, key material or personal data, not even at `trace`. Log an opaque or
  keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names. Test keys are generated at test time; never commit key material.
- The built-in catalogue is additive only: append new types, never reorder or alter existing ones.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`. For local callee protos,
  point `SNEAKERS_AUDIT_PROTO_DIR` and `SNEAKERS_NOTIFY_PROTO_DIR` at a local `proto/` directory
  when running `scripts/proto-generate.sh`, rather than editing a pin in `proto-refs.env`.
