# AGENTS.md - sneakers-vault

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers vault and workflow services: secrets, versions, rotation, heartbeat state and approvals (with their gRPC APIs)

<!-- Fill in: what the project does, what it ships (library, service, action, CLI), and the one or
two things an agent must understand before changing it. -->

## Using sneakers-vault

<!-- If this project is consumed by others (a library/plugin/action), describe the contract a
consumer must respect: the single entry point, the public surface, required options, and anything
that must not be bypassed. Delete this section for a leaf application. -->

## Layout

<!-- The directories that matter and what lives in each. Keep it short; point at the entry points. -->

- `src/` - <what>
- `<tests dir>/` - <what>

## Build, test, lint

<!-- The exact commands. Pull these from package.json scripts (npm), the Taskfile (Go/Task), or
pyproject (Python) so they stay accurate. -->

- Build: `<command>`
- Test: `<command>` (note any service/fixture the integration tests require)
- Lint: `<command>`
- Package checks (npm packages), after a build: `npm run check:pack` (contents and ceiling),
  `npm run check:pack:growth` (growth against the last release), `npm run check:install`
  (install the tarball, import ESM and CJS); see CLAUDE.md "npm package contents"
- License headers / docs: `<command>`

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
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- <project-specific conventions, non-obvious constraints, and traps an agent should know>
