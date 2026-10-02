# CLAUDE.md - sneakers-vault

Working agreement for this repository. The governance below is shared across the org's repos and
kept in sync with them.

## Enforced by hooks (run `bash .claude/hooks/install.sh` once per clone)

- Conventional Commits on commits, issue titles, and PR titles.
- No AI tells in commits/issues/PRs/comments/source; no emoji in source or commit messages (emoji
  are allowed in Markdown docs and CI workflow files).
- Pre-push: the ecosystem's format/lint/test gate must pass (Go: gofmt/vet/golangci-lint/test;
  npm: lint/test scripts; Python: ruff/pytest).

## Conventions

- Branching: never commit to `main`. Work on a feature/working branch; open a PR.
- Commits: Conventional Commits (`type(scope): description`). The operator (@Bugs5382) is the
  author of record on every commit.
- Voice: human-authored. No attribution trailers (`Co-Authored-By`, `Generated with`), no robot
  glyphs/emoji, no session framing.
- Local notes live in the git-ignored `.local/` folder; delete a note when its work is done.
- GitHub Actions: a job id must be a plain identifier (a letter or `_`, then alphanumerics/`-`/`_`);
  put emoji and display text in the job's `name:`, never the job key. The Actionlint check
  (`.github/workflows/action-lint.yaml`) enforces this, so a malformed workflow fails at PR time
  instead of silently at startup on `main`.

<!-- layout:begin go/app -->
## Project layout

The `go/app` baseline layout.
The governance sync replaces this whole CLAUDE.md with the shared template on
every run. Only the layout choice in the begin marker carries over, and this
section is rendered again from it. Anything else written here is replaced, so
keep repo-specific notes in AGENTS.md, which the sync leaves alone.

A long-running Go service (HTTP or gRPC API, worker or consumer).

### Tree

```text
.
├── cmd/server/
│   └── main.go           entry point: load config, wire the helpers, run, shut down
├── internal/
│   ├── config/           typed settings from the environment
│   ├── server/           transport: routes or gRPC handlers
│   ├── <domain>/         business logic, one package per domain area
│   └── store/            queries behind interfaces the domain owns
├── migrations/           ordered SQL migrations
├── proto/                protobuf sources, when the service speaks gRPC
├── gen/                  code generated from proto/ or a schema
├── deployments/          Helm chart or manifests, when the repo ships them
├── testdata/             test fixtures
├── Dockerfile
├── .env.example          every setting, with safe local defaults
├── go.mod
├── Taskfile.yaml
└── .golangci.yml
```

### What goes where

- Shared infrastructure is not written from scratch. Logging and trace correlation, database and
  cache connections, message brokers, coded errors and seed data come from the owner's
  published helper packages wherever one covers the job (see the owner's package catalog for each
  package and its version). The service configures and wires them; it does not wrap or
  re-implement them. When no package covers a need, report it as a gap instead of building a
  one-off.
- `cmd/server/`: only `main.go`. It builds the dependencies from the helper packages, starts the
  server and handles signals. A second binary (a worker, a migration runner) gets its own
  `cmd/<name>/`.
- `internal/config/`: one struct filled from environment variables and validated at start-up,
  holding the settings each helper package takes. No config reads anywhere else.
- `internal/server/`: request decoding, auth and turning coded errors into responses. It calls the
  domain; it holds no business rules.
- `internal/<domain>/`: the rules, free of transport and database types, so they test without
  either.
- `internal/store/`: the service's own queries, run on the connection the helper package provides.
  Sub-packages per backend (`store/postgres/`, `store/memory/`) when there is more than one.
- `migrations/`: numbered, forward-only files (`0001_create_users.up.sql`). Never edit a migration
  that has shipped; add a new one.
- `proto/` and `gen/`: sources in `proto/`, generated output only in `gen/`.

### Naming

- Packages: short, lowercase, one word, named for the domain (`billing`, `session`), never `util`
  or `models`.
- Files: lowercase `snake_case.go`, one concept per file (`handler.go`, `repository.go`).
- Environment variables: `UPPER_SNAKE_CASE`, listed in `.env.example`. `LOG_LEVEL` and `LOG_FORMAT`
  are always there.
- Interfaces are declared by the package that uses them, not the one that implements them.

### Tests, fixtures and generated code

- Unit tests sit next to the code as `<file>_test.go`.
- Tests that need real infrastructure (database, broker) are behind `//go:build integration`, or in
  `test/e2e/` when they drive the whole running service.
- Fixtures go in `testdata/` next to the package that reads them.
- Generated code lives in `gen/` (or `<name>_gen.go`), is committed, carries the
  `// Code generated ... DO NOT EDIT.` header and is rebuilt by a Taskfile task. Never edit it by
  hand.
<!-- layout:end -->

## CI and Actions minutes

GitHub bills every job for at least one full minute, and a private org's included minutes run out
fast during a wave of PRs. The shipped workflows are shaped around that:

- **Drafts run nothing.** PR workflows skip draft PRs and run on `ready_for_review`, `opened`,
  `synchronize` and `reopened`. Open a PR as a draft, run the full checks locally, push once they
  pass, and mark it ready when the work is finished. That starts one CI run. After it is ready,
  push only real fixes, batched into one push.
- **One job for the small checks.** PR Title, PR Body, PR Hygiene and the gitleaks secret scan are
  steps of one `✅ PR Checks` job (`job-pr-checks.yaml`). Every step runs even when an earlier one
  fails, so the log shows every failure. This job and the label checker are the only workflows
  that react to `edited`: a title or body fix reruns them, not the build.
- **Pull requests only.** Build, test, lint, licence and security workflows run on pull requests,
  not on push to `main`. The squash merge lands the tree the PR run already tested. Only the
  release workflows (Release Manager, Release Drafter, publish) run on `main`, and Go Security keeps
  its weekly schedule for advisories published later.
- **Keep the PR run honest:** the PR run covers the merged code only when the branch is up to date
  with `main` before it merges. In the branch ruleset, add **Require status checks to pass** with
  the repo's check names and turn on **Require branches to be up to date before merging** (API:
  the `required_status_checks` rule with `strict_required_status_checks_policy: true`; classic
  branch protection: `required_status_checks.strict: true`). The setting only exists alongside
  required checks. Use GitHub's "Update branch" when a PR falls behind.
- **No no-op jobs.** The licence check ships per ecosystem: `job-license-check-go.yaml` only where
  there is a root `go.mod`, `job-license-check-npm.yaml` only where there is a root `package.json`.
- **Every job has a `timeout-minutes`** (10 for small checks, 15 to 30 for builds, scans and
  releases), so a hung job stops long before GitHub's 360-minute default. Jobs that call a reusable
  workflow (`uses:`) cannot take one; the called workflow's jobs carry it.
- **Prebuilt security tools.** Go Security installs the pinned gosec release binary and checks it
  against the published SHA-256, building the same version from source only when `go.mod` needs a
  newer Go than the binary was built with. govulncheck has no release binaries, so it is built once
  per version and Go toolchain and cached; the weekly run on `main` keeps that cache warm for PRs.
  To bump either tool, change the version (and for gosec the checksum) in `job-go-security.yaml`.
- **Required checks:** if the ruleset or branch protection lists required checks, use the job
  names: `✅ PR Checks` replaces `PR Title`, `PR Body`, `PR Hygiene` and `Gitleaks (secret scan)`.

## Engineering discipline

- Root-cause before fixing: confirm the actual cause with evidence before changing code; do not
  patch symptoms.
- Map every reference before removing a feature: trace its wiring across the tree first, preserve
  adjacent behavior that only looks related, and defer-and-flag an entangled piece rather than
  guessing it.
- Verify with evidence, not assertions: run the real check for what changed (lint, a full
  template/build render, `actionlint` for workflows) before calling it done. Green CI is necessary,
  not sufficient.
- One concern per branch/PR, even tiny ones — it keeps reviews and the drafted changelog clean.
- When PRs interact, state an explicit merge ORDER rather than opening them and walking away:
  anything a *tag* triggers needs its inputs on `main` first; a new *gate* (check) needs the
  violations it catches fixed first; a workflow that builds from committed content needs that
  content merged first.
- Semver framing: `breaking` only means breaking against a *released* version; removing something
  that was never shipped is not a breaking change.
- Cross-repo reconciliation goes through a neutral drop-zone outside both repos — never a repo
  inside a repo, and no accidental gitlinks/submodules.

## Logging

- Log generously in any code you write or touch: entry and exit of significant operations, the
  decisions and branches taken, retries, state changes, external calls (target, duration,
  outcome), and every error with its context. Finding a problem fast matters more than quiet code.
- Pick the level by detail: `trace` for step-by-step detail and values, `debug` for flow, `info`
  for lifecycle, `warn` and `error` for problems. The environment level filters the volume, so
  too much logging is fine.
- Levels by environment: local dev `trace`; dev cluster `debug`; pre-production (qa/staging)
  `info`; production `error`. Set them per environment through `LOG_LEVEL` and `LOG_FORMAT`, never
  by changing code. Library fallbacks stay safe when nothing is set.
- Format: local dev is human-readable (`LOG_FORMAT=console`), never JSON. Every cluster
  environment logs JSON. Local run targets (the Taskfile, or `.env.example` where there is no run
  target) set `LOG_LEVEL=trace LOG_FORMAT=console`.
- Deployment defaults are production-safe: a Helm chart's `values.yaml` defaults to `json` and
  `error`, and a dev values overlay sets `debug`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID
  instead.

## Workflow

Issue (from a template; free-form issues are disabled) -> for sequential / multi-step work, a parent
issue with ordered **sub-issues** -> put it on the active **milestone** -> branch
`<type>/<issue#>-<slug>` -> code (comments cite the issue) -> PR with a Conventional Commit title
(the autolabeler sets the category label from the title), the template body, and a **closing
summary** before merge -> **squash** merge. The operator (@Bugs5382) is the assignee.

On merge, release-drafter drafts the next notes by label and `CHANGELOG.md` updates on `main` via the
changelog action -- **nothing tags automatically**. When the first push to main resolves the version,
rename the milestone to that version. The maintainer then **manually publishes the GitHub Release**,
which creates the tag with the finalized changelog (and triggers the publish where the repo ships a
package).

Keep public artifacts (issues, PRs, commit messages) free of references to local-only design notes.

## Releasing

On every push to `main` the **Release Manager** workflow (`.github/workflows/job-version-bump.yaml`)
runs: release-drafter anticipates the next version, the manifest version is bumped (package
ecosystems only), `CHANGELOG.md` is updated via the changelog action, and a
`chore(pre-release): vX [skip ci]` commit is pushed back to `main`. **Nothing tags automatically.**
The maintainer then publishes the GitHub Release by hand, which creates the `vX.Y.Z` tag with the
finalized changelog and triggers the publish workflow where the repo ships a package.

In npm-based ecosystems (repos with a `package.json`), the canonical version bump is
`npm version "v<resolved>" --no-git-tag-version --allow-same-version` in `job-version-bump.yaml`.
Do not swap it for a Taskfile `update-version` target: that pulls go-task into the bump job for no
gain. A repo that needs the version elsewhere reads it from `package.json`. Python repos bump
`pyproject.toml` instead, and Go and Action repos have no manifest to bump.

### npm package contents

npm packages (the npm, fastify and storybook templates) carry three checks in `scripts/`. Run
them after `npm run build`; CI runs them on every PR.

- **Contents and ceiling** (`npm run check:pack`, `checkPack.mjs`, in `action-test`): runs
  `npm pack --dry-run --json --ignore-scripts` and fails if the tarball would ship a `.map` file,
  TypeScript source, test files, a build cache or a non-runtime folder (`src/`, `test/`, `docs/`,
  `scripts/`, `coverage/`, `temp/`), if an entry point in `main`/`module`/`types`/`exports` is
  missing, if `files` is not set, or if the unpacked size is over the ceiling. The file list and
  sizes go to the job summary.
- **Growth against the last release** (`npm run check:pack:growth`, `checkPackGrowth.mjs`, in its
  own `job-pack-growth` workflow): compares this build with
  `npm view <pkg> dist.unpackedSize dist.fileCount` for the `latest` dist-tag and fails when either
  grows by more than `config.packMaxGrowthPercent` (25 in the template). Growth under 10,000 bytes
  or 5 files never fails on its own, so small packages can change. A package that was never
  published passes with a note.
- **Install smoke test** (`npm run check:install`, `checkInstall.mjs`, in `action-test` on every
  Node version in the matrix): packs the package, installs the tarball and its required peers in a
  throwaway folder outside the repo, and loads every `exports` subpath as ESM (`import`) and CJS
  (`require`). It fails when an entry point does not load, loads empty, or the ESM and CJS builds
  export different names. Stylesheet subpaths (`./style.css`) are resolved, not loaded, and style
  imports inside the JavaScript are stubbed the way a bundler would, so a component library that
  imports its own CSS still loads in Node.

- **Ceiling:** `config.packMaxUnpackedBytes` in `package.json` (250 kB in the template). Raise it
  on purpose, in the same PR as the growth, and say why in the PR body.
- **Intended growth:** add the `pack-size-approved` label to the PR and say in the PR body why the
  package grew. Adding or removing the label reruns `job-pack-growth`; with the label the growth is
  still reported in the job summary but does not fail. Change `config.packMaxGrowthPercent` only
  when the default does not fit the package, not to pass one PR.
- **Source maps** are off in the build (`sourcemap: false` in `tsdown.config.ts`). Never turn them
  back on for the published output.
- **Always pass `--ignore-scripts`** to `npm ci`, `npm install` and `npm pack`. A `prepare` script
  (husky) resets `core.hooksPath` and bypasses the commit guard, and `prepack`/`prepare` would run a
  build the check did not ask for.
- Before a release, also build locally, read `npm pack --dry-run` output, and run
  `npm run check:pack:growth` and `npm run check:install`. They are the CI versions of the
  compare-with-`npm view` and install-the-tarball release checks.


**GitHub Action repos release differently** — a composite/JS action has no package manifest and is
**not** published to a registry. The maintainer manually tags `vX.Y.Z`, publishes the GitHub
Release, and repoints the floating major tag `@vN` (e.g. `git tag -fa v1 -m "v1 -> v1.2.3" v1.2.3 &&
git push origin v1 --force`) so consumers pinned to `owner/repo@vN` pick up the release; publishing
to the GitHub Marketplace is an optional manual step. The first release is `v1.0.0`, prepared as
below.

### First release

release-drafter cannot draft a first release (upstream release-drafter#1630). With no earlier
published release it proposes a version with "No changes" and a "could not find a previous
published release" warning block. Do not fix that draft by hand; the maintainer prepares the first
release notes.

### Docs site and first-release gotchas

- A tag-gated GitHub Pages deploy (publishing only on `vX.Y.Z`) fails at the Deploy step unless the
  auto-created `github-pages` environment allows tag refs. Once, alongside enabling Pages
  (Settings -> Pages -> Source = GitHub Actions), add a tag policy, then re-run the failed Deploy
  job (no need to re-cut the tag):
  `gh api -X POST repos/Sneakers-PAM/sneakers-vault/environments/github-pages/deployment-branch-policies -f name='v*' -f type=tag`
- Docusaurus MDX 3: avoid the `## Heading {#custom-id}` explicit-id syntax (it fails to compile);
  rely on the auto-generated slugs.
