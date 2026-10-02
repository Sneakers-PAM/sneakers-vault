# Contributing to sneakers-vault

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). Set `TEST_DATABASE_DSN` (vault) and
  `WORKFLOW_PG_DSN` (workflow) to run the Postgres integration tests; without them those tests are
  skipped.
- Changing an API: edit `proto/sneakers/vault/v1/vault.proto` or
  `proto/sneakers/workflow/v1/workflow.proto`, then run `buf generate` (with the `protoc-gen-go`
  and `protoc-gen-go-grpc` versions pinned in `.github/workflows/job-go-lang-ci.yaml`) and commit
  the result under `gen/go`. CI fails if the generated code is stale or the change breaks the API.
- Changing the crypto or the key ring: add tests that prove records sealed before the change still
  open after it. Never commit key material; generate test keys at test time.
- Every `.go`, `.proto` and `.sql` file starts with the Apache-2.0 header:

  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
