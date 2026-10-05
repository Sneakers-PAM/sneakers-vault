# Vault and Workflow Services 🔐

> 🗝️ The Sneakers-PAM secret store and the approvals and check-out flow built on it.

Two gRPC services built from one repository. They run as separate processes, each with its own
Postgres database, and ship as two images: `sneakers-vault` and `sneakers-workflow`.

## 🔐 Vault service

`sneakers.vault.v1.VaultService`: secret types, the folder tree, and the secrets themselves, with
every field value envelope-encrypted at rest under a rotating key ring.

- 📁 **Secrets and folders:** shared and personal folders, an ordered firewall-style RACI ruleset
  on folders, secrets and targets, and an append-only version history per secret.
- 🔑 **Key ring:** per-secret data keys wrapped by working keys, which a root key wraps in turn.
  `RotateKek` mints a new working key and re-wraps every record.
- ❤️ **Heartbeat and rotation:** the connector claims due checks and rotations, and the vault
  records the outcome.
- 🤖 **Machine access:** service accounts, workloads and personal tokens act through the
  `*ForPrincipal` calls, never with admin authority.
- 🚨 **Break-glass:** an audited emergency reveal that notifies the owner and queues a rotation.

## ✅ Workflow service

`sneakers.workflow.v1.WorkflowService`: time-boxed check-out leases and access-request approvals.

- ⏱️ **Check-out saga:** a check-out issues a lease, check-in rotates the credential and closes
  it, and a reaper closes leases that expire without a check-in.
- 🙋 **Approvals:** access, folder-move and secret-move requests, with a comment thread and an
  approver-chosen access window.
- 🧹 **Retention:** resolved requests are purged after the retention window the vault's security
  settings hold.

## 🚀 Run it

```bash
docker run -d --name sneakers-pg -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 postgres:17-alpine
docker exec sneakers-pg createdb -U postgres vault
docker exec sneakers-pg createdb -U postgres workflow

export WORKLOAD_AUTH=disabled   # local only: trust every caller
DATABASE_DSN='postgres://postgres@localhost:5432/vault?sslmode=disable' GRPC_PORT=9091 \
  go run ./cmd/vault
DATABASE_DSN='postgres://postgres@localhost:5432/workflow?sslmode=disable' GRPC_PORT=9193 \
  VAULT_ADDR=localhost:9091 go run ./cmd/workflow
```

Both services refuse to start without service-to-service authentication
(`WORKLOAD_OIDC_ISSUER` and friends) unless `WORKLOAD_AUTH=disabled` is set, which is for local
development only; see [docs/workload-auth.md](docs/workload-auth.md).

The container trusts local connections without a password, for development only. Each service
applies its own migrations at start. Outside `ENVIRONMENT=dev` the vault needs a root key in
`VAULT_ROOT_KEK`; see [docs/configuration.md](docs/configuration.md).

Run the tests, including the Postgres integration tests:

```bash
docker exec sneakers-pg createdb -U postgres vault_test
docker exec sneakers-pg createdb -U postgres workflow_test
TEST_DATABASE_DSN='postgres://postgres@localhost:5432/vault_test?sslmode=disable' \
  WORKFLOW_PG_DSN='postgres://postgres@localhost:5432/workflow_test?sslmode=disable' \
  go test ./...
```

Without those variables the integration tests are skipped.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
docker build --target vault .     # or workflow, seed-catalog, seed
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables for both services and the
  tools.
- [docs/api.md](docs/api.md): both gRPC APIs, by area, and the rules they enforce.
- [docs/runbook.md](docs/runbook.md): operating the services, the key ring and the seed tools.
- [docs/workload-auth.md](docs/workload-auth.md): how every caller proves who it is.
- [docs/worker-identity.md](docs/worker-identity.md): the connector's worker identity on its pull-API.
- [docs/type-change.md](docs/type-change.md): changing a secret's type as a machine principal.
- [proto/sneakers/vault/v1/vault.proto](proto/sneakers/vault/v1/vault.proto) and
  [proto/sneakers/workflow/v1/workflow.proto](proto/sneakers/workflow/v1/workflow.proto): the API
  definitions.

## 🙏 Acknowledgements

Sneakers-PAM was originally written by [@Bugs5382](https://github.com/Bugs5382).

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
