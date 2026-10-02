# Configuration

Both services and every tool read their settings from environment variables. Nothing else is read
at start. `.env.example` holds safe local defaults.

## Shared by both services

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_DSN` | (required) | Postgres DSN for this service's own database. The vault and workflow never share a database. |
| `MIGRATE_DSN` | `DATABASE_DSN` | A direct (session) connection for migrations. Set it when `DATABASE_DSN` goes through a transaction-pooling connection pooler, which breaks the advisory locks migrations take. |
| `MIGRATIONS_DIR` | `migrations/vault` or `migrations/workflow` | Where the service's migrations are. The images set `/migrations`. |
| `GRPC_PORT` | `9090` | The gRPC listen port. Give each service its own port when they run on one host. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OpenTelemetry OTLP gRPC endpoint for traces and metrics. |
| `LOG_LEVEL`, `LOG_FORMAT` | `go-log` defaults | Log level and format. Local development uses `trace` and `console`; clusters log JSON. |

### Service-to-service authentication

Both services authenticate every caller and present their own token on outbound calls. See
[workload-auth.md](workload-auth.md).

| Variable | Default | Meaning |
|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | (required) | The cluster's ServiceAccount issuer. Without it a service refuses to start, in every environment, unless `WORKLOAD_AUTH=disabled`. |
| `WORKLOAD_OIDC_JWKS_URL`, `WORKLOAD_OIDC_CA_FILE`, `WORKLOAD_OIDC_BEARER_FILE` | | Where and how the issuer's keys are fetched. |
| `WORKLOAD_AUDIENCE` | `sneakers` | The audience every caller's token must carry. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | (required with the issuer) | Comma list of `<namespace>/<serviceaccount>`: the service's callers. The vault's are gateway, workflow, sshbroker and connector; the workflow's is the gateway. |
| `WORKLOAD_AUTH` | (unset) | `disabled` trusts every caller. Local development and mocks only; the charts never set it. A warning is logged at start and every 5 minutes. |
| `WORKLOAD_TOKEN_FILE` | (unset) | This service's projected token (audience `sneakers`), sent on every outbound call: the vault's to audit and notify, the workflow's (and `workflow-purge`'s) to the vault. The charts mount it at `/var/run/secrets/sneakers/token`. Unset sends none. |

## Vault service

### Environment and keys

| Variable | Default | Meaning |
|---|---|---|
| `ENVIRONMENT` | `dev` | The environment name. Only `dev` may run without `VAULT_ROOT_KEK`. `dev`, `local` and `development` install the built-in baseline at every boot; any other name starts empty and waits for first-run setup (`SeedBuiltins`). `prod` and `production` also refuse the dev worker token and limit hard delete to site admins. |
| `VAULT_ROOT_KEK` | (none) | The root key: 32 bytes, standard base64. It wraps the working keys in `kek_keyring`. Required in every environment except `dev`. It's permanent for the database: keep it in your secret store and back it up with the database, because without it no secret can be opened. |
| `DEV_KEK_SEED` | a built-in dev seed | `dev` only, with no `VAULT_ROOT_KEK`: the root key is derived from this string, so a dev database opens across restarts with no setup. It's public in the source; never use it outside development. |
| `VAULT_DISABLE_DEV_STATIC_KEK` | `false` | `true` drops the decrypt-only static dev key (`dev-static-v1`) from the key ring. The vault refuses to boot with it set while any stored row still uses that key. |
| `KEK_ROTATION_DAYS` | `90` | Seeds `kek_rotation_days` on a fresh instance's security settings. `0` turns automatic rotation off. Existing instances keep their stored value. |
| `KEK_SCHEDULER_CHECK_MINUTES` | `60` | How often the automatic rotation scheduler checks the active working key's age. |
| `VAULT_KEK_ROTATION_PRINCIPALS` | (empty: off) | Comma list of `system:<name>` principals that may call `RotateKek` besides a human site admin. See [runbook.md](runbook.md#rotating-the-working-key). |

Generate a root key with:

```bash
openssl rand -base64 32
```

### Other services

| Variable | Default | Meaning |
|---|---|---|
| `AUDIT_ADDR` | `localhost:9194` | The audit service (`sneakers.audit.v1.AuditService`). Every mutation is recorded there. |
| `NOTIFY_ADDR` | `localhost:9195` | The notify service (`sneakers.notify.v1.NotifyService`), for owner and informed-party notices. |
| `REDIS_URL` | (none) | Redis for cache invalidation between replicas. Unset or unreachable degrades to single-replica reads; the boot doesn't fail. |
| `VAULT_INVALIDATE_CHANNEL` | `vault:invalidate` | The Redis pub/sub channel for invalidations. The catalogue seed publishes on it too. |

### Connector worker identity

| Variable | Default | Meaning |
|---|---|---|
| `WORKLOAD_OIDC_*`, `WORKLOAD_AUDIENCE`, `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | | The same settings as above; with the issuer set, the connector's body token is checked by the OIDC verifier too. |
| `CONNECTOR_DEV_TOKEN` | `dev-connector-token` | The shared dev token for the connector's body token, used only outside production and only when no OIDC issuer is set (so with `WORKLOAD_AUTH=disabled`). |

[worker-identity.md](worker-identity.md) explains which verifier runs and what each setting does.

## Workflow service

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | `localhost:9091` | The vault, for check-out leases, rotation on check-in and the retention setting. |

The workflow service keeps its own tables (`workflow_schema_migrations`) and the saga engine's
tables in the same database.

## Tools

### `workflow-purge`

Deletes resolved access requests (and their comments) older than the retention window, then
exits. Run it from a daily scheduled job; the workflow service also runs the same purge once a day.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_DSN` | (required) | The workflow database. |
| `VAULT_ADDR` | (none) | When reachable, the window comes from the vault's `request_history_retention_days`. |
| `RETENTION_DAYS` | (none) | An explicit window in days; wins when greater than 0. |

The window is `RETENTION_DAYS`, else the vault setting, else 90 days.

### `seed-catalog`

Upserts the built-in secret-type catalogue (secret types, extension catalogue, connections) and
publishes a reload so running replicas pick it up. It writes no demo data.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_DSN` | (required) | The vault database. |
| `REDIS_URL`, `VAULT_INVALIDATE_CHANNEL` | as the vault | Where to publish the reload. Unset or unreachable only logs a warning. |

### `seed` (development and test only)

`seed <catalog|per-type|bulk|requests>` loads demo data. Never run it against production.

| Variable | Default | Used by |
|---|---|---|
| `DATABASE_DSN` | (required) | `catalog`, `bulk` |
| `VAULT_ADDR` | `vault:9091` | `per-type`, `bulk`, `requests` |
| `WORKFLOW_ADDR` | `workflow:9193` | `requests` |
| `SEED_FOLDER`, `SEED_USER` | `folder-personal-turing`, `user-turing` | `per-type` |
| `SECRET_TARGET` | (none) | `bulk` |

## Tests

| Variable | Meaning |
|---|---|
| `TEST_DATABASE_DSN` | A vault test database; the server must allow `CREATE DATABASE`, because some tests create their own. |
| `WORKFLOW_PG_DSN` | A workflow test database. |

Without them the Postgres integration tests are skipped.
