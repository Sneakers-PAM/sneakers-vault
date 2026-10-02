# Runbook

## Vault start-up

At start the vault:

1. reads its configuration (it exits if `DATABASE_DSN` is missing);
2. starts OpenTelemetry export, and opens client connections to audit and notify;
3. resolves the root key (`VAULT_ROOT_KEK`, or the dev seed in `dev`) and checks it can unwrap
   the stored key ring, **before** any migration runs. A missing, malformed or wrong root key
   exits with the schema untouched;
4. applies the migrations in `MIGRATIONS_DIR` using `MIGRATE_DSN` (or `DATABASE_DSN`);
5. builds the key ring, seeding the first working key (`kek-v1`) on a fresh database, and logs a
   report of how many stored rows use each key ref (refs and counts only, never key material);
6. loads the store into memory; in `dev`, `local` and `development` it also installs the
   built-in baseline;
7. starts the automatic key rotation scheduler, the connector worker-identity verifier and, with
   `REDIS_URL`, the cache invalidation subscriber;
8. serves gRPC on `GRPC_PORT`.

A failure in steps 1 to 5 is logged at fatal level and the process exits non-zero. Stored rows
that reference a key ref the ring can't unwrap are logged at error level; those secrets can't be
opened until the right key is back.

## Workflow start-up

The workflow service applies its own migrations (version table `workflow_schema_migrations`) and
the saga engine's, connects to Postgres and the vault, starts the lease reaper (every minute) and
the history purge (at start, then daily), and serves gRPC on `GRPC_PORT`.

## Health

```bash
grpcurl -plaintext localhost:9091 grpc.health.v1.Health/Check   # vault
grpcurl -plaintext localhost:9193 grpc.health.v1.Health/Check   # workflow
```

## First-run setup

Outside `dev`, a new vault starts empty. The gateway's first-run setup creates the first
administrator in identity, then calls `SeedBuiltins`, which installs the secret types, extension
catalogue, default password policies, connections, the personal folder root and that
administrator's personal folder. `SeedBuiltins` is idempotent.

## Keys

- **Root key** (`VAULT_ROOT_KEK`): wraps the working keys. It's permanent for a database: there is
  no previous-root support, so losing it makes every secret unrecoverable. Keep it in your secret
  store and back it up separately from the database.
- **Working keys** (`kek-v1`, `kek-v2`, ...): wrap each secret's data key. The active one seals new
  data; older ones stay in the ring, decrypt-only, until nothing references them.
- **Dev seed** (`DEV_KEK_SEED`): only in `dev`, and public in the source. Never run real data on it.

### Rotating the working key

`RotateKek` mints a new working key, makes it active, re-wraps every stored record and version
onto it, and marks generations nothing references any more as retired. It's safe to re-run; a
failed sweep resumes on the next run. Callers:

- a human site admin, through the gateway;
- the scheduler, when the active key is older than `kek_rotation_days` (security settings; `0`
  turns it off), checked every `KEK_SCHEDULER_CHECK_MINUTES`;
- a `system:<name>` principal listed in `VAULT_KEK_ROTATION_PRINCIPALS`, called directly on the
  vault's gRPC port with `principal_kind: PRINCIPAL_KIND_WORKLOAD`. Leave the list empty unless an
  operator task needs it, because that port trusts the actor it's given.

Other replicas pick up the new generation through the cache invalidation channel, or at their
next restart without Redis.

### Dropping the static dev key

The key ring holds `dev-static-v1`, the static dev key, derived from the dev seed. It is
decrypt-only: it opens data sealed with the static dev key and seals nothing new. To drop it:

1. run `RotateKek`, which re-wraps every row that still uses it;
2. check the boot report shows `dev_static_rows=0`;
3. set `VAULT_DISABLE_DEV_STATIC_KEK=true` and restart. The vault refuses to boot with it set while
   any row still uses the key.

## Replicas

Every mutating call runs as one serialized write across replicas (a Postgres advisory lock), on
freshly reloaded state, and is persisted in the same transaction; a persist failure fails the
call with `Unavailable`. With `REDIS_URL` set, each write publishes an invalidation and the other
replicas reload. Without Redis, run a single replica.

## Connector

The connector polls `ClaimDueHeartbeats` and `ClaimDueRotations`. Set up its identity as in
[worker-identity.md](worker-identity.md). With no verifier (production without
`WORKLOAD_OIDC_ISSUER`) every connector call answers `Unavailable`.

## Catalogue updates

Run `seed-catalog` after each deploy (the `seed-catalog` image) to upsert new built-in types into
an existing store. It publishes a reload, so running replicas pick the change up without a
restart.

## Request history

Resolved access requests are deleted after the retention window. The workflow service runs the
purge daily; run the `workflow-purge` tool from the `workflow` image as a scheduled job when the
service's own schedule isn't enough (for example, with replicas that restart often).

## Demo data

`seed` (the `seed` image) loads demo data for development and test environments:
`catalog`, `per-type`, `bulk` and `requests`. Never run it against production; no service image
ships it.
