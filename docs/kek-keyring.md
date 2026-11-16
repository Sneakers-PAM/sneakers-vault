# The key ring

How the vault protects secret values at rest, and how the key that protects them is rotated.
This is the design reference for anyone changing `internal/vault/crypto` or the `kek_*` and
`keyring_*` files in `internal/vault/grpcsvc`. For running it (start-up, rotating, dropping the dev
key) see [runbook.md](runbook.md#keys); for the settings see
[configuration.md](configuration.md).

## Three tiers

```text
root key (VAULT_ROOT_KEK, outside the database; wraps working keys only)
  └─ wraps → working keys kek-v1, kek-v2, ... (kek_keyring table, one active)
       └─ wraps → data key, one per secret (stored with the secret)
            └─ seals → each field value (AES-256-GCM)
```

- **Root key.** 32 bytes from `VAULT_ROOT_KEK`. It only ever wraps and unwraps working keys, never
  a data key or a value. It can be replaced with the previous-root support described below. In `dev`
  with no root key set, it's derived from `DEV_KEK_SEED`.
- **Working keys.** 32-byte keys the vault generates with `crypto/rand` and stores in
  `kek_keyring`, each wrapped under the root key and tagged with the root's ref (`root_ref`).
  Exactly one row is `active`, enforced by the partial unique index `kek_keyring_one_active`.
  At start-up every row is unwrapped into memory (`crypto.KeyringKEK`).
- **Data keys.** Each secret has its own data key. Its field values are sealed under it, and the
  data key is wrapped by the active working key. The secret stores the wrapped data key and the
  working key's ref (`KeyRef`); `secret_versions` rows store theirs the same way.

Rotating the working key only re-wraps each small wrapped data key. Field ciphertext and the data
keys themselves never change, and no value is decrypted during a rotation.

## Data flow

- **Seal** (create or update): a new data key seals the fields, then `WrapDEK` wraps it under the
  active working key and records that key's ref.
- **Open** (reveal, check-out, rotation): `UnwrapDEK` picks the working key by the stored ref. A
  ref that isn't in the ring is an error, never an empty or wrong value.
- **Rotate** (`rotateOnce`, shared by the `RotateKek` RPC and the scheduler):
  1. load the ring and mint the next ref (`kek-v<n+1>`);
  2. generate the key, wrap it under the root and insert it as the active row, flipping the old
     one in the same transaction;
  3. re-wrap every in-memory secret record not on the new ref and persist the result, in one
     serialized write, so a stale snapshot can never overwrite a peer's newer writes;
  4. publish a cache invalidation, so the other replicas reload the ring (`reconcileKeyring`) and
     the records;
  5. re-wrap `secret_versions` in the database, in batches;
  6. stamp `retired_at` on every generation that no record or version references any more.

## Invariants

- **No generation is ever deleted.** A retired generation stays in the ring, decrypt-only, so
  every row can always be opened under the ref it's on, whatever step a rotation stopped at.
- **Every step is idempotent.** The stored ref is the progress marker: a re-run touches only rows
  that aren't on the active ref yet, so running `RotateKek` again finishes a failed run.
- **One rotation at a time** per process. A second caller gets a no-op that reports the active
  ref; across replicas the write lock serializes the sweep.
- **Fail closed at start-up.** The root key must unwrap every stored working key before any
  migration runs. A missing, malformed or wrong root key stops the vault with the schema
  untouched.
- **Key material never leaves the process.** No root key, working key or data key is logged,
  audited or returned. The `kek.rotate` audit event and the RPC response carry refs, counts, the
  outcome and who rotated it, nothing else.

## Who can rotate

- A human site admin, through `RotateKek` (`requireSiteAdmin`).
- The in-process scheduler, every `KEK_SCHEDULER_CHECK_MINUTES`, when the active key is older
  than the security setting `kek_rotation_days`. `0` turns automatic rotation off; manual
  rotation still works. It audits as `system:kek-scheduler`.

No workload principal can call `RotateKek`.

## The static dev key

`dev-static-v1` is a decrypt-only member of the ring, derived from the dev seed. It exists so data
sealed by the original single-key provider still opens. The first rotation moves every row off
it; `VAULT_DISABLE_DEV_STATIC_KEK=true` then drops it, and the vault refuses to boot with that
set while any row still uses it.

## Failure modes

| Failure | Effect | Recovery |
|---|---|---|
| Root key missing or wrong at start-up | The vault exits before migrating. | Supply the right `VAULT_ROOT_KEK`. |
| `VAULT_ROOT_KEK_PREVIOUS` malformed, equal to the current key, set without `VAULT_ROOT_KEK`, or unable to open a key on the previous root | The vault exits before migrating or moving anything. | Supply the key that was the root before. |
| The move to the new root fails | Status `failed`, `pending` working keys not moved; the stored ring is unchanged and the vault serves with both roots. | Fix the cause and restart: the next start finishes it. |
| A stored ref the ring can't unwrap | Logged at error level at start-up; those secrets can't be opened. | Restore the missing working key's row and its root key. |
| The record sweep fails | The new generation is active; un-swept rows stay on their old ref and stay readable. | Run `RotateKek` again. |
| The version sweep fails | Records are on the new ref; some versions stay on older refs and stay readable. | Run `RotateKek` again. |
| Retirement bookkeeping fails | Logged as a warning; the rotation still succeeds. | The next rotation retires them. |

## Replacing the root key

`VAULT_ROOT_KEK_PREVIOUS` is the root key being replaced. With it set next to the new
`VAULT_ROOT_KEK`, the vault holds both roots (`crypto.RootKEKs`):

- Each working key is opened under the root its `root_ref` names. The new root's ref is derived from
  the key (`crypto.RootRef`, `root-` and eight hex digits), so the two roots are told apart; any
  other ref, including the unrotated `root-v1`, means the previous root. With no previous key set,
  every ref opens under the one root, as before.
- New wrapping always uses the current root.
- At start, after the migrations, every working key still on the previous root is re-wrapped under
  the current root and its `root_ref` updated. Each new wrapping is checked to open under the
  current root alone and to give the same key before anything is written, and the batch is one
  transaction, so a failure leaves the stored ring exactly as it was. A key another replica moved
  first is left alone. A restart, or a start with every key already on the current root, changes
  nothing.
- Then every working key is read back under the current root alone. Only then does the status read
  `verified`.
- The root key wraps only working keys, so no secret value or data key is re-encrypted.
- The vault never deletes a working key and never drops the previous key. Retiring it is the
  operator's step, after the status reads `verified`.

The status is a response header on the gRPC health check (readable on the boot-time health service
too): `sneakers-root-key: {"state":"none|in-progress|verified|failed","pending":N}`, where `pending`
is the number of working keys not yet on the current root. On the plain `HEALTH_PORT` when mutual TLS
is on. The health service `root-key-rotation` answers SERVING for `none` and `verified`. It carries
no key, wrapped key or key name, and the log carries counts only. A `failed` vault keeps serving, since
it still opens the ring with both roots, and retries at the next start.

## Out of scope

- **HSM and cloud KMS root providers.** The root is behind the same `KEKProvider` interface as the
  working keys, so a hardware or KMS-backed root can replace it; see
  [sneakers-vault#41](https://github.com/Sneakers-PAM/sneakers-vault/issues/41).
- **An admin view of the ring** (generations, ages, row counts per ref). The start-up report logs
  the counts today.
