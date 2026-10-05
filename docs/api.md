# API

Both services speak gRPC with plaintext transport. Every call is authenticated with the caller's
workload identity and checked against a per-method allow-list (see [Callers](#callers)); only a
caller allowed to act on behalf of a user may send an actor context, which the gateway sets from
the signed-in session. The full
definitions are [vault.proto](../proto/sneakers/vault/v1/vault.proto) and
[workflow.proto](../proto/sneakers/workflow/v1/workflow.proto); the generated Go is under
`gen/go/sneakers/`. Both servers also serve gRPC health (go-buildinfo's,
`github.com/Bugs5382/go-buildinfo`) and reflection. The vault's own calls to
audit and notify are covered in [Calling other services](#calling-other-services).

A health check's answer carries the build in its response headers: `sneakers-version` (the image
tag, `dev` when unstamped) and `sneakers-commit` (the source commit, `unknown` when neither the
build nor Go's VCS stamp knows it). A readiness answer also carries `sneakers-dep-postgres` (the
first word of `server_version`, such as `16.4`; re-read every 5 minutes, `unknown` until the first
read succeeds) and `sneakers-depstate-<name>` (`ok`, `degraded` or `down`) for each dependency.
The gateway's diagnostics read them.

Both servers' health checks follow their dependencies:

- **Readiness** is service `""` (the default). It answers `NOT_SERVING` while a required
  dependency is down and `SERVING` otherwise, including while an optional one is failing
  (degraded). It recovers on its own once the dependency answers again.
- **Liveness** is service `liveness`. It always answers `SERVING` and checks no dependency, so an
  outage never restarts the pod.
- Any other service name gets `NOT_FOUND`. `Watch` streams the serving status of either service as
  it changes.

Each dependency is pinged with a 1-second timeout, and the results are reused for 5 seconds, so
probes don't load the dependencies. A readiness answer carries the results in the
`sneakers-health` header, as compact JSON:

```json
{"status":"degraded","ready":true,"dependencies":[
  {"name":"postgres","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z","version":"17.11"},
  {"name":"audit","state":"degraded","required":false,"error":"unavailable","checkedAt":"2026-10-05T12:00:00Z"}]}
```

`status` and `state` are `ok`, `degraded` (an optional dependency failing) or `down` (a required
one failing). `error` is a class: `timeout`, `refused`, `unavailable`, `unauthenticated` or
`error` (or go-buildinfo's `connection-refused`, `dns`, `network`, `canceled` or `panic`). It never carries the error's text, an address or a DSN. `version` is present when known.
See the [runbook](runbook.md#health) for each server's dependencies.

## Vault: `sneakers.vault.v1.VaultService`

| Area | RPCs |
|---|---|
| Secret types | `ListSecretTypes`, `CreateSecretType`, `UpdateSecretType`, `DeleteSecretType`, `CloneSecretType`, `ListAvailableExtensions`, `ImportExtension`, `ImportExtensionFromJson` |
| Folders | `ListFolders`, `CreateFolder`, `RenameFolder`, `MoveFolder`, `DeleteFolder`, `ReorderFolders` |
| Access rules | `GetFolderRuleset`, `SetFolderRuleset`, `GetMyAccess`, `SimulateFolder`, `SimulateSecret`, `GetSecretRuleset`, `SetSecretRuleset`, `GetMySecretAccess`, `GetTargetRuleset`, `SetTargetRuleset`; the older `ListFolderRules`, `GetInheritedFolderRules`, `AddFolderRule`, `RemoveFolderRule` |
| Secrets | `ListSecretsInFolder`, `GetSecret`, `CreateSecret`, `UpdateSecret`, `SetSecretAutomation`, `GetSecretFields`, `RevealSecretField`, `CopySecret`, `RetireSecret`, `RestoreSecret`, `DeleteSecret`, `ListSecretVersions`, `RevealSecretVersionField`, `BreakGlassSecret` |
| Dashboard | `GetSecretStats`, `GetTopAccessedSecrets`, `ListSecretsByStatus`, `FindSecretsByPublicKey` |
| Machine principals | `RevealSecretFieldForPrincipal`, `ListSecretsForPrincipal`, `CreateSecretForPrincipal`, `GenerateSecretForPrincipal`, `MoveSecretForPrincipal`, `ChangeSecretTypeForPrincipal`, `RenameSecretForPrincipal`, `UpdateSecretFieldsForPrincipal`, `ListFoldersForPrincipal`, `CreateFolderForPrincipal`, `RenameFolderForPrincipal`, `MoveFolderForPrincipal`, `SetSecretTargetForPrincipal`, `SetSecretAutomationForPrincipal`, `RequestHeartbeatForPrincipal`, `GetHeartbeatStatusForPrincipal` |
| Use without reveal | `PrepareSecretUse`, `GetSecretUse`, `ListPendingSecretUses`, `DecideSecretUse`, `RedeemSecretUse`, `CreateUseGrant`, `ListUseGrants`, `RevokeUseGrant`, `SetSecretTokenApproval` |
| Certificates | `ImportCertificate`, `ExportCertificate`, `ReplaceCertificate` |
| Connections and targets | `ListConnections`, `SaveConnection`, `DeleteConnection`, `ListTargets`, `SaveTarget`, `DeleteTarget` |
| Connector | `ClaimDueHeartbeats`, `RevealForHeartbeat`, `ReportHeartbeat`, `EnqueueRotation`, `ClaimDueRotations`, `RevealForRotation`, `ReportRotation` |
| Connector builds | `ListConnectors` |
| Instance settings | `ListPasswordPolicies`, `SavePasswordPolicy`, `DeletePasswordPolicy`, `GetSecuritySettings`, `UpdateSecuritySettings`, `SeedBuiltins` |
| Keys | `GenerateKeyPair`, `RotateKek` |
| Import | `SealForImport` |

### Rules the vault enforces

- **Connector builds:** every pull-API call whose worker identity verifies records that worker's
  last contact, and its build from the call's `sneakers-version` and `sneakers-commit` gRPC
  metadata (each capped at 128 bytes). A call without the metadata keeps the build the worker last
  sent. `ListConnectors` returns each worker's id, version, commit and last contact (RFC3339), by
  worker id, for the gateway's diagnostics, so the gateway never dials a connector. A failure to
  record is logged as a warning and never fails the pull call.
- **Values:** secrets are returned masked. A sensitive field comes back only through an audited
  reveal or copy. Values are stored and returned byte for byte, including trailing `=` and
  embedded newlines, on every path.
- **Access:** an ordered firewall-style RACI ruleset (C read and reveal, R author, A approve,
  I informed) on folders, secrets and targets, evaluated target first and then up the folder
  chain. Folder owners get read, approve and author. Site admins and root read everything but are
  never automatic approvers or authors.
- **Seeing secrets:** `ListSecretsInFolder` and `GetSecret` show a secret's metadata to anyone who
  can see its folder, even without read, so people can find a secret and request access. Each
  secret carries `can_read`, false when the caller can't read it. A secret an explicit deny
  covers, or one in someone else's personal tree, is hidden: left out of the list, and `NotFound`
  from `GetSecret`, audited as `secret.read.denied`. `GetSecretFields` returns field values, so it
  needs read (`PermissionDenied` with reason `NO_ACCESS` otherwise, audited the same way). A
  hidden secret's `NotFound` carries no reason, so it doesn't confirm the secret exists.
- **Group rules:** a GROUP rule saved with a `subject_id` (the directory group id) matches the
  caller's `group_ids` exactly, for people, personal tokens and service accounts alike;
  `subject_name` is then only the display name, so renaming a group changes nothing and another
  group that takes the old name gains nothing. A rule with only a `subject_name` (older rules)
  still matches the caller's `group_names`, ignoring case. `SimulateFolder` and `SimulateSecret`
  take `sim_group_ids` for the same matching.
- **Admin authority:** the vault checks it itself and doesn't rely on the gateway. Security
  settings, password policies, secret types, extensions, connections and `SeedBuiltins` need a
  human site admin or root whose actor names a real user (an empty or `system` user id never
  counts). Folder rules, renaming a folder and reordering a folder's children need the folder's
  owner or such an admin; reordering top-level folders needs an admin. A refusal is
  `PermissionDenied` with a `google.rpc.ErrorInfo` in domain `sneakers.vault`, reason
  `NOT_SITE_ADMIN` or `NOT_FOLDER_OWNER`, and is audited as `authz.denied` (method, reason).
- **Machine principals:** service accounts, workloads and personal tokens act only through the
  `*ForPrincipal` calls, which reject a human actor. Their admin flags are ignored, they never
  own a folder or target, and they get nothing from an `everyone` allow (an `everyone` deny still
  applies). There is no machine delete. A personal token may create folders in its own personal
  tree only; a service account never creates inside a personal tree. Names may not contain `/` or
  `\`. `RevealSecretFieldForPrincipal` also returns non-sensitive fields, audited as
  `secret.read.principal`.
- **Token approval** (`SetSecretTokenApproval`, `require_token_approval`) covers **personal
  tokens only**: with it on, a personal token's reveal of a sensitive field answers
  `approval_required` until the token's owner approves the use (or a use grant with
  `allow_reveal` covers it). It doesn't apply to service accounts, which have no person to
  approve: their reveals are governed by their RACI grants and by `allow_api_for_sensitive`
  (off by default, which keeps super-sensitive fields from them).
- **Runs of secret uses:** `PrepareSecretUse` takes an optional `run_id` and `purpose`, stored on
  the `SecretUse`, so the uses one agent run raises can be shown and decided on one page. `run_id`
  must match `[A-Za-z0-9_-]{1,64}`; `purpose` is at most 200 characters of plain text (valid
  UTF-8, no control characters such as newlines or tabs). Either one out of range is
  `InvalidArgument`. A run id only groups uses for display and grants nothing. Every
  `secret.use.*` audit event (prepare, approve, deny, redeem, and their refusals) carries
  `run_id`, empty for a use without one. `ListPendingSecretUses` takes an optional `run_id`
  filter: the signed-in owner lists all their pending uses or one run's; a personal token lists
  only its own token's pending uses, and only with a `run_id` (`PermissionDenied` without one).
  Deciding stays one use at a time through `DecideSecretUse`, with its own checks and audit.
- **Moves:** personal to shared is free. Shared to personal needs a site admin; for anyone else the
  vault moves nothing, answers `approval_required`, and the caller files a move request with the
  workflow service. A move is audited as `secret.move` (or `secret.move.principal`) with
  `from_folder_id` and `to_folder_id`, and mints no version.
- **Versions:** every edit and rotation appends a version. A save that changes nothing mints none.
  A field the record never stored and one stored as empty are the same value, so an editor that
  re-sends empty fields (on a folder move, say) adds no version, and the change list never names
  such a field.
- **Version history (recovery):** `ListSecretVersions` gives a human reader the change list
  (version numbers, authors, times, changed field keys), never values; machine principals are
  refused. Revealing a field of any version (`RevealSecretVersionField`) and
  `RestoreSecretVersion` need read on the secret plus the recovery role (`is_recovery`; site
  admin and root don't imply it) and an MFA within `MFA_MAX_AGE`. Otherwise `PermissionDenied`
  with reason `RECOVERY_ROLE_REQUIRED` or `STEP_UP_REQUIRED`, audited as `recovery.denied`.
  Both are recorded at the audit tier (`secret.version.reveal`, `secret.version.restore`).
- **Restore:** makes a prior version's fields the current ones as a new version. It changes only
  the vault's copy and is never pushed to a target: a managed target's heartbeat result goes to
  unknown and a heartbeat is queued, so drift shows. It's refused while a rotation is queued or
  running (`FailedPrecondition`, `ROTATION_IN_PROGRESS`). The gateway refuses it while the secret
  is checked out.
- **Automation:** `SetSecretAutomation` (or the principal variant, with RACI Author) opts a secret
  out of rotation or heartbeat; an opted-out secret has no schedule row. Rotation and heartbeat are
  scheduled only for a secret whose target has a connection; a manual rotation or heartbeat
  request without one answers `FailedPrecondition`.
- **What can rotate:** `EnqueueRotation` refuses a secret whose type has no rotation
  (`FailedPrecondition`, reason `ROTATION_NOT_SUPPORTED`) or that is opted out
  (`ROTATION_OPTED_OUT`). Nothing is queued, and the refusal is audited as `rotate.refused`. A
  check-in or break-glass rotation the vault refuses this way is skipped, so the lease still
  closes.
- **Heartbeat:** a FAILED check pauses that secret's heartbeat so a wrong password isn't retried
  into a lockout. It resumes, due at once, when a person changes the value, a rotation commits, or
  `RequestHeartbeatForPrincipal` is called (at most once a minute). Without a worker-identity
  verifier no connector can claim checks, so that request answers `FailedPrecondition`.
- **Built-in Administrator:** an Active Directory account the connector reports as RID 500 is
  never rotated (heartbeat still runs). Manual rotation and turning rotation back on answer
  `FailedPrecondition`; check-in and break-glass rotations are skipped so the lease still closes.
  `admin_count` (adminCount=1) is recorded but doesn't block rotation.
- **Connections:** `SaveConnection` (site admin only) changes `target_id` and
  `privileged_secret_id` only when the request sets them; a change of the privileged secret is
  audited as `connection.privileged_secret.change`.
- **SSH host keys:** `Target.ssh_host_keys` holds the host keys the SSH broker accepts for the
  target, one OpenSSH public key per entry in authorized_keys form (`ssh-ed25519 AAAA... comment`).
  They are public keys, not secrets. `SaveTarget` replaces the whole list: each entry must parse,
  carry no options, and be neither a private key nor a certificate (else `InvalidArgument`, naming
  the entry by position only); repeats of one key are dropped; at most 16 per target. Only a human
  site admin may add, change or clear them (`PermissionDenied` otherwise); anyone who may edit the
  target can save it with the pins it already has. A change is audited as
  `target.host_keys.change` with the SHA256 fingerprints `added` and `removed`, never the keys.
  `ListTargets` returns them. An empty list means the target isn't pinned, and the broker refuses
  to connect to it. They're stored in `target_ssh_host_keys` with their fingerprints.
  Heartbeat and rotation jobs carry them too (`HeartbeatTarget.ssh_host_keys`, empty for an
  unpinned target), so the connector can check the host before it sends a credential. It reports
  `HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED` or `HEARTBEAT_RESULT_HOST_KEY_MISMATCH` when it refuses;
  the vault records either as a failed check with the connector's reason (counted as drift,
  notified like a drift, audited as `secret.heartbeat.host_key`), but doesn't pause the schedule,
  because no credential was tried.
- **Type changes:** see [type-change.md](type-change.md).
- **Catalogue:** built-in types change additively only. An existing store picks up new built-ins
  through `seed-catalog`.
- **Key rotation:** `RotateKek` needs a human site admin or root (`NOT_SITE_ADMIN` otherwise),
  called through the gateway. The in-process scheduler rotates on its own and is audited as
  `system:kek-scheduler`.
- **Sensitive data switches:** with `allow_api_for_sensitive` off, a service account or
  personal token is refused super-sensitive fields on `RevealSecretFieldForPrincipal`,
  `PrepareSecretUse` and `RedeemSecretUse` (`PermissionDenied`, `API_SENSITIVE_DISABLED`, audited
  as `secret.reveal.denied`). Every refused reveal, copy or version reveal is audited the same
  way, with the reason (`NO_ACCESS`, `RETIRED`, `API_SENSITIVE_DISABLED`) and the action, and the
  refusal carries the same reason as an ErrorInfo (domain `sneakers.vault`): `NO_ACCESS` with
  `PERMISSION_DENIED`, `RETIRED` with `FAILED_PRECONDITION`. Step-up on reveal (`require_mfa_for_reveal`, overridden per folder
  by `SetFolderRevealStepUp`, site admin only) refuses a person's `RevealSecretField` or
  `CopySecret` without an MFA within `MFA_MAX_AGE` (`STEP_UP_REQUIRED`, audited as
  `secret.reveal.step_up_required`). See [configuration.md](configuration.md#security-settings).
- **Security settings:** before first-run setup has stored any (a store outside `dev`, `local`
  and `development` starts empty), `GetSecuritySettings` returns the defaults setup installs, and
  `UpdateSecuritySettings` starts from them.
- **Import:** `SealForImport` seals up to 500 field sets per call under the active working key and
  returns the envelopes in the form `secret_records` and `secret_versions` store, without storing
  anything. `sneakers-migrate import` uses it to re-wrap imported secrets, so the root key never
  leaves the vault. Only the migrate caller may call it, as itself (it sends no actor; the vault
  acts as `system:migrate`). With workload authentication disabled it's refused. Each call is
  audited as `vault.import.seal` with the item count.
- **Delete:** with `ENVIRONMENT` set to `prod` or `production`, hard delete needs a human site
  admin or root.

## Workflow: `sneakers.workflow.v1.WorkflowService`

| Area | RPCs |
|---|---|
| Leases | `ListActiveLeasesForUser`, `GetActiveLease`, `CheckoutSecret`, `CheckinSecret` |
| Approvals | `ListApprovalRequests`, `CreateAccessRequest`, `CreateFolderMoveRequest`, `CreateSecretMoveRequest`, `ResolveApproval`, `AddApprovalComment` |
| Rotation | `RotateSecret` |

### Rules the workflow service enforces

- **Check-out** runs as a saga: issue the lease, wait for check-in, rotate through the vault, then
  close the lease. If the run fails, a compensation releases the lease. A reaper closes leases
  that pass their expiry without a check-in, once a minute.
- **Sensitive check-out:** with `require_mfa_for_sensitive_checkout` on (the default), checking
  out a secret whose type has a super-sensitive field needs an MFA within `MFA_MAX_AGE`, or it's
  refused with `STEP_UP_REQUIRED` and audited as `checkout.denied`.
- **Who may check out:** the caller needs read (RACI C) on the secret, from the vault's
  `GetMySecretAccess` with the user's full context (groups, admin flags, MFA time), and the
  secret's type must have check-out on. A secret has at most one active lease (a unique index
  enforces it, so racing check-outs get one lease between them). Only the lease holder can check
  in, so nobody else can force a rotation.
- **Refusals** carry a `google.rpc.ErrorInfo` with domain `sneakers.workflow` and a stable reason:
  `CHECKOUT_NO_ACCESS` (`PermissionDenied`), `CHECKOUT_TYPE_DISABLED` (`FailedPrecondition`),
  `CHECKOUT_LEASE_HELD` (`FailedPrecondition`, metadata `holder_user_id`; also when approving an
  access request while someone else holds the secret, and the request stays pending), and
  `CHECKIN_NOT_HOLDER` (`PermissionDenied`).
- **Audit:** the workflow records, to the audit service (activity tier), never a value, a
  comment body or a reason's text:
  - `checkout` (lease id, expiry), `checkin` (lease id), `checkout.denied` and `checkin.denied`
    (reason), under the user, with the secret as subject;
  - `request.create` (kind, secret or folder ids), under the requester, with the request as
    subject;
  - `request.approve` (requester, secret, grant hours) and `request.deny`, under the approver;
    `approval.denied` (reason) for a refused resolve;
  - `request.comment` (comment id), under the author;
  - `lease.expire` (lease id, user, expiry), under `system:workflow`, when the reaper closes an
    expired lease.
- **Approvals:** an approved access request grants temporary read on the secret in the vault for
  the approver's chosen window (`grant_hours`, clamped to 1 to 24, default from the service), and
  check-in revokes it. Folder-move and secret-move requests are resolved by a site admin, and the
  approval performs the move.
- **Who may resolve:** approving or denying an access request needs RACI A on the secret (the
  vault's `GetMySecretAccess`); a move request needs a site admin naming a real user. Nobody
  resolves their own request. Refusals are `PermissionDenied` with reason `NOT_APPROVER` or
  `SELF_APPROVAL` (domain `sneakers.workflow`), audited as `approval.denied`, and the request
  stays pending.
- **Resolved once:** approving or denying a request that's already approved or denied is
  refused with `FailedPrecondition` and reason `REQUEST_NOT_PENDING` (domain
  `sneakers.workflow`), audited as `approval.denied`, and nothing changes: the first decision
  stands, and no lease, grant or move follows. The store checks and writes the status in one
  statement, so two approvers racing on one request can't both resolve it.
- **Retention:** resolved requests and their comments are purged after
  `request_history_retention_days` (vault security settings, default 90), daily and at start.

## Callers

Every call is authenticated with the caller's workload identity; see
[workload-auth.md](workload-auth.md). A service refuses to start without it unless
`WORKLOAD_AUTH=disabled` (local development only), in which case every caller is trusted as
before. Each service checks the caller against a per-method
allow-list in code (`CallerPolicy` in `internal/vault/grpcsvc/callers.go` and
`internal/workflow/grpcsvc/callers.go`). **On behalf** means the caller may pass an end-user
actor; **self** means it acts only as itself, and a request from it that carries an actor is
refused with `PermissionDenied`. Any caller or method not listed is refused.

- Codes: no token, or a token that fails verification, including a valid one from a service
  account that isn't on `WORKLOAD_ALLOWED_SERVICEACCOUNTS`: `Unauthenticated`. A listed caller on
  a method outside its allow-list, or a self caller that sends an actor: `PermissionDenied`. No
  issuer key set loaded yet: `Unavailable`.
- A refusal is audited as `rpc.denied` in the audit tier, under the actor `service:<caller>` (or
  `service:unauthenticated`), never under the user a request claimed. The attributes carry the
  method, caller, service account, code and reason, plus the claimed `user_id`, root, site-admin
  and principal-kind flags when the request had an actor. The workflow logs its refusals.
- The vault acts for the workflow as `system:workflow` (root on the workflow's methods only).
  The workflow sends no actor on those calls.
- The connector's pull-API also checks the worker identity in the request body
  ([worker-identity.md](worker-identity.md)).

| Service | Methods | Caller | Access |
|---|---|---|---|
| vault | every method except the connector pull-API, `SealForImport` and `ListConnectors` | gateway | on behalf |
| vault | `ListConnectors` | gateway | self (diagnostics) |
| vault | `RevealSecretField` | sshbroker | on behalf |
| vault | `SealForImport`, `RevealSecretField`, `GetSecret`, `ListTargets`, `ListConnections` | migrate (the sneakers-migrate Job) | self, as `system:migrate` (root) |
| vault | `GetMySecretAccess` | workflow | on behalf (the check-out check) |
| vault | `GetSecret`, `ListSecretTypes`, `GetSecretRuleset`, `SetSecretRuleset`, `MoveFolder`, `UpdateSecret`, `EnqueueRotation`, `GetSecuritySettings` | workflow | self |
| vault | `ClaimDueHeartbeats`, `RevealForHeartbeat`, `ReportHeartbeat`, `ClaimDueRotations`, `RevealForRotation`, `ReportRotation` | connector | self |
| workflow | every method | gateway | on behalf |

The vault itself calls audit and notify, and the workflow calls the vault, each with its own token.

## Calling other services

The vault never imports another service's Go module. It generates its own client stubs from each
callee's protos, pinned by commit:

- `proto-refs.env` pins each callee: `SNEAKERS_AUDIT_REF=<commit>` for `Sneakers-PAM/sneakers-audit`
  and `SNEAKERS_NOTIFY_REF=<commit>` for `Sneakers-PAM/sneakers-notify`.
- `scripts/proto-generate.sh` downloads only the callee's `proto/` at that commit into `.protos/`
  (git-ignored) and runs `buf generate`. The stubs land in `gen/go/thirdparty/audit/v1` and
  `gen/go/thirdparty/notify/v1`, inside this module, so they can't collide with the owner's Go
  packages. The stubs are committed, so a build needs no network; the protos never are.
- To try an unmerged proto change, point `SNEAKERS_AUDIT_PROTO_DIR` and `SNEAKERS_NOTIFY_PROTO_DIR`
  at a local `proto/` directory and run the script.
- To move to a newer callee, change its ref, run the script and commit `proto-refs.env` and `gen/`
  together. Build & Test fails when `gen/` doesn't match the pins.
- The `proto-sync` check (from `Sneakers-PAM/.github`) fails a PR whose pin isn't on the owner's
  `main` or that the owner's `main` breaks, and warns when `main` has moved on. On a schedule it
  opens a PR that bumps stale pins.
