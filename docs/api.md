# API

Both services speak gRPC with plaintext transport and trust the actor context the caller sends.
Only the gateway, which sets that context from the signed-in session, should reach them. The full
definitions are [vault.proto](../proto/sneakers/vault/v1/vault.proto) and
[workflow.proto](../proto/sneakers/workflow/v1/workflow.proto); the generated Go is under
`gen/go/sneakers/`. Both servers also serve gRPC health and reflection. The vault's own calls to
audit and notify are covered in [Calling other services](#calling-other-services).

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
| Instance settings | `ListPasswordPolicies`, `SavePasswordPolicy`, `DeletePasswordPolicy`, `GetSecuritySettings`, `UpdateSecuritySettings`, `SeedBuiltins` |
| Keys | `GenerateKeyPair`, `RotateKek` |

### Rules the vault enforces

- **Values:** secrets are returned masked. A sensitive field comes back only through an audited
  reveal or copy. Values are stored and returned byte for byte, including trailing `=` and
  embedded newlines, on every path.
- **Access:** an ordered firewall-style RACI ruleset (C read and reveal, R author, A approve,
  I informed) on folders, secrets and targets, evaluated target first and then up the folder
  chain. Folder owners get read, approve and author. Site admins and root read everything but are
  never automatic approvers or authors.
- **Machine principals:** service accounts, workloads and personal tokens act only through the
  `*ForPrincipal` calls, which reject a human actor. Their admin flags are ignored, they never
  own a folder or target, and they get nothing from an `everyone` allow (an `everyone` deny still
  applies). There is no machine delete. A personal token may create folders in its own personal
  tree only; a service account never creates inside a personal tree. Names may not contain `/` or
  `\`. `RevealSecretFieldForPrincipal` also returns non-sensitive fields, audited as
  `secret.read.principal`.
- **Moves:** personal to shared is free. Shared to personal needs a site admin; for anyone else the
  vault moves nothing, answers `approval_required`, and the caller files a move request with the
  workflow service.
- **Versions:** every edit and rotation appends a version. A save that changes nothing mints none.
- **Automation:** `SetSecretAutomation` (or the principal variant, with RACI Author) opts a secret
  out of rotation or heartbeat; an opted-out secret has no schedule row. Rotation and heartbeat are
  scheduled only for a secret whose target has a connection; a manual rotation or heartbeat
  request without one answers `FailedPrecondition`.
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
- **Type changes:** see [type-change.md](type-change.md).
- **Catalogue:** built-in types change additively only. An existing store picks up new built-ins
  through `seed-catalog`.
- **Key rotation:** `RotateKek` runs as a human site admin, or as a `system:<name>` principal listed
  in `VAULT_KEK_ROTATION_PRINCIPALS`, sent with `principal_kind: PRINCIPAL_KIND_WORKLOAD`. The
  gateway never sends a workload actor, so that path is a direct call to the vault's gRPC port,
  which trusts the actor it's given. Scheduled rotations are audited as `system:kek-scheduler`.
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
- **Approvals:** an approved access request grants temporary read on the secret in the vault for
  the approver's chosen window (`grant_hours`, clamped to 1 to 24, default from the service), and
  check-in revokes it. Folder-move and secret-move requests are resolved by a site admin, and the
  approval performs the move.
- **Retention:** resolved requests and their comments are purged after
  `request_history_retention_days` (vault security settings, default 90), daily and at start.

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
