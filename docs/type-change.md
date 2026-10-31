# Changing a secret's type

A secret's type changes through one of two RPCs that share their code:

- `ChangeSecretType` is for a signed-in person with RACI Author on the secret, or the owner of its folder. Any other actor, a person's own token included, gets PermissionDenied. A per-secret deny on Author holds, unless the person owns the folder. There's no step-up, the same as `UpdateSecret`: the values stay sealed and are never shown.
- `ChangeSecretTypeForPrincipal` is for a token, service account or workload with RACI Author on the secret.

Any type may be converted into or out of any other, including the rotation and heartbeat types (Active Directory, Windows and database accounts) and the certificate type, with one exception: changing a plain checkout type (one without rotation or heartbeat) to a type without checkout is human-only, so only `ChangeSecretType` may do it. No approval request is involved. A retired secret is refused on both paths.

## Value rules

- Every non-empty value lands in a field of the new type, by the same key or through `field_mapping`. A value with nowhere to go is appended to the new type's notes field, or the call fails with `unmapped_fields = REFUSE`. Nothing is dropped.
- A sensitive value only moves into a sensitive field, and a super-sensitive value only into a super-sensitive field. Otherwise the call fails and names the fields.
- The new type's required fields, patterns and max lengths apply.
- The new values are sealed as a new active version. The previous values stay in version history.
  That version's `change_label` describes the change itself — "Type changed: <old type> → <new
  type>", naming any field added, renamed (`field_mapping`) or carried over, and any moved to
  notes — so history never reads as only "Changed: <field>" (#165). The response and the audit
  event's `change_label` attribute carry the identical text.
- The change is audited as `secret.type_change` for a person and `secret.type_change.principal` for a machine, with field keys only, never values.
- Dropping checkout from a plain checkout type (one without rotation or heartbeat) is human-only.

Nothing is ever lost, so a client never has to ask whether a value would be. The caller picks what happens to a value with no field through `unmapped_fields`: NOTES (the default) moves it to notes, and REFUSE fails the change naming the keys.

## Preview

`PreviewSecretTypeChange` takes the same inputs and the same access as `ChangeSecretType`, runs the same rules, and writes nothing: no version, no audit event, no schedule change. It returns field keys, never values.

A missing secret or type, no access, a retired secret or the type the secret already has are gRPC errors. A change the rules refuse is a normal response:

| Field | Meaning |
|---|---|
| `allowed` | Whether `ChangeSecretType` would succeed with these inputs. |
| `refusal_reason`, `refusal_message` | When not allowed, what `ChangeSecretType` would refuse with. |
| `field_changes` | Each stored non-empty field: `from_key`, `to_key`, `outcome` (CARRIED, RENAMED, MOVED_TO_NOTES or BLOCKED) and, when BLOCKED, the `reason`. |
| `missing_required_keys` | Required fields of the new type that nothing fills yet, to ask for through `fields`. |
| `notes_field_key` | The notes field values would move into. |
| `field_keys`, `change_label` | When allowed, the keys the new type would hold and the text the version would carry. |
| `rotation`, `heartbeat`, `target`, `from_target_id`, `target_id` | What automation would do, the same values as the audit attributes below. |

## Refusal reasons

Each refusal carries a `google.rpc.ErrorInfo` with domain `sneakers.vault`. Unless noted, its metadata `fields` lists the field keys involved, joined by commas.

| Reason | Code | When |
|---|---|---|
| `TYPE_CHANGE_UNMAPPED_FIELDS` | FailedPrecondition | A value has no field, under `unmapped_fields = REFUSE` or because the new type has no notes field. |
| `TYPE_CHANGE_LOWERS_PROTECTION` | FailedPrecondition | A value would land in a less protected field, the notes field included. |
| `TYPE_CHANGE_NOTES_TOO_LONG` | FailedPrecondition | Moving values to notes would pass its max length. |
| `TYPE_CHANGE_INVALID_FIELD` | InvalidArgument | A mapping or a value doesn't fit the new type: an unknown field, two values for one field, a max length or pattern, or a key pair that doesn't match. A key pair names no fields. |
| `TYPE_CHANGE_CERTIFICATE_INVALID` | InvalidArgument | The material doesn't validate as a certificate, or a stored value differs from the one derived from it. |
| `FIELD_VALUE_REQUIRED` | InvalidArgument | The new type requires a field nothing fills. Metadata `field`. |
| `FIELD_VALUE_NOT_ALLOWED` | InvalidArgument | A SELECT value isn't one of the options. Metadata `field` and `allowed`. |
| `ROTATION_IN_PROGRESS` | FailedPrecondition | A rotation of the secret is claimed. No metadata. |
| `TYPE_CHANGE_CHECKOUT_HUMAN_ONLY` | FailedPrecondition | A machine tried to drop checkout. No metadata. Never returned to a person. |
| `RETIRED` | FailedPrecondition | `ChangeSecretType` or the preview on a retired secret. No metadata. |

## Certificate type

- Into the certificate type: the `certificate` field must hold a PEM certificate and no key. `privateKey`, if set, must hold an unencrypted PEM private key, and `chain`, if set, PEM certificates. This is the parser `ImportCertificate` uses. The PEM values are stored as they are, and the metadata an import stores (subject, issuer, SANs, serial, fingerprint, validity, key algorithm and size, `hasPrivateKey`, `isCA`) is filled in from the certificate. A metadata field that already holds a different value is refused. The secret's expiry becomes the certificate's Not After.
- Out of the certificate type: the normal value rules apply. The private key is super-sensitive, so it needs a super-sensitive field in the new type. The certificate, chain and metadata may move into notes.

## Automation and target

| Change | Result |
|---|---|
| Into a rotation type | Rotation is opted out (`rotation_opt_out` true) and no rotation row exists until rotation is enabled with `SetSecretAutomation(ForPrincipal)`. |
| Into a heartbeat type | A heartbeat row is created only when the secret has a target with a connection (plus, for `type-ssh-key`, at least one pinned host key) and isn't opted out of heartbeat. |
| Out of a rotation or heartbeat type | Its rotation and heartbeat rows are removed, which also drops any claim on them. |
| Rotation in flight | While a rotation claim is live the call fails with FailedPrecondition. Retry once the rotation finishes. |
| Target | Kept when the new type takes a target (rotation, heartbeat, `type-ssh-key`, `type-unix-ssh`), otherwise every attached target is detached. |

The audit event records the outcome in its attributes:

- `rotation`: `none` or `off`.
- `heartbeat`: `none`, `scheduled`, `no_target` (no target with a connection) or `opted_out`.
- `target`: `none`, `kept` or `detached`, with `from_target_id` and `target_id`.

The response's `secret` carries the new type, target and opt-outs, so a caller can derive the same outcome.
