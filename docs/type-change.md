# Changing a secret's type

`ChangeSecretTypeForPrincipal` changes a secret's type for a token, service account or workload with RACI Author on the secret. Any type may be converted into or out of any other, including the rotation and heartbeat types (Active Directory, Windows and database accounts) and the certificate type. No approval is needed.

## Value rules

- Every non-empty value lands in a field of the new type, by the same key or through `field_mapping`. A value with nowhere to go is appended to the new type's notes field, or the call fails with `unmapped_fields = REFUSE`. Nothing is dropped.
- A sensitive value only moves into a sensitive field, and a super-sensitive value only into a super-sensitive field. Otherwise the call fails and names the fields.
- The new type's required fields, patterns and max lengths apply.
- The new values are sealed as a new active version. The previous values stay in version history.
- The change is audited as `secret.type_change.principal` with field keys only, never values.
- Dropping checkout from a plain checkout type (one without rotation or heartbeat) is still human-only.

## Certificate type

- Into the certificate type: the `certificate` field must hold a PEM certificate and no key. `privateKey`, if set, must hold an unencrypted PEM private key, and `chain`, if set, PEM certificates. This is the parser `ImportCertificate` uses. The PEM values are stored as they are, and the metadata an import stores (subject, issuer, SANs, serial, fingerprint, validity, key algorithm and size, `hasPrivateKey`, `isCA`) is filled in from the certificate. A metadata field that already holds a different value is refused. The secret's expiry becomes the certificate's Not After.
- Out of the certificate type: the normal value rules apply. The private key is super-sensitive, so it needs a super-sensitive field in the new type. The certificate, chain and metadata may move into notes.

## Automation and target

| Change | Result |
|---|---|
| Into a rotation type | Rotation is opted out (`rotation_opt_out` true) and no rotation row exists until rotation is enabled with `SetSecretAutomation(ForPrincipal)`. |
| Into a heartbeat type | A heartbeat row is created only when the secret has a target with a connection and isn't opted out of heartbeat. |
| Out of a rotation or heartbeat type | Its rotation and heartbeat rows are removed, which also drops any claim on them. |
| Rotation in flight | While a rotation claim is live the call fails with FailedPrecondition. Retry once the rotation finishes. |
| Target | Kept when the new type takes a target (rotation, heartbeat, `type-ssh-key`, `type-unix-ssh`), otherwise detached. |

The audit event records the outcome in its attributes:

- `rotation`: `none` or `off`.
- `heartbeat`: `none`, `scheduled`, `no_target` (no target with a connection) or `opted_out`.
- `target`: `none`, `kept` or `detached`, with `from_target_id` and `target_id`.

The response's `secret` carries the new type, target and opt-outs, so a caller can derive the same outcome.
