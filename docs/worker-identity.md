# Connector worker identity

The connector pull-API (`ClaimDueHeartbeats`, `RevealForHeartbeat`, `ReportHeartbeat`, `ClaimDueRotations`, `RevealForRotation`, `ReportRotation`) and the workload reveal path are gated by a worker-identity verifier. The connector sends its token in the request body as `identity.token` (`WorkerIdentity.token`), the raw token string with no `Bearer ` prefix. There is no gRPC metadata involved.

## Which verifier runs

| Environment | `WORKLOAD_OIDC_ISSUER` set | Verifier |
|---|---|---|
| any | yes | OIDC (projected ServiceAccount tokens) |
| `prod` / `production` | no | none: every connector call returns `Unavailable` |
| anything else | no | dev shared token (`CONNECTOR_DEV_TOKEN`, default `dev-connector-token`) |

The dev token is never accepted in prod. If both the OIDC settings and `CONNECTOR_DEV_TOKEN` are set outside prod, the OIDC verifier wins.

The verifiers live in `internal/vault/workloadid`. Vault only picks one at boot (`cmd/vault/worker_identity.go`).

## OIDC settings

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | yes | | The cluster's ServiceAccount issuer. The token's `iss` must equal it exactly. Must be `https://`. |
| `WORKLOAD_OIDC_JWKS_URL` | no | discovered | JWKS URL. When unset, it's read from `jwks_uri` in `<issuer>/.well-known/openid-configuration`. Must be `https://`. |
| `WORKLOAD_OIDC_CA_FILE` | no | system roots | Extra PEM CA bundle trusted for discovery and the JWKS fetch, such as the in-cluster API server CA. |
| `WORKLOAD_OIDC_BEARER_FILE` | no | | File holding a bearer token sent on discovery and the JWKS fetch. It's re-read on every fetch, so a projected token rotated by the kubelet keeps working. |
| `WORKLOAD_AUDIENCE` | no | `sneakers-vault` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | yes | | Comma list of `<namespace>/<serviceaccount>`. Matched exactly against `sub` = `system:serviceaccount:<namespace>:<serviceaccount>`. |

Vault refuses to boot when the issuer is set and the allow-list is missing or has a malformed entry, when a URL isn't `https://`, or when the CA or bearer file can't be read.

## Token checks

- Signature: `RS256` or `ES256` only, key looked up by `kid`. A token without a `kid` is rejected.
- `iss` equals the issuer exactly, `aud` contains the audience, and `exp` is required.
- `exp`, `nbf` and `iat` are checked with at most 60s clock skew.
- `sub` is on the allow-list. When the token carries a `kubernetes.io` claim, its `namespace` and `serviceaccount.name` must match `sub`. A malformed claim counts as a mismatch.

The worker id recorded in audit (`connector:<namespace>/<serviceaccount>`) is the allow-listed entry.

## JWKS cache and failures

- Keys are fetched at boot, every 15 minutes, and when a token has an unknown `kid` (at most once every 30s).
- A failed fetch keeps the last good set and is logged at error with the reason.
- With no set loaded yet (issuer unreachable since boot), connector calls return `Unavailable`, never success.
- A bad, expired or wrong-audience token, or a subject not on the list, returns `PermissionDenied` and is audited as `heartbeat.denied`, `rotate.denied` or `reveal.principal.denied`. The log gives the reason, never the token.

## Finding the cluster issuer

From a shell with a kubeconfig for the cluster:

```sh
kubectl get --raw /.well-known/openid-configuration
```

`issuer` is the value for `WORKLOAD_OIDC_ISSUER`, and `jwks_uri` is where the keys are published. To see the keys:

```sh
kubectl get --raw /openid/v1/jwks
```

When the issuer URL isn't reachable from inside the cluster, or the API server doesn't serve discovery anonymously, point vault at the in-cluster endpoint instead:

```text
WORKLOAD_OIDC_ISSUER=<issuer from the discovery document>
WORKLOAD_OIDC_JWKS_URL=https://kubernetes.default.svc/openid/v1/jwks
WORKLOAD_OIDC_CA_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
WORKLOAD_OIDC_BEARER_FILE=/var/run/secrets/kubernetes.io/serviceaccount/token
WORKLOAD_ALLOWED_SERVICEACCOUNTS=<connector namespace>/<connector serviceaccount>
```

The bearer must belong to a ServiceAccount allowed to read the issuer discovery endpoints (the default `system:service-account-issuer-discovery` ClusterRole).

The connector gets its token from a projected `serviceAccountToken` volume with audience `sneakers-vault`, which its deployment sets up.
