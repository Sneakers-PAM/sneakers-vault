# Service-to-service authentication

Every gRPC call between Sneakers services carries the caller's Kubernetes workload identity. The
code lives in `internal/workloadauth`. It imports no service code or protos, so the same files are
copied unchanged into each service; this repository holds the canonical copy.

## Caller side

The caller mounts a projected ServiceAccount token with audience `sneakers` at
`/var/run/secrets/sneakers/token` and names it in `WORKLOAD_TOKEN_FILE`. Each call sends it as
`authorization: Bearer <token>` gRPC metadata. The file is read again on every call, so a token
the kubelet rotates is picked up without a restart.

```go
opt, ok, err := workloadauth.DialOptionFromEnv(os.Getenv) // ok is false when WORKLOAD_TOKEN_FILE is unset
```

A set path that can't be read fails start-up. With the variable unset no token is sent, which
only works against a callee with authentication off (local development).

## Callee side

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | yes | | The cluster's ServiceAccount issuer. The token's `iss` must equal it exactly. Must be `https://`. |
| `WORKLOAD_OIDC_JWKS_URL` | no | discovered | JWKS URL. When unset, it's read from `jwks_uri` in `<issuer>/.well-known/openid-configuration`. Must be `https://`. |
| `WORKLOAD_OIDC_CA_FILE` | no | system roots | Extra PEM CA bundle trusted for discovery and the JWKS fetch. |
| `WORKLOAD_OIDC_BEARER_FILE` | no | | Bearer token sent on discovery and the JWKS fetch, re-read on every fetch. |
| `WORKLOAD_AUDIENCE` | no | `sneakers` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | yes | | Comma list of `<namespace>/<serviceaccount>`: the callee's callers in the call graph. |
| `WORKLOAD_AUTH` | no | | `disabled` turns authentication off. No other value is accepted. |

Authentication fails closed. `ServerConfigFromEnv` refuses to start a callee with no
`WORKLOAD_OIDC_ISSUER`, in every environment, unless `WORKLOAD_AUTH=disabled` is set. With that
flag every caller that reaches the port is trusted, so it's for local development and mock tooling
only: the charts never set it, and `WarnDisabled` logs a warning at start and every 5 minutes.
Setting both the issuer and the flag is refused too.

The verifier checks the signature (`RS256` or `ES256`, key by `kid`), `iss`, `aud`, `exp`, `nbf`
and `iat` (60 s skew), that `sub` is a service account on the list, and that the `kubernetes.io`
claim names the same one. Keys load at start, every 15 minutes and on an unknown `kid` (at most
every 30 s); a failed fetch keeps the last good set.

The service account `<namespace>/sneakers-<name>` is the caller `<name>`. The interceptors
(`UnaryServerInterceptor`, `StreamServerInterceptor`) then check the method's allow-list
(`workloadauth.Policy`, written in code by each service):

| Outcome | Code |
|---|---|
| No `authorization` metadata, or not a single `Bearer` value | `Unauthenticated` |
| Token rejected | `Unauthenticated` |
| No key set loaded yet | `Unavailable` |
| Caller not on the method's list | `PermissionDenied` |
| Caller listed as `Self` and the request carries an `actor` | `PermissionDenied` |

`Self` callers act only as themselves; `OnBehalf` callers may pass an end-user actor. The health
service is always exempt. Each refusal is logged (never the token) and handed to the
`WithDenyHook` hook, which the service uses to audit it. A handler reads the verified caller with
`workloadauth.GrantFromContext`.

## Copying the package

Copy `internal/workloadauth/` byte for byte, tests included. Change it here first, then copy the
new version into each service.
