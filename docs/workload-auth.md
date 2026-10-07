# Service-to-service authentication

Every gRPC call between Sneakers services carries the caller's Kubernetes workload identity. The
verifier, the interceptors and the caller credentials come from the owner's helper package
[`github.com/Bugs5382/go-workload-identity`](https://github.com/Bugs5382/go-workload-identity)
(v1.0.0), imported as `workloadauth`. The service sets its Sneakers values explicitly in
`internal/server/workloadauth.go` (`WorkloadConfigFromEnv`), so it relies on no default of the
package.

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
| `WORKLOAD_SERVICEACCOUNT_PREFIX` | | | Not read. The caller-name prefix is always `sneakers-`. |

Authentication fails closed. `WorkloadConfigFromEnv` refuses to start a callee with no
`WORKLOAD_OIDC_ISSUER`, in every environment, unless `WORKLOAD_AUTH=disabled` is set. With that
flag every caller that reaches the port is trusted, so it's for local development and mock tooling
only: the charts never set it, and `WarnDisabled` logs a warning at start and every 5 minutes.
Setting both the issuer and the flag is refused too.

The verifier checks the signature (`RS256` or `ES256`, key by `kid`), `iss`, `aud`, `exp`, `nbf`
and `iat` (60 s skew), that `sub` is a service account on the list, and that the `kubernetes.io`
claim names the same one. Keys load at start, every 15 minutes and on an unknown `kid` (at most
every 30 s); a failed fetch keeps the last good set.

The service account `<namespace>/sneakers-<name>` is the caller `<name>` (the package's
`ServiceAccountPrefix`, set to `sneakers-`). The interceptors
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

## The dependency

Every Sneakers service imports the same release of `go-workload-identity`; there is no local copy
to keep in step. A fix to token checking goes into the package and reaches each service as a
version bump. `internal/server/workloadauth_tokens_test.go` pins which tokens the vault accepts and
refuses (wrong audience, wrong issuer, expired, a caller not on the method's list), so a bump that
changes that fails here.

## Readiness

`server.WorkloadAuth` returns the verifier it built, alongside the server options. Both the vault
and the workflow process register it as a required dependency (`server.WorkloadIdentity`) on
their readiness checker: `/readyz` and the gRPC health check answer `NOT_SERVING`, and the
`workload-identity` entry in the readiness body reports `down`, until the issuer's key set has
loaded. It's left out of the dependency list when authentication is disabled
(`WORKLOAD_AUTH=disabled`), since there's then no verifier to wait on. A later failed JWKS refresh
keeps the last good key set, so once ready the dependency stays ready (see `Verifier.Ready`).
Liveness is unaffected.
