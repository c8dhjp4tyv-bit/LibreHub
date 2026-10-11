# GitHub Actions OIDC federation (M7)

Workflows authenticate without any LibreHub secret in GitHub. The workflow asks GitHub for an
OIDC identity token (`permissions: id-token: write`), LibreHub verifies it with the
production verifier and returns a **short-lived credential bound to one project**.

```
GitHub OIDC identity ──► LibreHub federated authentication ──► project-scoped authorization
   ──► durable automation engine ──► M3/M1/M2/M5/M6 services ──► signed outbound events
```

External CI never touches flat-manager credentials, attestor keys or publisher tokens; it can only
start automations the project owner defined and wait for them.

## Server configuration

| Variable | Meaning |
| --- | --- |
| `LIBREHUB_OIDC_AUDIENCE` | Required to enable federation. Tokens must carry exactly this `aud`. |
| `LIBREHUB_OIDC_ISSUER` | Default `https://token.actions.githubusercontent.com`. Compared exactly with `iss`. |
| `LIBREHUB_OIDC_JWKS_URL` | Default `<issuer>/.well-known/jwks`. Must be https. |
| `LIBREHUB_OIDC_INSECURE_FOR_TESTS=1` | Allows an `http://` JWKS URL for local test issuers only. |

## Verification (`POST /api/v1/integrations/github/oidc/exchange`)

`Authorization: Bearer <GitHub JWT>`, body `{"project_id": "<uuid>"}`. Checks, in order:

* size ≤ 8 KiB and three base64url segments;
* algorithm exactly `RS256` (`none`, HMAC and others die here); headers `jku`, `jwk`, `x5u`,
  `x5c`, `crit`, `zip`, `cty` are refused (GitHub's `x5t` thumbprint hint is ignored; only `kid` selects a key); a `kid` must exist in the issuer's JWKS and
  RSA moduli below 2048 bits are rejected;
* RSASSA-PKCS1-v1_5/SHA-256 signature (ring);
* `iss` equals the configured issuer, `aud` contains the configured audience;
* `exp`/`iat` required, `nbf` honoured, 30 s leeway, lifetime ≤ 1 h;
* claims `repository`, `repository_id`, `repository_owner(_id)`, `ref`, `sha` (40 hex),
  `event_name`, `workflow_ref`, `jti`, `run_id`, `run_attempt` required; numeric IDs must be
  canonical digits; the `sub` must start with `repo:<repository>:` (so a subject naming another
  repository is refused).

**JWKS handling.** Keys are fetched only from the configured URL (https, redirects off, 3 s/8 s
deadlines, 256 KiB cap), cached 10 minutes, refreshed at most once per minute (also when an
unknown `kid` appears, once, then retried), kept up to 24 h if GitHub is unreachable and
otherwise fail closed (`503 oidc_keys_unavailable`). A token cannot influence key selection
beyond naming a `kid` already published by the issuer. The endpoint is limited to 120 requests/minute.

**Replay.** Every accepted `jti` is stored until it expires; a second exchange of the same token
is denied (`token_replayed` in the audit trail).

Failures: `401` with a specific `oidc_*` code for token problems; `403 oidc_exchange_denied` for
every policy refusal. The response never says which rule failed (to avoid a project/policy
oracle); the owner sees the reason in `GET …/integrations/audit`.

## Trust policy (deny by default)

Created by the project owner (`integrations:write`):

```json
POST /api/v1/projects/{id}/integrations/oidc
{ "name": "release workflow",
  "policy": {
    "repository_id": "1296269", "repository_owner_id": "583231", "repository": "octo/hello",
    "allowed_refs": ["refs/heads/main", "refs/tags/v*"],
    "allowed_workflows": ["octo/hello/.github/workflows/release.yml@*"],
    "allowed_environments": [],
    "allowed_event_types": ["push", "workflow_dispatch"],
    "allowed_permissions": ["projects:read", "builds:read", "automations:read", "automations:run"],
    "token_ttl_seconds": 600 } }
```

Find the IDs with `gh api repos/OWNER/REPO --jq '.id, .owner.id'`. Authorization uses the
**immutable numeric IDs**; `repository` is display-only, so a renamed repository keeps working and
a recreated same-name repository (new ID) does not. Every list must be non-empty except
`allowed_environments`: when empty the token must carry *no* `environment`; otherwise it must
match. `*` in patterns matches any characters including `/`. `allowed_workflows` match the
`workflow_ref` claim (the entry workflow in the trusted repository).

Pull requests: `pull_request` and `pull_request_target` identities are denied unless the event is
listed, and even then receive read-only scopes (`projects:read`, `builds:read`,
`publishes:read`, `automations:read`) — never `automations:run`.

## Issued credential

Same `librehub_<id>_<random>` format as ordinary tokens, stored hashed. It is bound to one
project (all other projects answer 404; global routes `/projects`, `/tokens`, `/audit`,
`/approvals` answer 403), expires after `token_ttl_seconds` (60–900, checked on every request),
has no refresh token and is revoked together with its integration. The only scopes a policy may
grant are `projects:read`, `builds:read`, `builds:write`, `publishes:read`, `automations:read`,
`automations:run`; `publishes:write`, `releases:approve`, `automations:write`,
`integrations:*`, `tokens:*`, `webhooks:write`, `audit:read` and `operator` are rejected when the policy is
created. A run triggered with such a credential takes its commit and ref from the *signed claims*
(`ci_commit_mismatch` otherwise), and stable promotion additionally requires an approved release
(`approval_required`), whatever the workflow says.

Audit (`GET /api/v1/projects/{id}/integrations/audit`, also mirrored into `/audit`):
`oidc.exchange_succeeded`, `oidc.exchange_denied` (with reason), `integration.created|updated|disabled|revoked`.
Tokens and identity tokens are never stored or logged.
