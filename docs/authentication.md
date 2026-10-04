# Developer API authentication

Run offline bootstrap before starting the API (the existing supervisor data lock
prevents a second process from altering a running instance). Select the same
`LIBREHUB_DATA_DIR` and optional `LIBREHUB_DATABASE_PATH` for both:

```bash
cargo build --workspace --locked
export LIBREHUB_DATA_DIR=data
./target/debug/librehub-admin create-developer "Example Developer"
# Copy the developer id from the JSON response:
./target/debug/librehub-admin create-token <DEVELOPER_ID> "local development"
```

The token creation JSON has `id`, `developer_id`, `name`, `scopes`, timestamps and
`token`. Save the raw token from this response in a secret manager. It is returned
once and cannot be retrieved later. The admin tool writes no raw token to disk.
Add `--operator` only for an operator who must access historical unowned M1/M2
builds; this scope cannot be issued by public token-management handlers.

```bash
export LIBREHUB_TOKEN='<the one-time token>'
curl http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer $LIBREHUB_TOKEN"
curl -X POST http://localhost:8080/api/v1/tokens \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"read-only","scopes":["projects:read","builds:read"]}'
curl http://localhost:8080/api/v1/tokens \
  -H "Authorization: Bearer $LIBREHUB_TOKEN"
curl -X DELETE http://localhost:8080/api/v1/tokens/<TOKEN_ID> \
  -H "Authorization: Bearer $LIBREHUB_TOKEN"
```

Tokens contain a UUID identifier and 256 bits of OS-generated random entropy.
SQLite stores SHA-256 of the complete token and typed token metadata; it never
stores the token itself. UUID lookup bounds verification work, followed by
constant-time digest equality, developer-status and revocation checks. High random
entropy makes offline hash brute force infeasible; password hashing is not needed
for machine-generated 256-bit secrets. Token metadata includes last_used_at and
revoked_at. Revocation applies to subsequent requests; a request already admitted
may finish. Created tokens must be subsets of the caller's scopes. The bootstrap
path is local administrative access, with no unauthenticated token endpoint.

Scopes: projects:read/write, builds:read/write, publishes:read/write,
webhooks:write, tokens:read/write, audit:read. `operator` is an offline-only legacy
resource capability. Tokens never grant cross-developer access. Scope selection
and ownership checks are centralized in middleware; project handlers additionally
resolve ownership before any mutation. Unknown/foreign owned IDs return 404.
Malformed/revoked tokens return 401 without echoing credentials. Bearer headers
are removed before downstream handling. Secret wrappers redact Debug output.
Use TLS and a protected gateway with request-rate controls for public deployment;
never pass bearer values in URLs or shell command arguments to Git/build tools.

Webhook secrets must remain recoverable to verify HMAC. They are encrypted using
XChaCha20-Poly1305, a random 192-bit nonce, and project ID as authenticated associated
data. The random 256-bit key lives in `<data>/webhook.key`, mode 0600, separate from
SQLite. Back up this file with metadata and keep it out of published artifacts.
Losing it invalidates webhook verification; there is no public key recovery path.
Git subprocess environments are cleared; build containers get neither this key
nor API/webhook/publisher secrets. Rotation atomically replaces encrypted secret
material; no overlap with the prior secret is supported.
