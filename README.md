# LibreHub

LibreHub is an open Flatpak build and distribution platform. **M1 — Build
Prototype** accepts standalone JSON/YAML manifests, validates them, queues durable
jobs, builds in disposable containers, and preserves logs and `.flatpak` bundles.
**M2 — Repository & Install** adds durable publication through flat-manager, signed
OSTree repositories, and installation with standard Flatpak clients.
**M3 — Developer Platform** adds scoped developer tokens, owned Git projects,
immutable source snapshots, signed webhooks and optional automatic publication.
**M4 — Public Store & Catalog** adds a publication-derived AppStream catalog, FTS5
search, a real web store and signed per-app Flatpak references.
**M5 — Trust, Security & Moderation** adds verified publisher domain ownership,
cryptographically tied SPDX 2.3 JSON SBOM generation, release-to-release Flatpak
permission diffing, OSV-compatible vulnerability scanning, catalog visibility
gating, abuse reporting, and store trust badges.

## Developer workflow

Bootstrap before starting the API (the admin commands use the same data directory):

```bash
cargo build --workspace --locked
./target/debug/librehub-admin create-developer "Example Developer"
./target/debug/librehub-admin create-token <DEVELOPER_ID> "local development"
export LIBREHUB_TOKEN='<one-time token from the create-token JSON>'
```

Start the Compose/publisher/API stack below, then register a public Git project:

```bash
curl -X POST http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"hello","display_name":"Hello","repository":{"provider":"github","url":"https://github.com/example/hello"},"default_branch":"main","auto_build":true,"build_branches":["main"],"build_tags":true,"auto_publish_channel":"beta"}'
# Save project.id and the one-time webhook_secret from the response.
curl -X POST http://localhost:8080/api/v1/projects/<PROJECT_ID>/builds \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  -H 'Content-Type: application/json' -d '{"ref":"main"}'
# Returns reserved build_id + source_event_id. Poll source processing first:
curl -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  http://localhost:8080/api/v1/projects/<PROJECT_ID>/source-events/<SOURCE_EVENT_ID>
curl -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  http://localhost:8080/api/v1/projects/<PROJECT_ID>/builds
```

After the source event completes, the existing build/status/log APIs use build_id.
Set a GitHub push/create webhook to `/api/v1/webhooks/github/<PROJECT_ID>` with the
returned secret. Signed allowed commits/tags create durable deduplicated events.
Remove auto_publish_channel (or set null/none) for manual publishing. Public HTTPS
smart Git is supported; the public store is available in M4.
See [developer-platform.md](docs/developer-platform.md),
[source-integration.md](docs/source-integration.md), [webhooks.md](docs/webhooks.md)
and [M3 verification](docs/m3-verification.md).

## Build, publish, and install

Requirements: Rust stable (edition 2024), a C compiler for bundled SQLite, Linux,
Python 3, Docker with Compose and daemon access, `flatpak`, `ostree`, `gpg`,
and support for nested unprivileged user namespaces.
Use a dedicated development/build host. The API defaults to localhost; developer,
build and publishing APIs require bearer tokens. Read [security.md](docs/security.md)
and [authentication.md](docs/authentication.md) before enabling access.

```bash
cargo build --locked
cargo test --workspace --locked
# Downloads and seeds the Freedesktop Platform and SDK 25.08 in the image.
# Allow several GiB of disk space and time for the first build.
export LIBREHUB_DEV_UID=$(id -u) LIBREHUB_DEV_GID=$(id -g)
docker compose up -d --build
sh scripts/wait-repository-bootstrap.sh
# After successful bootstrap completion, load public trust and scoped token:
. data/dev/publisher.env
cargo run -p librehub-api --bin librehub-api
```

Compose provisions the worker image, PostgreSQL, flat-manager, ephemeral development
signing and nginx at `http://localhost:8090`. The API runs on the host and launches
one new container per build; no container receives the Docker socket. The
bootstrap credentials and signing key expire after one day. Recreate the disposable
stack to generate new signing material; see [repository.md](docs/repository.md). Alternatively, build the image directly:

```bash
docker build -f infra/docker/worker.Dockerfile -t librehub-worker:m1 .
```

Submit and inspect a build:

```bash
curl -X POST http://localhost:8080/api/v1/builds \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/org.librehub.Hello.json
# Returns HTTP 202: {"id":"<BUILD_ID>","status":"queued"}
curl -H "Authorization: Bearer $LIBREHUB_TOKEN" http://localhost:8080/api/v1/builds/<BUILD_ID>
curl -H "Authorization: Bearer $LIBREHUB_TOKEN" 'http://localhost:8080/api/v1/builds/<BUILD_ID>/logs?after=0&limit=200'
```

YAML also works with `Content-Type: application/yaml` and
`@examples/org.librehub.Hello.yaml`. An optional JSON envelope accepts
`{"manifest":"<JSON or YAML text>","format":"yaml","architecture":"x86_64"}`.
The default image supports `org.freedesktop.Platform` and `org.freedesktop.Sdk`
25.08 for its native architecture. Other runtimes must be provisioned in a custom
trusted image. Cross compilation is outside M1.

On success, the build record contains exit code and artifact metadata: relative
path, size and SHA-256. Find the unsigned bundle at
`data/builds/<BUILD_ID>/artifacts/application.flatpak`. Bundles do not include their runtimes. After the build succeeds:

```bash
curl -X POST http://localhost:8080/api/v1/builds/<BUILD_ID>/publish \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" \
  -H 'Content-Type: application/json' -d '{"channel":"stable"}'
# Returns 202 with a publication ID; poll until status is succeeded:
curl -H "Authorization: Bearer $LIBREHUB_TOKEN" http://localhost:8080/api/v1/publishes/<PUBLISH_ID>
flatpak remote-add --user --if-not-exists librehub \
  http://localhost:8090/librehub.flatpakrepo
flatpak install --user librehub org.librehub.Hello
flatpak run --user org.librehub.Hello
```

Use `beta` and `librehub-beta.flatpakrepo` for the independent beta repository.
The `.flatpakrepo` embeds the signing public key and Flathub runtime descriptor.
Signing private keys stay in flat-manager's trusted volume. Publication progress,
source checksum and published checksum are durable. See [publishing.md](docs/publishing.md).


## Public store workflow (M4)

On a dedicated Linux development host with the requirements above, Node.js 22 and
`jq`, start Compose and bootstrap a developer before starting the host API:

```bash
cargo build --workspace --locked
export LIBREHUB_DEV_UID=$(id -u) LIBREHUB_DEV_GID=$(id -g)
docker compose up -d --build
sh scripts/wait-repository-bootstrap.sh
. data/dev/publisher.env
DEVELOPER_ID=$(./target/debug/librehub-admin create-developer "Store Developer" | jq -r .id)
LIBREHUB_TOKEN=$(./target/debug/librehub-admin create-token "$DEVELOPER_ID" "local store" | jq -r .token)
export LIBREHUB_TOKEN
# API includes the catalog worker; keep this one host supervisor running.
./target/debug/librehub-api
```

In another terminal, use that same token to build the actual LibreHub example from
its public Git repository (explicit manifest selection avoids ambiguity):

```bash
export LIBREHUB_TOKEN='<token returned above>'
PROJECT_ID=$(curl --fail -s http://localhost:8080/api/v1/projects \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"store-hello","display_name":"Store Hello","repository":{"provider":"github","url":"https://github.com/c8dhjp4tyv-bit/LibreHub"},"default_branch":"main","manifest_path":"examples/org.librehub.Hello.json"}' | jq -r .project.id)
TRIGGER=$(curl --fail -s "http://localhost:8080/api/v1/projects/$PROJECT_ID/builds" \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" -H 'Content-Type: application/json' -d '{"ref":"main"}')
BUILD_ID=$(printf '%s' "$TRIGGER" | jq -r .build_id)
EVENT_ID=$(printf '%s' "$TRIGGER" | jq -r .source_event_id)
curl --fail -s "http://localhost:8080/api/v1/projects/$PROJECT_ID/source-events/$EVENT_ID" \
  -H "Authorization: Bearer $LIBREHUB_TOKEN"
curl --fail -s "http://localhost:8080/api/v1/builds/$BUILD_ID" -H "Authorization: Bearer $LIBREHUB_TOKEN"
# Poll until source event is completed and build is succeeded, then publish:
PUBLICATION_ID=$(curl --fail -s "http://localhost:8080/api/v1/builds/$BUILD_ID/publish" \
  -H "Authorization: Bearer $LIBREHUB_TOKEN" -H 'Content-Type: application/json' \
  -d '{"channel":"stable"}' | jq -r .id)
curl --fail -s "http://localhost:8080/api/v1/publishes/$PUBLICATION_ID" -H "Authorization: Bearer $LIBREHUB_TOKEN"
# Poll until succeeded; catalog indexing follows asynchronously. Public queries need no token:
curl --fail -s http://localhost:8080/api/v1/catalog/apps/org.librehub.Hello
curl --fail -s 'http://localhost:8080/api/v1/catalog/search?q=org.librehub.Hello'
```

Open **http://localhost:3000**, search `org.librehub.Hello`, open its detail page and
click **Install with Flatpak**. With no AppStream supplied the example correctly
uses app ID/date fallback; real projects can install standard metainfo/desktop/icon
files to provide richer metadata. The mandatory M4 acceptance builds such a project.
Install from the same signed repository with a normal client:

```bash
flatpak remote-add --user --if-not-exists librehub http://localhost:8090/librehub.flatpakrepo
flatpak install --user librehub org.librehub.Hello
# Or download/open the standard reference:
curl --fail -o org.librehub.Hello.flatpakref http://localhost:8080/api/v1/catalog/apps/org.librehub.Hello/flatpakref
flatpak install --user ./org.librehub.Hello.flatpakref
```

See [catalog](docs/catalog.md), [metadata](docs/metadata.md), [store](docs/store.md)
and [M4 verification](docs/m4-verification.md). Catalog GETs intentionally use public
CORS/cache headers; developer write/read APIs keep M3 authentication and ownership.
Compose runs web on Linux host networking to reach the host API; this preserves the
rule that no container receives the Docker socket. `/ready` includes catalog
worker/search availability. Offline reindex: stop API, then
`./target/debug/librehub-admin catalog rebuild`, restart API.

## API

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/health` | 200 while serving; 503 when stopping |
| GET | `/ready` | Structured database, flat-manager, repository and publisher readiness |
| POST | `/api/v1/builds/{id}/publish` | Validate source; enqueue stable/beta publication; 202 |
| GET | `/api/v1/builds/{id}/publishes` | Publications for this build |
| GET | `/api/v1/publishes/{id}` | Durable publication state, result or error |
| POST | `/api/v1/publishes/{id}/cancel` | Cancel queued publication; 409 after worker claim |
| GET | `/librehub.flatpakrepo` | Stable repository descriptor with embedded public key |
| GET | `/librehub-beta.flatpakrepo` | Beta repository descriptor |
| GET | `/repository.gpg` | Exported signing public key |
| POST | `/api/v1/builds` | Validate and persist; 202 with ID, status and Location |
| GET | `/api/v1/builds/{id}` | Status, timestamps, manifest metadata, result, errors |
| GET | `/api/v1/builds/{id}/logs` | Ordered log array; `after` sequence and `limit` 1–500 (default 200) |
| POST | `/api/v1/builds/{id}/cancel` | 202 while active cancellation is requested; 200 if terminal |

Active cancellation becomes terminal only after the executor returns from container
teardown. Queued jobs cancel immediately. Cancelling a terminal job is idempotent.
Poll logs with the last returned `sequence` as `after`. `logs_truncated` on the build
record indicates the persisted quota was reached. Streams are `stdout`, `stderr`
and `system`, with UTC timestamps. Long lines are emitted in bounded chunks.

Errors use `{"code":"...","message":"..."}`. Validation failures return HTTP 422
with `{"valid":false,"errors":[{"field":"...","code":"...","message":"..."}]}`.
Malformed JSON/envelopes and UUIDs return 400, oversized HTTP bodies 413,
unsupported media types 415, unknown builds 404, and a full queue 503.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIBREHUB_BIND` | `127.0.0.1:8080` | Listen address |
| `LIBREHUB_DATA_DIR` | `data` | SQLite, logs, manifests and artifacts; one supervisor per directory |
| `LIBREHUB_DOCKER` | `docker` | Container CLI binary; rootless Podman can be used on compatible hosts |
| `LIBREHUB_WORKER_IMAGE` | `librehub-worker:m1` | Trusted preprovisioned native image |
| `LIBREHUB_WORKER_NETWORK` | `none` | `none` or `bridge`; bridge permits remote source downloads |
| `LIBREHUB_BUILD_TIMEOUT_SECONDS` | `1800` | Per-job deadline excluding bounded cleanup |
| `RUST_LOG` | `info` | tracing filter |

When `LIBREHUB_FLAT_MANAGER_URL` is absent the existing M1 API remains usable and
publication admission/readiness report unavailable. Publishing configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIBREHUB_DATABASE_PATH` | `<data>/builds.sqlite3` | Operator-selected SQLite path |
| `LIBREHUB_FLAT_MANAGER_URL` | unset | Trusted manager API URL; enables publishing |
| `LIBREHUB_FLAT_MANAGER_TOKEN_FILE` | unset | Scoped bearer token file (preferred) |
| `LIBREHUB_FLAT_MANAGER_TOKEN` | unset | Alternative secret environment value |
| `LIBREHUB_PUBLIC_BASE_URL` | required | Public HTTP origin/prefix; `/repo/stable/` and `/repo/beta/` appended |
| `LIBREHUB_SIGNING_PUBLIC_KEY_FILE` | required | Binary exported public key; never a private key |
| `LIBREHUB_SIGNING_FINGERPRINT` | required | Signing key fingerprint persisted with releases |
| `LIBREHUB_RUNTIME_REPO_URL` | Flathub `.flatpakrepo` | Runtime source for clients |
| `LIBREHUB_PUBLISH_CONCURRENCY` | `1` | Active publications, 1–8 |
| `LIBREHUB_CONNECT_TIMEOUT_SECONDS` | `5` | Connection timeout, 1–60 |
| `LIBREHUB_REQUEST_TIMEOUT_SECONDS` | `60` | Request timeout, 1–600 |
| `LIBREHUB_PUBLISH_TIMEOUT_SECONDS` | `900` | Publication attempt deadline, 1–7200 |

Repository names are the validated channels `stable` and `beta`; no API request
can choose a manager repository name, artifact path or signing key. Configuration
is parsed and validated before the API listens. Tokens are redacted from debug output.

Defaults: one active build, at most 64 nonterminal jobs, 1 MiB manifest text,
2 MiB HTTP body (for escaped envelopes), 8 MiB/10,000 persisted log entries per
build, 1 GiB artifact, 4 GiB container memory, 2 CPUs, 512 processes. Remote sources
require bridge networking, HTTPS and checksums for file/archive sources; the tiny
inline example builds offline. Storage retention is manual in M1.

## Checks

Frontend checks (locked install):

```bash
cd apps/web
npm ci
npm run lint
npm run typecheck
npm test
npm run build
cd ../..
```


```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
docker compose config --quiet
# Explicit opt-in, after provisioning the worker image:
cargo test -p librehub-builder --test flatpak -- --ignored --nocapture
```

The opt-in test builds Hello through the actual executor, checks the preserved
bundle/hash and verifies temporary workspace removal. CI runs Rust checks,
builds the worker image, then runs this test on a disposable Linux runner.
CI also starts the real manager/PostgreSQL/static server, dynamically generates a
one-day signing key, and runs `scripts/test-publish-install.py`. It builds through
the M1 API, publishes stable and beta, verifies signed summary/commit trust, installs
Hello in an isolated normal Flatpak installation, and runs it. To reproduce after
starting Compose and sourcing `data/dev/publisher.env`:

```bash
cargo build --workspace --locked
# Stop any existing API on port 8080; this test starts its own isolated API database.
python3 scripts/test-publish-install.py
python3 scripts/test-developer-platform.py
# Stop Compose web so the acceptance can start its own production server:
docker compose stop web
python3 scripts/test-public-store.py
python3 scripts/test-trust-security.py
```

The resulting `data/e2e-proof.json`, `data/m3-proof.json`, `data/m4-proof.json`, and `data/m5-proof.json` are uploaded as CI artifacts.
On hosts with AppArmor restrictions, nested user namespaces may be denied; see
[security.md](docs/security.md) rather than adding privileged mode.

Code: `services/source` (HTTPS Git, manifests and source snapshots), `crates/common` (domain types), `services/validator` (policy and parsing),
`services/builder` (executor boundary and Docker implementation), `services/api`
(HTTP, SQLite repository and supervisors), `services/publisher` (artifact validation,
flat-manager client and signed public repository verification), `services/catalog` (AppStream extraction and catalog models),
`services/security` (SPDX SBOM generator, permission diffing, DNS verification, and vulnerability scanning),
and `apps/web` (Next.js public store). See [architecture.md](docs/architecture.md), [trust.md](docs/trust.md),
[sbom.md](docs/sbom.md), [vulnerability-analysis.md](docs/vulnerability-analysis.md), [moderation.md](docs/moderation.md),
and [m5-verification.md](docs/m5-verification.md).

M1 keeps its bounded bundle artifact guarantees. M2 reconstructs a private OSTree
repository from a verified bundle using `flatpak build-import-bundle`; flat-manager
manages commit rewriting/signing, publication and summary refresh. Developer projects and authentication are implemented in M3. Catalog indexing and store in M4. Trust, verification, SBOMs, permission diffing, and moderation are implemented in M5. Hardened multi-tenant isolation and other package formats remain deferred.
