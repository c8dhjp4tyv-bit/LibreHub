# LibreHub

LibreHub is an open Flatpak build and distribution platform. **M1 — Build
Prototype** accepts standalone JSON/YAML manifests, validates them, queues durable
jobs, builds in disposable containers, and preserves logs and `.flatpak` bundles.
**M2 — Repository & Install** adds durable publication through flat-manager, signed
OSTree repositories, and installation with standard Flatpak clients.

## Build, publish, and install

Requirements: Rust stable (edition 2024), a C compiler for bundled SQLite, Linux,
Python 3, Docker with Compose and daemon access, `flatpak`, `ostree`, `gpg`,
and support for nested unprivileged user namespaces.
Use a dedicated development/build host. The API defaults to localhost and has no
M1 authentication. Read [security.md](docs/security.md) before enabling access.

```bash
cargo build --locked
cargo test --workspace --locked
# Downloads and seeds the Freedesktop Platform and SDK 25.08 in the image.
# Allow several GiB of disk space and time for the first build.
export LIBREHUB_DEV_UID=$(id -u) LIBREHUB_DEV_GID=$(id -g)
docker compose up -d --build
# Wait for repository-bootstrap to finish, then load public trust and scoped token:
. data/dev/publisher.env
cargo run -p librehub-api
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
  -H 'Content-Type: application/json' \
  --data-binary @examples/org.librehub.Hello.json
# Returns HTTP 202: {"id":"<BUILD_ID>","status":"queued"}
curl http://localhost:8080/api/v1/builds/<BUILD_ID>
curl 'http://localhost:8080/api/v1/builds/<BUILD_ID>/logs?after=0&limit=200'
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
  -H 'Content-Type: application/json' -d '{"channel":"stable"}'
# Returns 202 with a publication ID; poll until status is succeeded:
curl http://localhost:8080/api/v1/publishes/<PUBLISH_ID>
flatpak remote-add --user --if-not-exists librehub \
  http://localhost:8090/librehub.flatpakrepo
flatpak install --user librehub org.librehub.Hello
flatpak run --user org.librehub.Hello
```

Use `beta` and `librehub-beta.flatpakrepo` for the independent beta repository.
The `.flatpakrepo` embeds the signing public key and Flathub runtime descriptor.
Signing private keys stay in flat-manager's trusted volume. Publication progress,
source checksum and published checksum are durable. See [publishing.md](docs/publishing.md).

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
```

The resulting `data/e2e-proof.json` is also uploaded as a CI artifact.
On hosts with AppArmor restrictions, nested user namespaces may be denied; see
[security.md](docs/security.md) rather than adding privileged mode.

Code: `crates/common` (domain types), `services/validator` (policy and parsing),
`services/builder` (executor boundary and Docker implementation), `services/api`
(HTTP, SQLite repository and supervisors), `services/publisher` (artifact validation,
flat-manager client and signed public repository verification). See [architecture.md](docs/architecture.md)
and [build-pipeline.md](docs/build-pipeline.md) for lifecycle and recovery details.
`apps/web` reserves a future web UI; M1 is operated through the API.

M1 keeps its bounded bundle artifact guarantees. M2 reconstructs a private OSTree
repository from a verified bundle using `flatpak build-import-bundle`; flat-manager
manages commit rewriting/signing, publication and summary refresh. Developer accounts,
moderation, web store, multi-tenant hardening and other package formats remain deferred.
