# LibreHub

LibreHub is an open Flatpak build and distribution platform. **M1 — Build
Prototype** accepts standalone JSON/YAML manifests, validates them, queues durable
jobs, builds in disposable containers, and preserves logs and `.flatpak` bundles.
Public repository distribution is deferred to M2.

## Run M1

Requirements: Rust stable (edition 2024), a C compiler for bundled SQLite, Linux,
Python 3 for process-level tests, Docker with daemon access, and support for nested unprivileged user namespaces.
Use a dedicated development/build host. The API defaults to localhost and has no
M1 authentication. Read [security.md](docs/security.md) before enabling access.

```bash
cargo build --locked
cargo test --workspace --locked
# Downloads and seeds the Freedesktop Platform and SDK 25.08 in the image.
# Allow several GiB of disk space and time for the first build.
docker compose up --build
cargo run -p librehub-api
```

Compose provisions the worker image and prints its versions, then exits. The API
runs on the host and launches one new container per job; no container receives the
Docker socket. Alternatively, build the image directly:

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
curl -X POST http://localhost:8080/api/v1/builds/<BUILD_ID>/cancel
```

YAML also works with `Content-Type: application/yaml` and
`@examples/org.librehub.Hello.yaml`. An optional JSON envelope accepts
`{"manifest":"<JSON or YAML text>","format":"yaml","architecture":"x86_64"}`.
The default image supports `org.freedesktop.Platform` and `org.freedesktop.Sdk`
25.08 for its native architecture. Other runtimes must be provisioned in a custom
trusted image. Cross compilation is outside M1.

On success, the build record contains exit code and artifact metadata: relative
path, size and SHA-256. Find the unsigned bundle at
`data/builds/<BUILD_ID>/artifacts/application.flatpak`. There is no public artifact
HTTP endpoint or repository publication. Bundles do not include their runtimes.

## API

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/health` | 200 while serving; 503 when stopping |
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
# Explicit opt-in, after provisioning the worker image:
cargo test -p librehub-builder --test flatpak -- --ignored --nocapture
```

The opt-in test builds Hello through the actual executor, checks the preserved
bundle/hash and verifies temporary workspace removal. CI runs Rust checks,
builds the worker image, then runs this test on a disposable Linux runner.
On hosts with AppArmor restrictions, nested user namespaces may be denied; see
[security.md](docs/security.md) rather than adding privileged mode.

Code: `crates/common` (domain types), `services/validator` (policy and parsing),
`services/builder` (executor boundary and Docker implementation), `services/api`
(HTTP, SQLite repository and supervisor). See [architecture.md](docs/architecture.md)
and [build-pipeline.md](docs/build-pipeline.md) for lifecycle and recovery details.
`apps/web` reserves a future web UI; M1 is operated through the API.

M2 adds flat-manager, OSTree repository publication, signing, `.flatpakrepo`, and
public installation from LibreHub. M1's per-build temporary OSTree export exists
only to create the retained bundle, and is discarded with the container.
