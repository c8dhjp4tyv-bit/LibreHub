# LibreHub

LibreHub M1 accepts standalone Flatpak manifests, validates them, queues isolated
builds, and preserves build status, logs, and unsigned `.flatpak` artifacts. The
backend is a Rust workspace with Axum, Tokio, and SQLite. Publishing is deferred
to M2.

## Run locally

Requirements: Rust stable, a Linux Docker daemon accessible to your user, and
nested unprivileged user namespaces. The worker image includes the native
Freedesktop Platform and SDK **25.08**. Building the image downloads several GB;
allow sufficient disk space. Other runtimes require a separately provisioned
worker image. No Flatpak installation on the API host is required.

```bash
cargo build --workspace --locked
cargo test --workspace --locked
# Compose provisions and checks the worker image; the API runs on the host.
docker compose up --build
cargo run -p librehub-api --locked
```

The API binds to `127.0.0.1:8080` by default. Leave it on a trusted development
host: M1 has no authentication or tenant isolation. Read
[the isolation limitations](docs/security.md) before changing the bind address.
The API supervises disposable containers through the host Docker CLI. The API
and Docker socket are never placed inside the build container.

The worker needs nested user namespaces for Flatpak's bubblewrap sandbox.
On Ubuntu hosts with AppArmor user-namespace restrictions, the smoke test may
fail with `Creating new namespace failed: Operation not permitted`. Configure a
**dedicated build host** to allow nested unprivileged namespaces; CI does this on
its disposable runner. M1 never adds `SYS_ADMIN` or uses privileged containers.

Rootless Podman is an alternative through its Docker-compatible socket, when
available:

```bash
export DOCKER_HOST="unix://${XDG_RUNTIME_DIR}/podman/podman.sock"
# Verify the connection before running Compose or the API.
docker info
```

Podman compatibility depends on the installed daemon and Compose provider; the
required CI integration test runs against Docker.

## Submit a build

```bash
curl -i -X POST http://localhost:8080/api/v1/builds \
  -H 'Content-Type: application/json' \
  --data-binary @examples/org.librehub.Hello.json
```

A valid submission returns HTTP **202** with a UUID and initial status:

```json
{"id":"<BUILD_ID>","status":"queued"}
```

Use the returned UUID to query the result, read logs, and cancel:

```bash
curl http://localhost:8080/api/v1/builds/<BUILD_ID>
curl 'http://localhost:8080/api/v1/builds/<BUILD_ID>/logs?after=0&limit=200'
curl -X POST http://localhost:8080/api/v1/builds/<BUILD_ID>/cancel
curl http://localhost:8080/health
```

For YAML:

```bash
curl -X POST http://localhost:8080/api/v1/builds \
  -H 'Content-Type: application/yaml' \
  --data-binary @examples/org.librehub.Hello.yaml
```

The JSON request envelope accepts a manifest **string**, format (`json` or
`yaml`), and architecture (`x86_64` or `aarch64`):

```json
{"manifest":"app-id: org.example.App\n...","format":"yaml","architecture":"x86_64"}
```

Only the host's native architecture is accepted. Raw submissions use that
architecture automatically. Manifests are limited to 1 MiB; the entire HTTP body
is limited to 2 MiB to allow envelope escaping. YAML anchors and aliases are
unsupported. Local source files and external module includes are unsupported;
use inline sources or checksummed HTTPS downloads. Runtime versions in YAML
must be quoted strings. Validation returns HTTP 422 and structured fields:

```json
{"valid":false,"errors":[{"field":"app-id","code":"invalid_app_id","message":"Identifier must use reverse-DNS notation (at least three components)"}]}
```

Malformed JSON requests return HTTP 400. Other errors use a JSON `code` and
`message`. Unknown UUIDs return 404, oversized bodies 413, unsupported media
415, and a full queue 503. Cancellation returns 202 while an active build is
being stopped, or 200 for queued/terminal builds. It is idempotent.

Logs have a sequence, UTC timestamp, stream (`stdout`, `stderr`, `system`), and
message. Request later pages using the last sequence as `after`; `limit` is
1–500 (default 200). Output chunks are at most 8 KiB; long lines may span
entries. Each build retains at most 10,000 entries / 8 MiB of encoded logs.
Further output is drained and discarded, and `logs_truncated` is set.

Successful results expose artifact path, size, and SHA-256:

```text
data/builds/<BUILD_ID>/artifacts/application.flatpak
```

Artifact paths are relative to the configured data directory. M1 does not offer
an HTTP download route. Inspect/copy artifacts on the build host; no final
LibreHub repository is published. SQLite metadata and logs survive restart.
Queued builds resume; interrupted active builds are cleaned and failed with
`worker_restarted`. Cancellation requests survive restart as well.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LIBREHUB_BIND` | `127.0.0.1:8080` | HTTP listener |
| `LIBREHUB_DATA_DIR` | `data` | Database, logs, temporary workspaces, artifacts |
| `LIBREHUB_DOCKER` | `docker` | Docker CLI executable |
| `LIBREHUB_WORKER_IMAGE` | `librehub-worker:m1` | Trusted, pre-provisioned worker image |
| `LIBREHUB_WORKER_NETWORK` | `none` | `none` or `bridge`; bridge enables source downloads |
| `LIBREHUB_BUILD_TIMEOUT_SECONDS` | `1800` | Total execution deadline, excluding final cleanup |
| `LIBREHUB_MAX_ARTIFACT_BYTES` | `1073741824` | Bundle size limit (positive, at most 16 GiB) |
| `RUST_LOG` | `info` | tracing filter |

There is one active build and at most 64 nonterminal jobs. Each build container
has two CPUs, 4 GiB memory, no extra swap, and a 512-process limit. Remote source
downloads need explicit `LIBREHUB_WORKER_NETWORK=bridge`; the included example
is completely offline after image provisioning. Bridge networking has no M1
egress allowlist. Runtime/SDK downloads happen during **image provisioning**,
not on behalf of a submitted manifest.

Use a private service-owned data directory; only one supervisor may open it.
SIGINT/SIGTERM stops the active build and preserves the pending queue. A cleanup
failure leaves the active record recoverable and stops the supervisor so it
cannot silently launch more jobs with an orphaned environment.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
# Opt-in real Flatpak smoke test, after provisioning the worker image:
cargo test -p librehub-builder --test flatpak -- --ignored --nocapture
```

The normal suite uses fake executors and a controlled Docker CLI. It checks
validation, state transitions, API errors, persistence, cancellation, process
cleanup, logs, and artifact handling without requiring Docker or Flatpak. The
ignored test performs a real Flatpak build. CI runs Rust checks, builds the
Docker image, and runs that smoke test.

See [architecture](docs/architecture.md), [the pipeline](docs/build-pipeline.md),
and [security](docs/security.md). M2 will add flat-manager, OSTree repository
publication, signing, `.flatpakrepo`, and public installation from LibreHub.
