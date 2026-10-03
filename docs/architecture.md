# M1 architecture

LibreHub is a Rust monorepo. The services are separate crates; M1 uses a single
HTTP/supervisor binary and disposable container processes, without a broker or
distributed control plane.

| Module | Responsibility |
| --- | --- |
| `crates/common` | UUID IDs, architectures, manifest structures, statuses, timestamps, validation/build errors, records, logs, artifacts |
| `services/validator` | Parse standalone JSON/YAML; validate required fields, inline modules, source definitions, and initial safety restrictions |
| `services/api` | Axum routes; SQLite repository; durable queue and asynchronous supervisor; shutdown handling |
| `services/builder` | `BuildExecutor` / `LogSink` boundaries; Docker lifecycle, streamed output, bounded artifact collection |
| `infra/docker` | Pre-provisioned Flatpak worker image and fixed entrypoint |
| `apps/web` | Reserved for a later UI; M1 uses the HTTP API |

Manifest core fields, modules, source kinds, state, results, and metadata are
strong Rust types. Flattened option maps preserve extensible Flatpak-specific
options; JSON values do not replace typed job state. The validator evaluates
these options before they reach the executor.

SQLite is accessed only through `Store`. Synchronous SQL runs on Tokio's
blocking pool. An exclusive filesystem lock prevents two supervisor processes
from controlling the same data directory. Transactions cover queue capacity,
status changes, cancellation, and log accounting. WAL and synchronous FULL
preserve committed metadata. A PostgreSQL implementation can replace this
repository boundary later; M1 does not introduce an ORM or database server.

The queue consists of persisted `queued` records. One supervisor claims the
oldest record, validates it again, and executes one build. An in-process wakeup
reduces latency; polling ensures committed jobs remain discoverable when a
wakeup is lost. Pending jobs resume after restart. Active jobs are never resumed
in place: the supervisor removes their deterministically named containers and
fails them. If cleanup cannot be verified, startup fails without launching
another build. Temporary staging workspaces are removed during recovery.

HTTP requests never wait for Flatpak compilation. The worker supervises Tokio
child processes; build commands run inside the container. `BuildExecutor` can
be replaced by a VM or remote executor without changing HTTP/domain types.
Executor panics are contained by task boundaries; teardown runs before failure
is persisted. Storage errors and uncertain container cleanup stop the supervisor
and initiate HTTP shutdown rather than concealing inconsistent state.

Metadata and bounded logs are in `data/builds.sqlite3`. Successful bundles are
in `data/builds/<UUID>/artifacts/`. Build workspaces, Flatpak caches, and the local
export repository live only inside the disposable container. No public OSTree
repository is retained or exposed by M1.
