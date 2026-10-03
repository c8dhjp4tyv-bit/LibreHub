# Build pipeline

```text
Manifest submission
        ↓
Validation
        ↓
Build record (SQLite)
        ↓
Job queue (persisted queued records)
        ↓
Isolated worker (disposable Docker container)
        ↓
flatpak-builder --sandbox
        ↓
Logs + unsigned .flatpak artifact
        ↓
Succeeded / Failed / Cancelled
```

1. `POST /api/v1/builds` accepts a raw JSON/YAML manifest or a JSON envelope.
   Input limits apply before parsing. Validation checks syntax, mandatory fields,
   IDs, modules and sources. Invalid input creates no job.
2. A transaction checks queue capacity, assigns a UUID, and stores canonical
   manifest data and a `queued` record. The API returns HTTP 202 and `Location`.
3. The supervisor claims the job as `validating` and revalidates persisted data.
   It transitions to `building`, creates a private temporary staging directory,
   and saves normalized JSON. Only service-generated UUIDs form filesystem paths.
4. The executor creates a nonroot resource-limited container with no host mounts
   and copies in the manifest. The preinstalled runtime and SDK must match the
   manifest. The default network is disabled.
5. The fixed entrypoint calls `flatpak-builder --sandbox --disable-rofiles-fuse`
   with fixed build/repository paths. The temporary repository is used only to
   generate an unsigned bundle with `flatpak build-bundle`; it is never published.
6. Stdout/stderr are streamed through fixed buffers into persistent bounded logs.
   Timestamps describe capture time; streams can interleave. After the retention
   cap, pipes continue draining to avoid deadlocking the build.
7. A nonzero exit or deadline produces a structured build error. After success,
   the executor requests exactly `application.flatpak` from Docker as a tar
   stream. Archive bytes and payload size are bounded. Only one regular file
   with the exact expected name is accepted; links and other paths are rejected.
   A staging file is hashed and atomically preserved without overwriting.
8. The executor stops/removes the container and deletes its temporary workspace.
   Successful artifact metadata is saved in the final result. Unsuccessful
   artifacts are removed. If teardown is uncertain, the record stays active for
   restart recovery and the supervisor stops.

The normal state path is `queued → validating → building → succeeded/failed`.
Failures during validation can transition directly to `failed`. Terminal records
cannot be resurrected. Cancellation of a queued build is immediate; cancellation
of an active build sets a persistent request. The supervisor observes it within
about 200 ms and signals the executor. Docker stop sends SIGTERM and waits five
seconds before SIGKILL; forced removal follows as a fallback. The final
`cancelled` status is recorded after teardown, never before an active container
is stopped. A cancellation request can win over a concurrently completed build;
its artifact is discarded.

SIGINT/SIGTERM also cancels active execution. Pending jobs are preserved. The
service waits up to 45 seconds for worker shutdown and ten more seconds for HTTP
drain; a hard interruption is reconciled on the next startup. Recovery verifies
container removal before marking interrupted jobs failed/cancelled, removes
incomplete artifacts, and clears abandoned staging directories.

Logs are paginated with `after=<sequence>&limit=<1..500>`. Records contain start,
finish, and update timestamps, manifest metadata, architecture, errors, optional
results, cancellation requests, and log truncation state. Artifacts are retained
locally until an operator removes them; M1 has no retention scheduler.

## Deferred to M2

- flat-manager integration
- OSTree repository publication and remote metadata
- signing and key management
- `.flatpakrepo` generation
- Public installation from LibreHub

The intermediate per-build export repository is an implementation detail for
bundle creation, not an M2 publishing system.
