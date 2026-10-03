# Build pipeline

```text
Manifest submission
        ↓
Validation
        ↓
Build record
        ↓
Job queue (SQLite)
        ↓
Isolated worker (one disposable container)
        ↓
flatpak-builder
        ↓
Logs + artifacts
        ↓
Succeeded / Failed / Cancelled
```

1. The API accepts raw JSON/YAML or a JSON request envelope. A 2 MiB HTTP cap
   bounds request memory; manifest text is capped at 1 MiB. Validation reports
   fields, codes and messages. Invalid submissions create no build record.
2. A transaction checks the 64-job pending quota, creates a UUID and stores the
   normalized manifest, metadata and queued status. HTTP 202 follows commit.
3. The supervisor selects the oldest queued job, records validating, revalidates
   the persisted manifest and records building with its start time.
4. The executor creates a private temporary directory under `data/tmp/`, saves
   `manifest.json`, creates the container, and copies only that file into `/work`.
   The configured image has native runtime/SDK installations and build tooling.
5. `librehub-build` verifies the requested runtime/SDK are installed, invokes
   `flatpak-builder --sandbox --disable-rofiles-fuse --repo=/work/repo`, and creates
   a single unsigned `.flatpak` bundle with `flatpak build-bundle`.
6. Docker output is captured concurrently from stdout/stderr with timestamps and
   a sequence assigned by SQLite. Each read and stored message is bounded at
   8 KiB. Persisted JSON entries are capped at 8 MiB and 10,000 entries per build;
   excess output is drained and discarded, with `logs_truncated=true`. Readers
   query pages instead of loading the entire history.
7. The executor independently inspects the container exit code. Only a zero exit
   enters artifact collection. Docker's copy archive is size-limited; extraction
   accepts exactly one regular `application.flatpak` entry, rejecting symlinks,
   extra files, unexpected paths, oversized and empty files. PAX/GNU metadata is
   capped at 64 KiB and 16 headers before parsing; effective paths are validated,
   and PAX size must match the file header. It streams to a
   temporary file, hashes SHA-256 and atomically preserves it under
   `data/builds/<UUID>/artifacts/` without overwriting an existing artifact.
8. Every outcome removes the container, including failed creation, timeout and
   cancellation. `docker stop --time=5` sends SIGTERM then SIGKILL; bounded forced
   removal is the fallback. The CLI process is also terminated. Scratch directories
   are removed by RAII. The final transaction records status, timestamps, exit
   code (when available), result or descriptive error.

The build deadline covers container creation, build and artifact copy. Cleanup has
separate short deadlines. Startup removes residual artifacts for failed/cancelled
builds, including a crash after a cancellation commit. Failed deletion blocks
startup until it can be retried successfully. Confirmed container cleanup clears
a durable pending flag while preserving the historical error; old databases are
migrated automatically. There is no automatic
retry, resumable active build, automatic retention, or artifact HTTP download in M1.
Container writable-layer disk consumption also requires host-level quotas/monitoring.

Example API commands and configuration are in the root README. Runtime provisioning
happens when building the trusted image, not through arbitrary manifest remotes.
Remote source downloads need explicit bridge networking; runtime changes require
an image rebuild. Missing runtimes produce a failed build with stderr explaining why.

The temporary per-build OSTree export is an internal Flatpak build step. **M2**
will add flat-manager, public OSTree publication, signing, `.flatpakrepo` generation
and public installation from LibreHub; none is implemented in M1.

References: [Flatpak Builder](https://docs.flatpak.org/en/latest/flatpak-builder.html),
[builder options](https://docs.flatpak.org/en/latest/flatpak-builder-command-reference.html),
and [single-file bundles](https://docs.flatpak.org/en/latest/single-file-bundles.html).
