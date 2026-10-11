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

The worker's temporary OSTree export remains internal to bundle creation. M2
uses the retained bundle as a bounded handoff: the trusted publisher verifies the
recorded hash/size/path, imports a private copy with `flatpak build-import-bundle`,
checks the exact ref and metadata with OSTree, then streams archive-z2 objects to
flat-manager. This avoids exposing a general worker directory-tree extraction
interface. M1 builds and historical successful bundle records remain compatible.

A publish request creates a separate durable job linked to the source build.
flat-manager stages the objects/ref, commits and signs them, publishes to stable
or beta, and refreshes summary metadata. LibreHub verifies the resulting served
summary and commit with the distributed public key before reporting success.
The `.flatpakrepo` descriptor then enables standard clients to install the app.
See [publishing.md](publishing.md) for the complete protocol and recovery rules.

References: [Flatpak Builder](https://docs.flatpak.org/en/latest/flatpak-builder.html),
[builder options](https://docs.flatpak.org/en/latest/flatpak-builder-command-reference.html),
and [single-file bundles](https://docs.flatpak.org/en/latest/single-file-bundles.html).

## Repository-backed M3 inputs

Project trigger admission first creates a persistent source event and reserved M1
build ID. The source supervisor resolves/persists a full commit SHA, fetches that
SHA, discovers one valid manifest, rewrites safe local source references and
prepares a deterministic bounded snapshot. Atomic/fsynced snapshot placement
precedes a transactional M1 handoff (build + owner/provenance + event completion).
The existing build queue, cancellation, logs, bundle extraction and restart
behavior then apply. The worker uses the same validator in its project-source
context, rehashes/reparses the snapshot, and copies only reconstructed regular
files into `/work/source`, with the normalized `/work/manifest.json`. There is no
host checkout mount. Source-stage failures appear in project history. A queued
build cannot silently use a different snapshot after restart. See
[source-integration.md](source-integration.md).

## M6 supply-chain evidence

See [supply-chain policy](supply-chain.md), [attestations and offline verification](attestations.md), [worker isolation](build-isolation.md), [rebuild verification](reproducible-builds.md), and [verification/recovery](m6-verification.md).
Cryptographic provenance is separate from publisher identity, vulnerability analysis,
moderation and application safety. Legacy releases carry no fabricated build evidence.
