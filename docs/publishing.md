# Publishing through flat-manager

M2 uses flat-manager 0.5.3, pinned at commit
`8da2bdda932ab0bf284af7eacbd803f548237222`. The implementation follows the
[upstream API and client](https://github.com/flatpak/flat-manager/tree/8da2bdda932ab0bf284af7eacbd803f548237222).
It does not duplicate repository management or signing inside LibreHub.

```text
Manifest → M1 build → validated bundle → publish request → LibreHub publisher
         → flat-manager → OSTree repository → signed summary/ref
         → .flatpakrepo → normal Flatpak client
```

## Admission and artifact format

`POST /api/v1/builds/{id}/publish` accepts only `{"channel":"stable"}` or
`{"channel":"beta"}`. It resolves the build and manifest internally. Only
successful, uncancelled native builds with exactly one successful bundle artifact
are eligible. It revalidates the manifest and persisted metadata, requires the
exact controlled relative path, rejects symlinks in every path component, opens
the regular file without following symlinks, and rechecks size and SHA-256.
Admission has two permits; saturation returns 503. Validation/import use blocking
pool work and asynchronous subprocesses, with bounded time and output.

A Flatpak bundle contains an OSTree static delta; it is not the upload payload
expected by flat-manager. Rather than extracting an arbitrary worker directory
tree, the publisher copies and hashes the bounded M1 bundle into a private
workspace, runs `flatpak build-import-bundle` into an archive-z2 repository, and
checks OSTree fsck, the exact app/architecture/manifest-branch ref and application
name/runtime/SDK metadata. This retains M1's existing artifact and archive guarantees
and supports existing successful M1 builds. The publisher repeats validation
before upload, so tampering after HTTP admission stops publication.

## Actual backend sequence

The Rust `Publisher`/`PublishJournal` boundary separates orchestration from Axum.
`FlatManagerClient` performs:

1. Persist creation intent; `POST /api/v1/build` with validated channel/app ID and
   a unique `build-log-url` correlation marker (`librehub://publication/<UUID>`).
2. Persist the remote numeric build ID. Query `missing_objects` in batches of at
   most 1,000 names, stream OSTree objects with multipart upload, check returned
   sizes, and requery missing objects. No local paths are derived from remote names
   unless they were in the publisher's validated object inventory.
3. Upsert the exact `build_ref` with its source commit; persist `committing`,
   request commit and wait for flat-manager's ready state (including checks).
4. Persist `publishing`, request publish and wait for the published state.
5. Read the build's publish-job result, which identifies the rewritten published
   checksum. Pull that exact ref from the **public HTTP repository**, requiring
   GPG verification of both summary and commit using the distributed public key.
   Verify the checksum equals the job result, then persist `succeeded` and result.

The publish job queues flat-manager's summary update. LibreHub waits until signed
public repository verification succeeds, so a queued summary update is never
reported as a successful publication. Failures to refresh the summary surface as
an unresolved publication deadline, not fabricated success.

There is no inline HTTP publication. Once admission succeeds, HTTP returns 202
and a Location header. SQLite is the publication queue, capped at 64 nonterminal
records. Concurrency defaults to one, configurable up to eight. Releases of the
same application/channel/architecture are serialized; an unresolved older release
also blocks newer releases for that ref. Different repositories can proceed
independently.

## States, persistence and restart

```text
queued → preparing → uploading → committing → publishing → succeeded
    ↘ cancelled        ↘ failed      ↘ failed      ↘ failed
```

The migration `002_publications.sql` adds tables without changing M1 records.
Each publication persists UUID, source build, channel, app/architecture, timestamps,
status, creation intent, remote build ID, source checksum, result (ref, rewritten
checksum, public repository URL, signing fingerprint), attempts and bounded
structured error information. No backend response bodies or credentials are
persisted. SQLite uses M1's lock, serialized blocking connection, transactions,
WAL and FULL synchronous writes. One supervisor owns a local data directory.

Progress is journaled before side effects. Startup resumes interrupted records:

| Recorded state | Reconciliation |
| --- | --- |
| preparing without creation intent | Revalidate/import and create once |
| preparing with intent but no remote ID | List builds for the exact app; require one matching correlation marker; never resend an uncertain create |
| uploading | Revalidate bundle/checksum; inspect remote state; resend only missing content-addressed objects and the same ref |
| committing | Inspect remote state; start only when still uploading; wait for accepted commit/check jobs |
| publishing | Inspect published state; start only when unpublished; resume waiting and signed public verification |

Safe queries/upserts have up to three HTTP attempts with exponential backoff.
Create/commit/publish POSTs are never blindly retried. A publication attempt has a
900-second default deadline; the supervisor makes at most three attempts, loading
the latest journal before each retry. Connect/request deadlines default to 5/60
seconds. Permanent authentication/4xx failures are not retried. An uncertain
create, malformed response or exhausted transient deadline leaves the last state
with `needs_attention=true` and a stable error code. It is reconciled once again
on restart; it is not repeatedly enqueued in a busy loop.

An operator must investigate an unresolved creation marker or publish failure
against flat-manager before changing metadata. M2 intentionally has no automated
administrative resolution/rollback endpoint. Do not delete the record and resend
while a remote outcome is uncertain. Upstream flat-manager's own failed jobs are
not silently restarted by LibreHub. Restarting LibreHub cannot fix a failed
backend signing/check/summary job; repair it through the trusted operator boundary.

## Idempotency, cancellation and future releases

`UNIQUE(build_id, channel)` is the explicit idempotency contract, including races.
Retries reuse the original publication UUID and result: 202 while active, 200
when terminal, including cancelled/failed results. A failed publication cannot be
replaced by another publication of the same build/channel; submit a new build
after investigating the failure. Different builds targeting the same ref are
ordered releases that supersede the current head; package version strings are
not a separate deduplication key. The immutable source build identity/checksum
defines a release attempt.

Cancellation is supported only while queued. Cancellation and the worker claim
are transactional. Repeated cancellation of an already cancelled record returns
200; every other state after claim returns 409 `publication_not_cancellable`.
This makes no claim to undo remote commit/signing/publication.

Persisted source/published checksums and per-channel publication history form the
foundation for promotion, superseding releases and rollback. A future trusted
workflow could publish an earlier source commit as a new audited release, retaining
both the old and new manager IDs. M2 exposes no fake rollback operation. Operator
retention must preserve referenced repository objects before adding such features.

## Errors and observability

Publication API errors preserve M1's structured `{"code":"...","message":"..."}`
shape. Invalid channel/extra request fields return 422, unknown IDs 404, invalid
build/integrity/cancellation state 409, busy/full admission 503. UUID syntax errors
return 400. Publication records carry `error: {code,message,retryable}`.

Codes include `artifact_integrity_failed`, `artifact_metadata_mismatch`,
`unsupported_architecture`, `flat_manager_unauthorized`, `partial_upload`,
`commit_failed`, `publish_failed`, `publish_timeout` and
`publication_outcome_uncertain`. Messages do not include filesystem paths, remote
response bodies or credentials. Tracing includes publication/build/app/channel/
architecture/remote build IDs and error codes. Tokens, headers and signing key
material never enter the publisher's error model.

## Verification

Run the root README checks and `scripts/test-publish-install.py` after Compose
bootstrap. The test uses the actual API, M1 worker, manager/PostgreSQL, nginx,
ephemeral GPG signing and an isolated standard Flatpak client. It verifies summary
refresh, trust descriptor agreement, duplicate identity, installation ref/checksum,
GPG signature verification, application execution and beta discovery. It also
SIGKILLs the API after real backend acceptance during preparing, uploading, committing
and publishing, restarts the API four times, and requires exactly one correlated
remote build after recovery. It never
disables GPG verification. CI uploads its JSON installation evidence.
