# M3 developer platform

LibreHub now accepts repository-backed projects. Bootstrap a developer offline,
use a scoped bearer token to register a public HTTPS repository, and trigger an
asynchronous source event by branch, tag (`refs/tags/v1.0`) or full 40-character
commit. Git resolution persists an immutable commit before fetching. Automatic
manifest discovery, the existing validator, a hashed source snapshot and the M1
executor produce the bundle. Manual/automatic publication uses M2 unchanged.

## API and ownership

All `/api/v1` developer/build/publish routes in the executable require bearer
authentication, except signed webhooks and M4 read-only catalog routes. Health, readiness and public repository
trust descriptors remain public. Existing M1/M2 bodies, statuses and structured
`{code,message}` errors are preserved; requiring auth is the intentional
compatibility change. An offline `--operator` token can access historical unowned
M1/M2 jobs; it cannot access another developer's owned jobs or projects. New raw
manifest builds are also owner-scoped. The legacy Rust router remains a test/
embedding helper; the executable always uses the authenticated platform router.

| Method | Route | Result / scope |
| --- | --- | --- |
| POST / GET | `/api/v1/projects` | Create / list owned projects; projects:write/read |
| GET / PATCH / DELETE | `/api/v1/projects/{id}` | Inspect / update / archive owned project |
| POST | `/api/v1/projects/{id}/builds` | Queue `{ "ref": "main" }`; builds:write |
| GET | `/api/v1/projects/{id}/builds` | Source/build/publication history; builds:read |
| GET | `/api/v1/projects/{id}/source-events/{event}` | Source progress/errors; builds:read |
| POST | `/api/v1/projects/{id}/webhook-secret/rotate` | New one-time secret; webhooks:write |
| GET | `/api/v1/projects/{id}/audit` | Owned project audit; audit:read |
| GET | `/api/v1/audit` | Developer's audit; audit:read |
| POST / GET / DELETE | `/api/v1/tokens[/{id}]` | Issue / list / revoke; tokens:write/read |

Trigger admission returns 202 with `build_id` (reserved immutable UUID),
`source_event_id`, `status` and the source-event Location. Poll the source event
until completed, then use the ordinary `/api/v1/builds/{build_id}` and `/logs`
endpoints. The build record exists after atomic M1 handoff. Source failures appear
in project history even if no M1 build could be created. Multiple-manifest errors
include candidate paths. History omits manifests and logs. Lists accept `limit`
(default 50, maximum 100) and `offset` (maximum 1,000,000). A build can have at most
two publications by M2's unique `(build_id,channel)` constraint.

Project slugs use lowercase ASCII letters, digits and hyphens, begin with a letter,
and contain 1–64 bytes. Slug/owner/project ID are immutable. Settings include exact
`build_branches` (maximum 16), `build_tags`, `manifest_path`, `auto_build`,
`auto_publish_channel` (null/none, beta, stable), and `auto_publish_tags_only`.
Enabling publication additionally requires publishes:write. Project status is
active, disabled or archived. DELETE archives, disables new source work and keeps
all historical builds, publications and audit. Archived projects cannot be restored
through PATCH. Disabled projects can be reactivated by their owner.

## Automation and policy races

Admission snapshots the entire typed project configuration and policy version in
one database transaction. Source resolution/fetch/discovery uses this snapshot,
so a queued event never observes a mixture of settings. Disable/archive is checked
again before processing and before M1 handoff. Builds already handed to M1 continue
and remain readable; archive does not claim to undo a build/publication in progress.

Auto-publication requires successful M1 output and a resolved immutable revision.
The current project must remain active with exactly the admitted policy version
and channel; any PATCH conservatively suppresses queued older automatic work.
The transaction enqueuing an automatic publication rechecks this rule. M2's claim
transaction checks it once more, cancelling stale queued automatic publications
before any publisher side effect. After publisher claim, M2's reconciliation and
cancellation boundary applies: changing settings cannot undo an accepted release.
`auto_publish_tags_only=true` permits automatic publication only for webhook tag
triggers; it does not globally impose a push→beta/tag→stable rule. First publication atomically claims an application ID for that developer across
channels; another developer cannot overwrite that application using their own build.
This is an ownership boundary, not verified publisher identity. Manual publish
is an explicit owner-authorized action and can publish retained historical builds.

## Storage and limits

Additive migration `003_developer_platform.sql` adds developers, hashed tokens,
projects/encrypted connections, source_events, webhook_deliveries, build_owners and
audit_events and application_owners. M1 JSON builds gain optional provenance; older JSON reads unchanged.
Source provenance records project, repository, commit/ref/resolution time, manifest
path, snapshot SHA-256/size/file count, trigger/event ID and policy version.

Defaults: 32 projects/developer (archived records count), 32 live tokens/developer,
64 active source events globally, one source fetch at a time, 10,000 retained source
events and webhook delivery tombstones/project, and 10,000 audit entries/developer.
These finite quotas intentionally refuse further admission rather than deleting
delivery identities and allowing replays. M1/M2 retain their 64-job queues. Source
snapshot limit is 64 MiB including tar structure / 4,096 regular files. Aggregate
artifact/snapshot/database retention and host disk quotas remain operator duties.

M4 adds a public catalog/store derived from successful publication. No OAuth, private Git credentials, organizations, billing,
moderation UI or other package formats are included. Containers still require a
dedicated host; M3 auth does not turn M1 shared-kernel isolation into a hardened
hostile multi-tenant service.

## M4 public presentation

Publishing through the same M2 APIs now asynchronously queues catalog indexing.
Install canonical AppStream metainfo/desktop/PNG files inside the Flatpak to supply
presentation metadata; do not duplicate those fields into project settings.
Only successful stable publication enables default public discovery. Publisher and
project UUIDs, display name, immutable source repository/commit and declared license
are intentionally public. API tokens/webhooks/audit/policy remain private. Archived
projects remain marked and installable with M3's retained-history/manual-publish
semantics. See metadata.md for accepted standard files and catalog.md for public API.

## M6 supply-chain evidence

See [supply-chain policy](supply-chain.md), [attestations and offline verification](attestations.md), [worker isolation](build-isolation.md), [rebuild verification](reproducible-builds.md), and [verification/recovery](m6-verification.md).
Cryptographic provenance is separate from publisher identity, vulnerability analysis,
moderation and application safety. Legacy releases carry no fabricated build evidence.
