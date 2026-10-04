# GitHub webhooks

Create a project with `auto_build=true`, provider github (or a generic connection
for a GitHub-compatible test payload), allowed build_branches and optional
build_tags. Copy its one-time webhook_secret response into the provider's webhook
configuration. Set the payload URL to:

```text
https://<librehub-origin>/api/v1/webhooks/github/<PROJECT_ID>
```

Choose JSON content and push/create events. Public repositories are supported;
provider OAuth/GitHub App installation/private credentials are deferred. Project
ID alone never authorizes admission. The raw body (maximum 256 KiB) must have a
valid X-Hub-Signature-256 (`sha256=<hex HMAC-SHA256>`) verified in constant time
before JSON processing. X-GitHub-Delivery must be a UUID, and event headers are
bounded. Repository clone_url must normalize to the registered identity.

Pushes to allowed exact branches and optionally tags create durable source events.
The push's after SHA is retained, so a newer push cannot change queued provenance.
Deleted refs are ignored. A create event with ref_type=tag resolves that tag to an
immutable commit; other create events are ignored. Other event types are safely
persisted as ignored. auto_build=false and disabled/archived projects create no
build. GitHub does not provide a signed timestamp header: durable delivery UUID
uniqueness supplies retry/replay protection. Retained tombstones are never pruned
behind a webhook's back; the 10,000-delivery/project quota blocks further admission
instead of making old deliveries replayable.

One transaction checks the current encrypted secret and project version, snapshots
policy, inserts a source event and inserts `(provider,project,delivery)` identity.
The HTTP handler returns 202 promptly and never clones/builds inline. Concurrent
retries and lost responses reuse the durable delivery identity: duplicates return
200 with code webhook_duplicate and the original source_event_id. Unsupported/
filtered events return 200 ignored. Invalid/unsigned payloads return 401
webhook_signature_invalid. Project-version conflicts return 409; provider retries
can reverify against the current connection. A rotation invalidates the old secret
immediately, including a verification/admission race.

Source states are queued → resolving → fetching → handoff → completed, with
ignored/failed terminals. The exact resolved commit is persisted before fetching.
Errors and bounded attempts are durable. The source worker polls SQLite and wakes
on admission. Build insertion, ownership/provenance and delivery completion share
one transaction with a reserved unique build ID. On restart, interrupted source
work resumes using its persisted SHA; the transaction prevents a second M1 build.
Subsequent M1/M2 execution follows their existing lifecycle/recovery behavior.

Rotate a project secret:

```bash
curl -X POST http://localhost:8080/api/v1/projects/<PROJECT_ID>/webhook-secret/rotate \
  -H "Authorization: Bearer $LIBREHUB_TOKEN"
```

The new secret is returned once. Update the provider immediately; old signatures
are rejected with no overlap. No secret value or raw webhook payload enters audit
records/logs. Delivery IDs/project/build/commit/ref IDs are safe tracing fields.
