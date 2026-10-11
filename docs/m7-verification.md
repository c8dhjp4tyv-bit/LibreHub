# M7 verification and recovery evidence

## What runs where

| Layer | Command | Covers |
| --- | --- | --- |
| Pure logic | `cargo test -p librehub-automation` | workflow schema/DAG/limits/YAML hardening, run/step/approval state machines, backoff and failure classification, UTC schedules, GitHub OIDC verification (signature, algorithm confusion, key substitution, issuer/audience/time/subject, identity policy, pull-request confinement), webhook signing and SSRF classification |
| In-process stack | `cargo test -p librehub-api --test automation --test automation_approvals --test automation_schedule --test automation_events --test oidc_federation --test outbound_webhooks` | real SQLite stores, supervisors and HTTP router with fake Git, builder output and publisher: pinned sources, build reuse, failed builds, cancellation, restart, stale policy, disabled/archived projects, approvals (owner, listed approver, outsider, CI token, expiry, reuse, changed candidate, rejection), schedules (daily, weekly, missed, restart, concurrency, disabled), OIDC federation over HTTP, outbox atomicity, signed delivery, persistence-before-send, retry identity, 500/429/timeout/dead letter, replay, SSRF and DNS rebinding, rotation, ownership |
| CLI | `cargo test -p librehub-cli` | argument parsing, JSON/human output, exit codes, redaction, OIDC exchange and outputs, polling, timeouts, Ctrl-C, credential file permissions, cancellation, unexpected API errors |
| Dashboard | `npm test` in `apps/web` | pipeline rendering with real step state, status labels, approvals, integrations without secrets, cookie attributes |
| Real stack | `python3 scripts/test-automation-integrations.py` | see below |
| Real GitHub token | CI job `github-oidc-integration` | the job's own GitHub-issued OIDC token is verified against GitHub's JWKS and used by `./actions/librehub` |

## `scripts/test-automation-integrations.py`

Real LibreHub API process; real HTTPS smart Git (`source_fixture.py`); the `librehub` CLI in
GitHub-Actions mode; a local OIDC issuer (`m7_fixtures.FakeGitHub`) whose tokens go through the same
verifier as GitHub's; a local TLS webhook receiver that verifies the HMAC.

Full-stack mode (when `LIBREHUB_FLAT_MANAGER_URL` is set, as in the `worker-image` CI job):

1. register a trusted GitHub identity; exchange via the CLI; assert scopes exclude every
   privileged scope and no credential is persisted;
2. negative exchanges: wrong audience, repository, owner, branch, workflow, expired,
   pull-request, and replay of a used token;
3. create the release automation and an HMAC webhook;
4. `ci build-and-publish-beta`: pinned commit → M3 source → real M1 Flatpak build → M6 build
   provenance → M2 beta; check outputs, provenance trigger `automation`, signed installation of
   the beta with a normal Flatpak client, independent attestation check with `librehub verify
   --trusted-keys`;
5. M5 analysis gate, `request-promotion`, nothing is promoted yet;
6. unauthorized approvals (other developer, token without `releases:approve`, federated token)
   fail; the owner approves; stable publishes the same build through M2 with its own release
   attestation (distinct publication ID and statement), approval consumed; M4 catalog shows the
   stable release; stable installs with a normal client;
7. the receiver verified HMACs for build/publication/automation events;
8. **failure injection** for a second commit: kill -9 at `trigger_admitted`, `before_source_bind`,
   `after_build_bound`, `after_build_complete`, `before_beta_publication`,
   `after_beta_publication`, `awaiting_approval`, `after_approval_decision`,
   `before_stable_publication`, asserting after every crash that source events, builds and
   beta/stable publications are never duplicated and stable is not published before the
   persisted approval; the run then completes with exactly one stable publication;
9. webhook receiver 503s, outage (connection refused), restart, bounded retries, replay, and
   secret rotation; outbound crash boundaries `after_event_admission` and `during_delivery`;
10. replay of the original external trigger changes no row counts.

Without a publishing stack the script runs only the stages that need no Flatpak build (1–3, a CI run
that resolves the pinned commit and fails closed, 9, the outbound crash boundaries and the replay
check) and lists every skipped stage in `data/m7-proof.json`; it never reports a skipped stage as
passed. Crash barriers exist only in debug builds
(`LIBREHUB_TEST_AUTOMATION_FAULT_STAGE`).

## Recovery semantics

* Admission is one transaction (run, steps, history, audit, `automation.started`).
* Re-polling is safe: each step re-derives state; side effects use idempotent admissions
  (`intent_key`, `(build, channel)`, `(automation, trigger_key)`, `(webhook, event, replay)`).
* A crash between consuming an approval and enqueueing stable leaves the approval consumed *for the
  same run/step*, and the retry completes the enqueue; nothing else can use it.
* `delivering` webhook rows return to `retry_wait` at startup; delivery is at-least-once with a
  stable event ID.
* Local environment note: the `librehub-security` test `dns_resolver_uses_ipv6_nameserver`
  needs IPv6 loopback and fails in IPv6-less sandboxes; it is unrelated to M7.
