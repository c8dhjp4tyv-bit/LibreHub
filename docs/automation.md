# Automation (M7)

An *automation* is a versioned, declarative release workflow owned by one project. LibreHub
runs it as a **durable workflow run**: every run, step, wait, retry and decision is a row in
SQLite, so a restart at any instant resumes from recorded state. Steps never run commands:
each step names an existing LibreHub operation (M3 source, M1 build, M6 evidence, M2
publication, M5 analysis, approval).

## Definition

```yaml
name: Release Pipeline
triggers:
  - type: push            # verified GitHub push webhook to these branches
    branches: [main]
  - type: tag             # verified tag push/create webhook
    patterns: ["v*"]
  - type: schedule        # daily or weekly, always UTC
    every: weekly
    weekday: mon
    at: "03:30"
    catch_up: skip        # or run_once
  - type: manual          # authenticated developer API (automations:run)
  - type: ci              # federated external CI (GitHub Actions OIDC)
steps:
  - id: build
    uses: librehub/build
  - id: verify
    uses: librehub/verify-provenance
    needs: build
  - id: publish-beta
    uses: librehub/publish
    needs: verify
    with: { channel: beta }
  - id: security
    uses: librehub/check-security
    needs: publish-beta
    with: { fail_on_severity: critical, on_unavailable: wait, timeout_seconds: 3600 }
  - id: approval
    uses: librehub/approval
    needs: security
    with: { required: true, expires_in_hours: 72 }
  - id: publish-stable
    uses: librehub/promote
    needs: approval
    with: { channel: stable }
policy:
  require_valid_build_attestation: true
  require_security_analysis_complete: true
```

Validation (`librehub automation validate --file wf.yaml`, and again on the server):

* strict schema (`deny_unknown_fields` everywhere); only the six step kinds above exist;
* at most 16 steps and 8 triggers, 64 KiB, nesting depth 12, 4,096 nodes;
* stable step IDs (`[a-z][a-z0-9-]{0,31}`), acyclic `needs`, exactly one `build` step;
* `publish` can only target `beta`, `promote` only `stable`;
* YAML anchors, aliases, tags and merge keys are rejected (no expansion attacks);
* no paths, commands, URLs or credentials can be expressed;
* `promote` needs a preceding **required** approval unless `policy.require_manual_approval:
  false` is set explicitly, and a preceding beta `publish` while
  `require_successful_beta_publication` (default true) holds.

`policy` flags: `require_build_success` and `require_no_blocking_moderation` (both always true; they cannot be disabled), `require_valid_build_attestation`,
`require_allowed_builder`, `require_successful_beta_publication`,
`require_security_analysis_complete`,
`require_manual_approval` (default true) and `release_approvers` (up to 8 developer IDs).

## Versions and admission

Every change creates an immutable version (`automation_versions`, enforced append-only by
triggers). A run copies the exact definition it was admitted with and keeps it. A *material*
change (any change to `steps` or `policy`, or disabling the automation) raises
`min_valid_version`; before every publication or promotion a run must satisfy
`definition_version >= min_valid_version`, the automation must still be enabled, and the project
must still be active. Otherwise the step fails permanently with `stale_policy` /
`automation_disabled` / `project_not_active`. Changing triggers or the name does not invalidate
in-flight runs.

A run needs: an active project and developer, an enabled automation, an allowed trigger
and a unique `(automation, trigger_key)`. Trigger keys: `delivery:<GitHub delivery UUID>`,
`ci:<repository_id>:<run_id>:<run_attempt>`, `schedule:<index>:<occurrence UTC>`,
`manual:<Idempotency key or random>`. A repeated key returns the original run (HTTP 200,
`"existing": true`). Defaults: 8 automations/project, 8 active runs/project, 64 active runs
globally, 60 runs/hour/automation, 5,000 retained runs/project, 16 pending approvals/project,
chain depth ≤ 3 (all configurable with `LIBREHUB_AUTOMATION_*` within hard bounds).

If a project is disabled or archived while a run is queued, the run fails with
`project_not_active` before any further step; archiving also cancels active runs through the
outbox. Builds already handed to M1 keep running and publications already past M2's cancellation
boundary complete; nothing is claimed to be rolled back.

## Statuses

Run: `queued → running → waiting_for_{build,publication,security,approval} → completed |
failed | cancelled`. A run becomes `completed` only when every step is `succeeded` or `skipped`
(enforced in the same transaction); an HTTP 202 never completes anything. Step: `pending →
running → waiting → succeeded | failed | skipped | cancelled`.

## Execution

The supervisor polls persisted runs (bounded to the global active-run limit, four at a time).
Each poll derives progress from durable M1–M6 state, so steps are idempotent:

| Step | Side effect and idempotency |
| --- | --- |
| build | Resolves the ref to an immutable commit through M3's provider **before** anything is queued, then one transaction binds the run to an existing equivalent in-flight/successful build of that commit or admits exactly one M3 source event (`intent_key = automation-run:<id>`). `fresh_build` forces a new build. Automation-created source events skip M3 auto-publication. |
| verify-provenance | Waits for the M6 build attestation (never fabricated: `skipped`/`not_configured` when no attestor exists and the policy does not require one). `require_allowed_builder` also needs a policy decision without violations. |
| publish | Pre-flight (below), then `enqueue_publish(build, beta)`, idempotent by M2's `UNIQUE(build, channel)`; the publication ID is bound to the run. |
| check-security | Waits for M5. Provider outage or failed analysis **waits** (or fails per `on_unavailable`) and is never treated as clean. `fail_on_severity` gates findings. Restricted/removed applications block. |
| approval | Persists an approval bound to one release candidate (see [release-promotion.md](release-promotion.md)). |
| promote | Pre-flight, approval verification and single-use consumption, then `enqueue_publish(build, stable)`; waits for publication and the stable release's *own* M6 attestation. |

Pre-flight before any publication: project ownership and status, automation head state and
policy version, the build is the same successful build in the same project with the pinned
commit, M6 policy (`check_supply_policy`), valid evidence when required, and M5 moderation.

Failures are classified. Transient codes (`source_queue_full`, `publish_queue_full`,
`source_unavailable`, `temporarily_unavailable`, …) retry with exponential backoff (5 s base,
15 min cap, ±25 % jitter, 8 attempts); everything else — including authorization, policy,
provenance, moderation and invalid-input failures — is permanent. A failed step skips its
dependents.

## Cancellation

`POST /api/v1/projects/{id}/automations/runs/{run}/cancel` records the request; the supervisor
then cancels pending steps, a not-yet-started source event it created, an M1 build it created that
has not finished, a still-queued M2 publication it created, and any pending approval. A
publication past M2's cancellation boundary continues and is reported as such
(`publication_continues` in the run history); cancelling never rewrites a signed release.

## Scheduling

Schedule triggers persist `next_run_at` per trigger. Occurrences are UTC wall times; a missed
occurrence is skipped (recorded as `automation.schedule_skipped`) or, with `catch_up: run_once`,
run once. The cursor advance and run insert share a transaction and the run key contains the
occurrence, so restarts and concurrent callers cannot duplicate it. `LIBREHUB_AUTOMATION_SCHEDULER=disabled`
switches evaluation off for operators; `schedules_enabled: false` does so per automation.

Runs have a 35-day deadline, allowing the maximum 720-hour approval window plus five days for build and security work.

## API

All routes need a bearer token. Lists accept `limit` (1–100) and `offset`.

| Method | Route | Scope |
| --- | --- | --- |
| POST/GET | `/api/v1/projects/{id}/automations` | `automations:write` / `:read` |
| GET/PATCH | `/api/v1/projects/{id}/automations/{automation}` | read / write (`spec`/`yaml`, `enabled`, `schedules_enabled`) |
| POST | `…/automations/{automation}/run` | `automations:run` |
| GET | `…/automations/{automation}/runs`, `/api/v1/projects/{id}/runs` | read |
| GET | `…/automations/runs/{run}`, `…/runs/{run}/events` | read |
| POST | `…/automations/runs/{run}/cancel` | `automations:run` |
| GET/POST | `/api/v1/approvals[/{id}[/approve\|/reject]]`, `/api/v1/projects/{id}/approvals` | read / `releases:approve` |
| GET | `/api/v1/whoami` | any valid credential |

Run request body: `{ref?, commit?, fresh_build?, idempotency_key?, chain_depth?, correlation_id?}`.
Errors are `{code, message}` with stable codes (`workflow_cycle`, `automation_queue_full`,
`automation_rate_limited`, `automation_loop_detected`, …).

See [the CLI](github-actions.md#cli) for `librehub automation …` and the dashboard under
`/dashboard`.
