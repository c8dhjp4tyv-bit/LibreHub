# Beta-to-stable promotion and approvals (M7)

Promotion publishes **the same validated build** to the stable channel through the unchanged M2
queue. Publication identity is `(build, channel)`, so the stable publication is a separate record
with its own final OSTree commit, security analysis and M6 release attestation; beta evidence is
never reused as stable evidence. Nothing is rebuilt from a moving branch: the run is pinned to a
commit and a build ID from admission on.

## Approval

The `approval` step persists a request bound to a **release candidate**: project, automation,
run, workflow version, build ID, source commit, source snapshot SHA-256, application ID, beta
publication and its OSTree commit, target channel (`candidate_sha256` is the digest of that
document). It expires (default 72 h, 1–720). States: `requested → approved | rejected | expired |
cancelled`, a single decision each.

Who may decide (always enforced by the API): the project owner (`project_owner`), developers listed in
the workflow's `policy.release_approvers` (`authorized_release_approver`) and offline `operator`
tokens (`operator`) — in every case only with the `releases:approve` scope. Federated CI credentials cannot
hold that scope, and unrelated developers get `404`. The decision records the actor, role, time,
reason and workflow version, and is audited (`release.approval_requested|approved|rejected`).
Deciding checks: still pending, not expired, run still active, project active, and the run still
points at the same build and commit.

Before stable publication the engine recomputes the candidate from live state and requires the
digest, workflow version, run and project to match the approval (`approval_stale` otherwise —
for example after the build record's source snapshot changed), the beta publication to have
succeeded for this build, analysis to be complete when required, and all pre-flight gates
(project status, automation version, M6 policy, M5 moderation). The approval is then consumed
(single use; resuming the same step after a crash finds it already consumed) and stable
publication is admitted. A rejection, expiry, cancellation or restart never approves anything.
A CI-triggered run can never promote without an approved release, even for a workflow whose
owner removed the approval step.

## What each gate covers

| Gate | Source of truth |
| --- | --- |
| build success, source pinning | M1 build record + M3 provenance |
| attestation, allowed builder | M6 `build_attestations`, `check_supply_policy` (also enforced inside M2 admission) |
| analysis complete, vulnerability gate | M5 `release_security`, `vulnerability_findings` — outages wait/fail, never "clean" |
| moderation | M5 `catalog_moderation` (`restricted`, `removed` block) |
| approval | `automation_approvals` |
| channel ownership, idempotency | M2 `(build, channel)` uniqueness and application ownership |

Once M2 commits a signed release, nothing in the automation can undo it; cancelling or failing the
run only stops further steps. The public store (M4) updates through the existing catalog worker after
stable publication.
