# Integrations (M7)

Two kinds of integration exist per project, both managed by the project owner with
`integrations:read` / `integrations:write` and listed in the dashboard at
`/dashboard/projects/<id>/integrations`:

* **Trusted CI identities** — GitHub Actions OIDC policies ([oidc-federation.md](oidc-federation.md)).
* **Outbound webhooks** ([outbound-webhooks.md](outbound-webhooks.md)).

Common rules: identifiers, fingerprints and redacted metadata only are ever shown after creation;
secrets and tokens appear once in the creation/rotation response. At most 4 active identities
and 8 webhooks per project; integration audit is capped at 10,000 rows per project.
Revoking an identity revokes every credential minted through it. Every action is audited
(`integration.created|updated|disabled|revoked|secret_rotated`, `oidc.exchange_*`,
`webhook.delivery_failed|replayed`) without secrets.

## Routes

| Route | Purpose |
| --- | --- |
| `POST/GET /api/v1/projects/{id}/integrations/oidc`, `GET/PATCH/DELETE …/oidc/{id}` | identities |
| `POST/GET /api/v1/projects/{id}/integrations/webhooks`, `GET/PATCH/DELETE …/webhooks/{id}` | webhooks |
| `POST …/webhooks/{id}/rotate` | new signing secret (returned once) |
| `GET …/webhooks/{id}/deliveries`, `GET …/integrations/deliveries[/{id}]` | delivery history |
| `POST …/integrations/deliveries/{id}/replay` | manual replay |
| `GET …/integrations/audit` | integration audit |
| `POST /api/v1/integrations/github/oidc/exchange` | token exchange (identity token is the credential) |

## Event flow and loops

State changes in M1–M6 tables enter `event_outbox` through SQLite triggers in the *same
transaction* as the change (`build.started|succeeded|failed`, `publication.started|succeeded|failed`,
`security.analysis_ready|failed`, `attestation.ready|failed`, `source_event.completed`,
`project.archived`); the engine writes `automation.*` events itself. The event ID is unique per
transition (`dedupe_key`), so a transition cannot be enqueued twice. Two durable consumers
(`automation`, `webhooks`) have cursors; fan-out creates delivery rows atomically with advancing the
cursor.

Every event carries `origin` (`automation`, `manual`, `webhook`, `system`), a `correlation_id` and
a `chain_depth`. A receiver that triggers LibreHub because of an event must send
`chain_depth = event.chain_depth + 1` (`POST …/run` accepts `chain_depth` and `correlation_id`);
chains deeper than 3 (configurable up to 8) are refused with `automation_loop_detected`, and events
already at the limit are not delivered (audited as `webhook.chain_limit`). Subscriptions can also
`exclude_origins` (for example `["automation"]`). Because builds are reused per commit, a CI that
re-triggers itself for the same commit does not create new builds.
