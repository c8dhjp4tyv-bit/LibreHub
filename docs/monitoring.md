# Monitoring

## What is exported

The API exposes Prometheus metrics on `LIBREHUB_METRICS_BIND` (default `127.0.0.1:9464`). The public proxy never routes `/metrics`. Every label value comes from a fixed vocabulary: a route template (never a concrete path), a status class, a queue name, or a state the code writes. Identifiers, tokens and user input never become labels.

| Metric | Type | Labels | Source |
| --- | --- | --- | --- |
| `librehub_build_info` | gauge | `version` | build |
| `librehub_ready` | gauge | | readiness of this instance |
| `librehub_http_requests_total` | counter | `route`, `status_class` | every request |
| `librehub_http_request_duration_seconds` | histogram | `route` | every request |
| `librehub_process_uptime_seconds` | gauge | | process |
| `librehub_queue_items` | gauge | `queue`, `state` | control-plane tables at scrape time |
| `librehub_outbox_backlog_events` | gauge | | outbox not yet admitted for delivery |
| `librehub_worker_ready` | gauge | `worker` | outbound, automation, catalog, security |
| `librehub_worker_degraded` | gauge | `worker`, `reason` | set when a worker stops itself |
| `librehub_webhook_failures_total` | gauge | `category` | outbound worker failure categories |
| `librehub_database_bytes` | gauge | | SQLite file plus WAL |
| `librehub_disk_total_bytes`, `librehub_disk_available_bytes` | gauge | | data directory file system |

`librehub_queue_items` queues are `builds`, `publications`, `automation_runs`, `automation_approvals`, `security_analyses`, `attestations`, `catalog_indexing` and `webhook_deliveries`. The states are those the code writes (for example `queued`, `validating`, `building`, `succeeded`, `failed`, `pending`, `analyzing`, `dead_letter`).

The webhook failure categories are `task_panic`, `task_cancelled`, `storage_busy`, `storage_full`, `storage_corrupt`, `storage` and `internal`.

**Limitations.** Queue gauges are counted at each scrape with a `GROUP BY` query. On a large database, scrape less often than every 30 seconds. The metrics do not yet include per-stage publication latency, per-job CPU and memory, or an end-to-end trace of a publication; those require a tracing backend that this release does not ship.

## Prometheus

`deploy/production/monitoring/prometheus/prometheus.yml` scrapes the API through the host gateway (`librehub-host`). `alerts.yml` contains the rules below. Run the rules through `promtool check rules` in your own pipeline; this repository's CI validates their YAML structure only.

## Alerts

| Alert | Fires when | First action | Runbook |
| --- | --- | --- | --- |
| `LibreHubApiDown` | the scrape fails for 2 minutes | check `systemctl status librehub-api` and the journal | [operations](operations.md#start-stop-status) |
| `LibreHubNotReady` | `librehub_ready` is 0 for 5 minutes | read `/ready` for the component that is `unavailable` | [operations](operations.md#health-and-readiness) |
| `LibreHubHighServerErrorRate` | more than 5% of requests fail with 5xx for 10 minutes | read the journal for the failing route | operations |
| `LibreHubSlowRequests` | p95 latency above 1 s for 15 minutes | check disk latency and the build queue | capacity planning |
| `LibreHubWorkerNotRunning` | a worker is not running for 5 minutes | restart the service after reading its journal lines | [worker recovery](operations.md#worker-recovery) |
| `LibreHubWorkerDegraded` | a worker reports a stopped state | treat as a database incident | [disaster recovery](disaster-recovery.md#corrupted-database) |
| `LibreHubBuildQueueStalled` | builds are queued or running for an hour | check the build daemon and its resource limits | operations |
| `LibreHubPublicationsFailing` | publications fail | see failed publications | [operations](operations.md#failed-publications) |
| `LibreHubAutomationQueueStalled` | more than 20 automation runs wait for an hour | check approvals and step concurrency | [automation](automation.md) |
| `LibreHubApprovalBacklog` | more than 10 stable approvals wait for a day | a reviewer must act | [release promotion](release-promotion.md) |
| `LibreHubSecurityBacklog` | more than 50 analyses are pending for two hours | check the vulnerability source | [security](security.md) |
| `LibreHubAttestationFailures` | an attestation is `failed` for 10 minutes | check the attestor seed and key bundle | [disaster recovery](disaster-recovery.md#lost-attestor-key) |
| `LibreHubWebhookDeadLetters` | a delivery is dead-lettered for 15 minutes | inspect the last error category | [operations](operations.md#webhook-retries) |
| `LibreHubWebhookFailuresRising` | more than 10 task failures in 30 minutes | read the journal for the category | operations |
| `LibreHubOutboxBacklog` | more than 1000 events wait for admission for 15 minutes | check the outbound worker state | operations |
| `LibreHubDiskLow` | less than 10% of the data disk is free for 15 minutes | expand storage or move backups off-host | [operations](operations.md#disk-exhaustion) |
| `LibreHubDiskCritical` | less than 3% is free for 5 minutes | builds are being refused; act now | [operations](operations.md#disk-exhaustion) |
| `LibreHubDatabaseLarge` | the database exceeds half the disk for an hour | plan capacity | [capacity planning](capacity-planning.md) |
| `LibreHubBackupStale` | no successful backup for 26 hours | run the backup and read its journal | [backups](backups.md) |

**Thresholds are starting points.** They were chosen for a single-controller reference deployment, not measured against production traffic. Adjust them from your own baseline. The backup alert depends on the node exporter textfile collector reading `/var/lib/prometheus/textfile/librehub-backup.prom`; without it, rely on the systemd `OnFailure=` unit that the backup service triggers.

## Alertmanager

`deploy/production/monitoring/alertmanager/alertmanager.yml` routes to a log-only receiver. Add your paging receiver through a mounted file, never inline credentials.

## Grafana

Provisioned from `deploy/production/monitoring/grafana/`. The dashboard **LibreHub production** reads only the metrics above: readiness, request rate and latency, queue depth, outbox backlog and dead letters, webhook failure categories, disk and database size. Anonymous access is disabled. The admin password is a secret file.
