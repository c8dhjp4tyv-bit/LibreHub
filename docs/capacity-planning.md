# Capacity planning

This document separates **measured** numbers from **limits**. Measured numbers come from the test environment named below and are not production guarantees. Measure your reference deployment with the same method before you size it.

## Measured in this environment

Environment: a single sandboxed Linux container, **debug build** of `librehub-api` and `librehub-admin`, no container runtime, no real builds, no webhook receivers. These are relative figures for regression tracking, not capacity claims.

| Measurement | Method | Result |
| --- | --- | --- |
| Database size with 200,000 outbox events | synthetic rows inserted with SQLite | 24 MB |
| Archive creation (online, same database) | `librehub-admin backup --to DIR` | 2.2 s, archive 24 MB |
| Archive verification | `librehub-admin verify-backup --from DIR` | 1.2 s |
| Metrics scrape with a 200,000-event outbox backlog | `curl /metrics`, three runs | 11–20 ms |
| Liveness latency under load | `GET /live`, 2,000 requests, 8 concurrent clients | p50 3.7 ms, p95 7.5 ms, p99 10.4 ms |
| Clean shutdown of an idle process | SIGTERM, process exit status | exit 0 |

The metrics scrape counts outbox events not yet admitted. That count is a range scan over the outbox; it grows with the backlog and is the first query to watch if scrapes slow down.

## Limits in this release

| Resource | Limit | Where |
| --- | --- | --- |
| Control-plane writers | one. All database work goes through one connection behind a mutex. | `services/api/src/store.rs` |
| Outbound webhook concurrency | 4 concurrent attempts | `OutboundWorker::concurrency` |
| Webhook attempts per delivery | 8, then dead-letter | `MAX_ATTEMPTS` |
| Webhook attempt deadlines | connect 5 s, total 15 s, resolution 3 s | `outbound_worker.rs` |
| Webhook lease | 120 s before an abandoned attempt is recovered | `LEASE` |
| Delivery history | the most recent 1000 terminal deliveries per subscription | `integration_store.rs` |
| Outbox retention | seven days, and only events every consumer has processed | `prune_outbox` |
| Publication concurrency | `LIBREHUB_PUBLISH_CONCURRENCY` (1–8, default 1) | config |
| Build queue | bounded; a full queue refuses admission | `worker.rs` |
| Free space before admission | `LIBREHUB_MIN_FREE_BYTES`, default 512 MiB (production template: 2 GiB) | `store.rs` |
| Per-project limits | automation runs, active runs, OIDC exchanges per hour, webhook subscriptions | `LIBREHUB_AUTOMATION_*`, `LIBREHUB_OIDC_MAX_EXCHANGES_PER_HOUR`, `LIBREHUB_WEBHOOKS_MAX_PER_PROJECT` |

## Where single-writer SQLite becomes the bottleneck

Every control-plane write is serialised. Read-heavy routes (catalog, store pages) still wait for the same connection. At the sizes this release targets, that is acceptable; it stops being acceptable when the controller's write rate, or the time each write holds the lock, grows. Watch:

- `LibreHubSlowRequests` (p95 above 1 s) on the API;
- `librehub_outbox_backlog_events` rising while workers are healthy;
- publication and automation queues growing faster than they drain.

When these persist with a healthy disk, the control plane has reached its ceiling. The remedy is a PostgreSQL control plane, which is **not implemented in M8**, so the remedy in this release is to shed load (fewer scheduled automations, fewer subscriptions per project) or to split projects across separate deployments.

## Disk

Per build, the disk cost is the source snapshot, the build output, logs, the artifact, the SBOM and attestation, and the repository objects it adds. Measure one real build in your environment (`du` on its directories before and after) and multiply by the expected build rate and your retention period. Add the backup archive size (database plus evidence) times the retention count. Keep at least 30% of the data disk free; the admission guard refuses new builds below `LIBREHUB_MIN_FREE_BYTES`, which should be set well above the size of one build's output.

## Memory and CPU

The API process is limited by the unit to 4 GiB of memory and 400% CPU. Build workers run in containers whose limits are set by the M1 and M6 worker configuration. These limits are configuration values, not measured peaks; measure peak RSS with `systemd-cgtop` or the journal under your real workload before you adjust them.

## Load testing

No load-test suite is included in M8. Use your own traffic generator against a staging deployment, never against a live external service and never without authorisation. Record the workload, the hardware, and the percentiles, and attach them to the release.
