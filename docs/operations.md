# Operations runbook

Every command below exists in this repository. Commands that do not exist are not listed.

## Start, stop, status

```bash
systemctl start librehub-api.service
systemctl stop librehub-api.service        # graceful: stops admission, drains webhook attempts
systemctl status librehub-api.service
journalctl -u librehub-api.service -o cat -n 200   # JSON lines when LIBREHUB_LOG_FORMAT=json
```

**Shutdown.** SIGTERM stops admission, lets in-flight HTTP requests finish, drains outbound webhook attempts (each has bounded connect, read and total deadlines), and releases the data-directory lock. The unit allows 90 seconds (`TimeoutStopSec=90s`). An idle process exits in well under a second. Builds still running are stopped by the executor and remain durable; they are recovered on the next start.

## Health and readiness

| Endpoint | Meaning | Exposed |
| --- | --- | --- |
| `GET /live` | The process is serving HTTP. | Public through nginx. |
| `GET /ready` | This instance can serve its role. `503` lists the components that are not ready. | Public through nginx. |
| `GET /health` | Legacy status (`ok` or `stopping`). | Public through nginx. |
| `GET /metrics` | Prometheus exposition. | Operator listener only. |

Webhook delivery is reported under `components.webhook_delivery` as `ok`, `degraded` or `unavailable`. A degraded webhook worker does not make the instance unready.

## Configuration

```bash
/usr/local/bin/librehub-api --check-config        # validates the environment and secret files; starts nothing
```

## Failed publications

1. Find the build and its publications: `GET /api/v1/builds/{id}/publishes`.
2. Read the publication: `GET /api/v1/publishes/{id}`. Its `status` and error codes say which stage failed.
3. Check the journal for the same publication identifier: `journalctl -u librehub-api.service -o cat | grep <publication_id>`.
4. Cancel a publication that has not reached the remote repository: `POST /api/v1/publishes/{id}/cancel`. A publication that the remote repository already completed is never cancelled locally (see [M2 publication recovery](publishing.md)).

## Worker recovery

Background work is durable. After a crash or a restart:

- Builds that were `validating` or `building` are recovered by the build supervisor at start.
- Webhook attempts that were `delivering` are made due again (at-least-once), with the same delivery and event identity.
- Automation runs and approvals resume from their stored state.

Restart the service to recover from a stuck worker. Do not edit the database to force a state change; use the API. If `/metrics` reports `librehub_worker_ready{worker="…"} 0`, check the journal for that worker's messages first.

## Webhook retries

```bash
# Delivery history for a project (newest first), then one delivery with its attempts:
curl -H "Authorization: Bearer $TOKEN" https://api.librehub.example/api/v1/projects/$PROJECT/integrations/deliveries
curl -H "Authorization: Bearer $TOKEN" https://api.librehub.example/api/v1/projects/$PROJECT/integrations/deliveries/$DELIVERY
# Re-send a terminal delivery as a new delivery identity:
curl -X POST -H "Authorization: Bearer $TOKEN" https://api.librehub.example/api/v1/projects/$PROJECT/integrations/deliveries/$DELIVERY/replay
```

A `dead_letter` delivery has exhausted its attempts. Its last error is a stable category (for example `timeout`, `connect_error`, `task_panic`, `storage_busy`, `lease_expired`). Fix the receiver or the cause, then replay. Repeated `task_panic` or `storage_*` categories are an operator incident, not a receiver problem.

## OIDC integration revocation

```bash
# Disable a connection (credentials minted through it are revoked in the same transaction):
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"enabled": false}' https://api.librehub.example/api/v1/projects/$PROJECT/integrations/oidc/$CONNECTION
# Revoke it permanently:
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://api.librehub.example/api/v1/projects/$PROJECT/integrations/oidc/$CONNECTION
# Review the audit trail (integration.credentials_revoked records the number of credentials revoked):
curl -H "Authorization: Bearer $TOKEN" https://api.librehub.example/api/v1/projects/$PROJECT/integrations/audit
```

Any narrowing of the trusted identity (branch, workflow, environment, event, owner, permission or lifetime) revokes existing credentials immediately. Credentials are rejected on the next request, not at expiry.

## Signing and attestation

- **Repository signing (M2 GPG):** the key lives in `/etc/librehub/gpg` and is used only by flat-manager. Rotation: [disaster recovery](disaster-recovery.md#signing-key-rotation).
- **Attestor (M6 Ed25519):** the seed lives in `/etc/librehub/secrets/attestor-seed`. `attestor provision` refuses to overwrite an existing seed, so a restart never silently creates a new identity.

## Disk exhaustion

Symptoms: `librehub_disk_available_bytes` falls, builds return `503 storage_capacity_low`, and the `LibreHubDiskLow` or `LibreHubDiskCritical` alert fires.

1. Confirm the usage: `df -h /var/lib/librehub /var/backups/librehub`.
2. Do not delete evidence: the source snapshots, build logs, publication journals, SBOMs, attestations and the signed repository are needed for provenance and replay defence. Expand the volume, or move the backup destination off-host.
3. A build whose container cleanup cannot be confirmed is marked `cleanup_pending`. The next start reconciles it before any new build is launched, and startup fails if the state is uncertain. Check `journalctl` for cleanup failures before manual work.
4. The control-plane database is bounded by retention (outbox events older than seven days that every consumer has processed, and the most recent 1000 deliveries per subscription). Its size is in `librehub_database_bytes`.
5. Admission resumes automatically once free space exceeds `LIBREHUB_MIN_FREE_BYTES`.

## Rebuilding catalog indexes

This release has no operator command for a full catalog reindex. The catalog worker indexes each publication when it completes. If an index is wrong, republish the affected release or restore the database from a backup taken before the defect; see [disaster recovery](disaster-recovery.md).

## Viewing metrics

```bash
curl -s http://172.17.0.1:9464/metrics | grep '^librehub_'      # from the host
```

Dashboards and alert rules are in [monitoring](monitoring.md).

## Log fields

With `LIBREHUB_LOG_FORMAT=json`, every request line carries `request_id`, `route` and `method`. Webhook lines carry `delivery_id`, `attempt` and `category`. Logs never contain tokens, webhook signatures, encrypted secrets, signing material or database passwords. Webhook bodies are not logged.
