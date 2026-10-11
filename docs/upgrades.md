# Upgrades and rollback

## Policy

- **Maintenance window.** Upgrades stop admission and restart the single controller. A short outage is expected and documented. Zero-downtime upgrades are **not** claimed for M8.
- **Forward only.** A database migrated by a release is not opened by an older binary. The start refuses a schema newer than the binary supports, and the file is left unmodified (tested in `services/api/tests/operations.rs`).
- **Backup first.** Every upgrade begins with a verified archive, and the procedure stops if the archive does not verify.

## Procedure

`deploy/production/scripts/upgrade.sh <librehub-api> <librehub-admin> <version>` runs these stages and stops at the first failure:

| Stage | What happens | If it fails |
| --- | --- | --- |
| 1. Preflight | `preflight.sh`: configuration, secret permissions, nginx syntax, backup timer | fix the reported item; nothing has changed |
| 2. New binary configuration | `librehub-api --check-config` with the new binary | nothing has changed |
| 3. Backup | `librehub-backup.sh`: archive, self-verify, encrypt | nothing has changed; investigate the backup |
| 4. Stop admission | `systemctl stop librehub-api.service`, which drains webhook attempts | restart the previous version |
| 5. Install | the new binaries under `/usr/local/lib/librehub/releases/`, symlinks switched | point the symlinks back |
| 6. Start | `systemctl start`: the unit runs `--check-config`, then migrations, then listeners | see [roll forward or restore](#when-the-start-fails) |
| 7. Smoke | `smoke.sh` against the real listeners | see [when the smoke test fails](#when-the-smoke-test-fails) |

Migrations run once, at start, in the order the store applies them. Each migration batch is transactional; a stop during a migration leaves either the whole batch or none of it.

## Before the first production upgrade

1. Restore the latest archive into a **separate** host or directory, and run the new binary against it with `LIBREHUB_DATA_DIR` pointing there. This is a rehearsal of stage 6.
2. Time the rehearsal. Your maintenance window must exceed backup time plus migration time plus smoke time, with margin.

## When the start fails

- **Configuration rejected (exit 2):** nothing was started. Fix the listed variables. The database was not opened.
- **Newer schema refused:** the database was written by a newer release. Install that release again, or restore an archive from before it.
- **Migration error:** the batch was rolled back. Read the journal, correct the cause (typically a disk or permission problem), and start again. Restoring the pre-upgrade archive is always safe.

Never remove the migration table to force a start.

## When the smoke test fails

Do not reopen traffic. Choose one:

1. **Roll forward:** fix the problem with a new release and run `upgrade.sh` again.
2. **Restore:** stop the API, restore the pre-upgrade archive into an empty directory with `librehub-admin restore`, point the unit at it, and start the previous binary (the symlink target is kept under `releases/`).

Restoring loses every record written after the archive. Record the gap in the incident report.

## Rollback

A rollback is a restore, not a downgrade. Rolling back to an older binary is refused for any database it cannot open, and it must never be forced with an edited schema. Records created by the newer release (publications, attestations, automation history, audit entries) are never removed by an upgrade or a rollback; they remain in the archive you restore from.

## Upgrading the containers

Pin each image by digest in the release manifest. Change one image at a time, run `smoke.sh` after each change, and keep the previous digest for rollback. `docker compose -f deploy/production/compose.yaml config --quiet` must pass before `up -d`.

## Upgrade checklist

- [ ] Archive created and verified today
- [ ] Rehearsal on a restored copy completed in the same window length
- [ ] Release notes read, including any migration notes
- [ ] `preflight.sh` passes
- [ ] Maintenance window announced
- [ ] Smoke test passes and `/ready` is 200
- [ ] Monitoring shows the expected series and no firing critical alerts

## Interrupted migration

See [disaster recovery](disaster-recovery.md#interrupted-migration).
