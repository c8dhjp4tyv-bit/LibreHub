# Disaster recovery

Recovery objectives below are **design targets, not measured guarantees**. The restore test in CI proves the archive and restore procedure on a small database. Measure the time of a restore on your own hardware and data before you rely on it, and record it in your runbook.

| Failure | Recoverable automatically? | Objective (target) | Procedure |
| --- | --- | --- | --- |
| Crash or restart of the API | yes: durable queues resume | minutes | restart the unit; [operations](operations.md#worker-recovery) |
| Lost API host (disk intact) | no | hours | reinstall, restore keys, start from the latest archive |
| Lost disk or database file | no | hours | restore the latest verified archive into an empty directory |
| Lost repository serving host | no | hours | rebuild from the archive's `repo/`, or fail over the static content |
| Lost attestor key | no | not recoverable | see [lost attestor key](#lost-attestor-key) |
| Lost GPG signing key | no | not recoverable | see [lost signing key](#lost-signing-key) |
| Corrupted backup | detected by verification | next backup | keep an older archive; see [corrupted backup](#corrupted-backup) |
| Interrupted migration | detected at start | minutes | see [interrupted migration](upgrades.md#interrupted-migration) |
| Corrupted database (live) | detected: integrity and worker degradation | hours | see [corrupted database](#corrupted-database) |

## Key backup

Keys are backed up **separately** from the archive, encrypted to a different recipient, and stored where the archive is not. For each key:

- `webhook.key` (encrypts webhook secrets and OIDC state): back up once after provisioning and after any rotation. Losing it makes every stored webhook secret unreadable, and the server refuses to start a production instance without it.
- The attestor seed (`attestor-seed`) and the public key bundle (`attestor-keys.json`): back up the seed encrypted; the bundle is public.
- The repository GPG private key (`/etc/librehub/gpg`): export it encrypted, and keep the public key and fingerprint in the repository.
- The flat-manager configuration (`flat-manager-config.json`) and the publisher token: recreate them with `provision.sh`; they hold no identity of their own.

## Lost attestor key

The attestor seed signs DSSE attestations. The public key bundle verifies them. If the seed is lost, new attestations cannot be signed with the same identity, and `attestor provision` refuses to create a new seed at the same path, so the outage is explicit.

1. Restore the seed from its encrypted backup. Do not regenerate one: a new key is a new identity, and every earlier attestation remains verifiable only through the historical bundle.
2. If no backup exists, keep the historical public bundle in the repository and in your records, provision a **new** seed under a new path, publish the new bundle with a documented rotation, and state in your release notes which releases were attested by which key.
3. Never edit `attestor-keys.json` to replace a historical key. Add the new key; retain the old one.

## Lost signing key

The repository GPG key signs the OSTree repository. A lost private key means the repository can no longer be updated with the same identity.

1. Restore from the encrypted export. This is the only way to keep one identity.
2. If it is unrecoverable, generate a new key, publish the new public key and fingerprint through your release channel, update `LIBREHUB_SIGNING_FINGERPRINT`, and tell users to trust the new key. Existing installs keep working for signatures made with the old key, because the old repository state remains signed by it.

## Corrupted backup

`verify-backup` detects a corrupted file, a modified file, an unlisted file, a path outside the archive, and a snapshot that fails `PRAGMA integrity_check`. A failed verification means the archive is not restorable. Use the previous archive, and find the cause before the next run: the backup job's journal shows the failing stage.

## Corrupted database

Symptoms: `librehub_worker_degraded{reason="storage_corrupt"}` is 1, the journal reports `SQLITE_CORRUPT` or `NOTADB`, and `/ready` is unavailable.

1. Stop the API: `systemctl stop librehub-api.service`. Do not run it against the damaged file.
2. Keep the damaged file for analysis: copy `builds.sqlite3`, `-wal` and `-shm` to a safe location.
3. Run `sqlite3 /path/copy 'PRAGMA integrity_check'` on the copy, for diagnosis.
4. Restore the latest verified archive into a new, empty data directory and provision keys (see above).
5. Start the API against the restored directory, check `/ready` and `scripts/smoke.sh`, then reopen traffic.

Data written after the archive was taken is lost. Compare the archive's time with the incident's, and record the gap. Do not merge a partial database by hand.

## Interrupted migration

Migrations run at start. The versioned migration files (002 to 007) each run inside their own `BEGIN IMMEDIATE … COMMIT`, so a stop during one leaves either all of its statements or none. Schema additions made by the store itself (for example the webhook lease column) are single `ALTER TABLE` statements, guarded by a check of the current columns, so a repeated start completes them. The start refuses a schema newer than the binary. Roll forward with the same release that migrated the database, or restore the pre-upgrade archive. Never run an older binary against a migrated database; see [upgrades](upgrades.md).

## Lost API host

1. Provision a new host following [production deployment](production-deployment.md), using the same domain names.
2. Restore the latest verified archive into `/var/lib/librehub/data`, and restore the keys into the same paths.
3. Run `preflight.sh`, start the unit, run `smoke.sh`.
4. Update DNS only after `smoke.sh` passes.

## Lost repository serving host

The public repository is static, signed content. Restore `repo/` from the archive, or copy the signed tree from any mirror that has it, and serve it from the same origin. Clients verify signatures against the repository key, so a copy from an untrusted source is detected at install time.

## Verifying a restore end to end

After any restore, confirm:

- `librehub-admin verify-backup` succeeds on the source archive;
- `smoke.sh` passes and `/ready` is 200;
- a sample release installs from the public repository with `flatpak install`;
- one attestation from the restored release verifies with the public bundle (`services/supply-chain` documents the verifier).

These are the manual steps of the M8 deployment test. They are not automated in CI in this release.
