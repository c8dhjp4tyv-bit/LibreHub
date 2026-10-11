# Backups

## What an archive contains

`librehub-admin backup --to DIR` writes an application-consistent archive:

| Content | How it is captured |
| --- | --- |
| Control-plane database | SQLite online backup API: a consistent point-in-time snapshot, including content still in the write-ahead log, taken while the API keeps writing. |
| Source snapshots (`sources/`) | copied; immutable once referenced |
| Build outputs and logs (`builds/`) | copied |
| Artifacts and publication journals (`artifacts/`, `publishes/`) | copied |
| SBOMs and vulnerability evidence (`security/`) | copied |
| Signed repository state (`repo/`) | copied; the OSTree objects are content-addressed and signed |
| `manifest.json` | SHA-256 and size of every archived file, the schema version, the release version and the time |

It never contains keys, locks, temporary files or symbolic links. These names are listed in the manifest's `excluded` field, without their contents: `keys/`, `webhook.key`, `tmp/`, `source-tmp/`, `supervisor.lock`, and any `*.key`, `*.pem`, `*.env` or `*.lock`.

**Keys are backed up separately**, under their own procedure, because an archive is a broader trust boundary than a key. See [disaster recovery](disaster-recovery.md#key-backup).

## Create, verify, restore

```bash
# Create (safe while the API runs). The command verifies its own output before it returns.
librehub-admin backup --to /var/backups/librehub/staging/20261011T021700Z

# Verify any archive independently: sizes, digests, snapshot integrity, and nothing unlisted.
librehub-admin verify-backup --from /var/backups/librehub/staging/20261011T021700Z

# Restore into an EMPTY data directory. The target must not contain anything.
librehub-admin restore --from /var/backups/librehub/staging/20261011T021700Z
```

`restore` runs verification before it writes anything, copies the snapshot and the evidence, verifies each copy, and then opens the store. Opening applies this release's migrations and refuses a schema newer than the release supports. Keys are not restored: provision them as described in [disaster recovery](disaster-recovery.md) before starting the API.

## Scheduled, encrypted backups

`deploy/production/scripts/librehub-backup.sh` runs from `librehub-backup.timer` (daily at 02:17 UTC, with up to 10 minutes of random delay). It:

1. creates and verifies an archive in a private work directory;
2. packs it into one tar file and encrypts it with **age** to `LIBREHUB_BACKUP_RECIPIENT` (an age recipient or a recipient file);
3. writes `librehub-<stamp>.tar.age` and its `.sha256` to `/var/backups/librehub`;
4. removes archives older than `LIBREHUB_BACKUP_RETENTION_DAYS` (default 14);
5. records success or failure in `/var/lib/prometheus/textfile/librehub-backup.prom`, for the `LibreHubBackupStale` alert.

A failed run exits non-zero, and the service's `OnFailure=` unit logs a critical message.

**Off-host copy.** Copy each archive to a second location that is not on the same host or account. The reference script does not hard-code any provider or credential. Use your provider's CLI, configured outside this repository, from a separate timer, and verify the copy with the `.sha256` file.

## Encryption and secrets

- Archives are encrypted at rest with age. The private identity is never stored on the production host; keep it in your secret store.
- The archive contains personal and operational data (developer records, token hashes, audit history). Treat it as confidential.
- Never commit an archive, a manifest from a production host, or an identity file to this repository. Never upload production backups to GitHub Actions. CI uses only generated stand-ins.

## Restore test

A backup is not trusted until it has been restored. Run this at least quarterly and after every change to the backup procedure:

```bash
# On a clean host or a disposable directory:
LIBREHUB_DATA_DIR=/tmp/restore-test LIBREHUB_DATABASE_PATH=/tmp/restore-test/builds.sqlite3 \
  librehub-admin restore --from /path/to/extracted/archive
```

The automated proof is `services/api/tests/backup_restore.rs`. It takes an archive while the environment's workers are running, rejects tampering, unlisted files and path traversal, restores into a clean directory, and checks that project, automation-run and delivery counts, the snapshot's integrity, and the evidence bytes all match the original. It does **not** install a Flatpak, verify a DSSE attestation from the restored repository, or check a restored signature against a repository key. Those checks are part of the M8 deployment test described in [M8 verification](m8-verification.md), which requires the container runtime and is not run in this environment.

## Retention and capacity

Keep at least 14 daily archives on the host and a longer off-host history that matches your audit obligations. Archive size is roughly the database plus the evidence directories; measure one archive and multiply by the retention count before sizing the backup disk (see [capacity planning](capacity-planning.md)). `librehub_database_bytes` and `librehub_disk_available_bytes` show the live figures.
