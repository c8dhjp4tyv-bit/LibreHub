#!/usr/bin/env bash
# Encrypted, verified backup of the control plane and evidence. Safe while the API runs.
# Requires LIBREHUB_BACKUP_RECIPIENT: an age public key (age1...) or an age recipient file path.
# Keys and signing material are never archived; see docs/backups.md.
set -euo pipefail
umask 077
: "${LIBREHUB_DATA_DIR:?LIBREHUB_DATA_DIR is not set}"
: "${LIBREHUB_BACKUP_RECIPIENT:?set LIBREHUB_BACKUP_RECIPIENT to an age recipient}"
DEST_ROOT=${LIBREHUB_BACKUP_DIR:-/var/backups/librehub}
RETENTION_DAYS=${LIBREHUB_BACKUP_RETENTION_DAYS:-14}
METRICS_DIR=${LIBREHUB_BACKUP_METRICS_DIR:-/var/lib/prometheus/textfile}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d "$DEST_ROOT/.work-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
fail() {
  if [ -d "$METRICS_DIR" ]; then
    printf 'librehub_backup_last_failure_timestamp_seconds %s\n' "$(date +%s)" > "$METRICS_DIR/librehub-backup.prom.tmp"
    mv "$METRICS_DIR/librehub-backup.prom.tmp" "$METRICS_DIR/librehub-backup.prom"
  fi
  echo "backup failed: $1" >&2
  exit 1
}
librehub-admin backup --to "$WORK/archive" >/dev/null || fail "archive creation or self-verification"
librehub-admin verify-backup --from "$WORK/archive" >/dev/null || fail "independent verification"
tar -C "$WORK" -cf "$WORK/archive.tar" archive
if [ -f "$LIBREHUB_BACKUP_RECIPIENT" ]; then RECIPIENT_ARGS=(-R "$LIBREHUB_BACKUP_RECIPIENT"); else RECIPIENT_ARGS=(-r "$LIBREHUB_BACKUP_RECIPIENT"); fi
age "${RECIPIENT_ARGS[@]}" -o "$WORK/librehub-$STAMP.tar.age" "$WORK/archive.tar" || fail "encryption"
(cd "$WORK" && sha256sum "librehub-$STAMP.tar.age" > "librehub-$STAMP.tar.age.sha256")
mv "$WORK/librehub-$STAMP.tar.age" "$WORK/librehub-$STAMP.tar.age.sha256" "$DEST_ROOT/"
find "$DEST_ROOT" -maxdepth 1 -name 'librehub-*.tar.age' -mtime +"$RETENTION_DAYS" -print -delete \
  | while read -r old; do rm -f "$old.sha256"; done
if [ -d "$METRICS_DIR" ]; then
  printf 'librehub_backup_last_success_timestamp_seconds %s\n' "$(date +%s)" > "$METRICS_DIR/librehub-backup.prom.tmp"
  mv "$METRICS_DIR/librehub-backup.prom.tmp" "$METRICS_DIR/librehub-backup.prom"
fi
echo "backup written: $DEST_ROOT/librehub-$STAMP.tar.age"
