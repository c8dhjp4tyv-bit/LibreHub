#!/usr/bin/env bash
# Restore an encrypted LibreHub backup into an EMPTY data directory, then provision keys separately.
# Usage: restore.sh <librehub-YYYYMMDDTHHMMSSZ.tar.age> <identity-file>
set -euo pipefail
umask 077
ARCHIVE=${1:?usage: restore.sh <archive.tar.age> <identity-file>}
IDENTITY=${2:?usage: restore.sh <archive.tar.age> <identity-file>}
: "${LIBREHUB_DATA_DIR:?LIBREHUB_DATA_DIR is not set}"
[ -f "$ARCHIVE.sha256" ] && (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
age -d -i "$IDENTITY" -o "$WORK/archive.tar" "$ARCHIVE"
tar -C "$WORK" -xf "$WORK/archive.tar"
librehub-admin verify-backup --from "$WORK/archive"
librehub-admin restore --from "$WORK/archive"
echo "restored into $LIBREHUB_DATA_DIR. Provision webhook.key, the attestor seed and the signing key"
echo "from their own recovery material before starting librehub-api (docs/disaster-recovery.md)."
