#!/usr/bin/env bash
# Upgrade LibreHub in a maintenance window. Stages: preflight, backup, stop admission, install,
# start (migrations run here), readiness, smoke. A failed stage stops the upgrade and never
# downgrades a migrated database; recovery is documented in docs/upgrades.md.
#
# Usage: upgrade.sh <path-to-librehub-api> <path-to-librehub-admin> <version>
set -euo pipefail
API=${1:?usage: upgrade.sh <librehub-api> <librehub-admin> <version>}
ADMIN=${2:?usage: upgrade.sh <librehub-api> <librehub-admin> <version>}
VERSION=${3:?usage: upgrade.sh <librehub-api> <librehub-admin> <version>}
HERE=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=/etc/librehub/librehub.env
echo "stage 1/7: preflight"
LIBREHUB_ENV_FILE=$ENV_FILE "$HERE/preflight.sh" --upgrade
echo "stage 2/7: validate the new binary's configuration before touching anything"
set -a
# The environment file is the installed configuration, chosen at run time, so it cannot be followed statically.
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a
"$API" --check-config
echo "stage 3/7: backup (online, verified)"
/usr/local/bin/librehub-backup.sh
echo "stage 4/7: stop admission"
systemctl stop librehub-api.service
echo "stage 5/7: install $VERSION (previous binary kept for diagnosis only)"
install -d /usr/local/lib/librehub/releases
install -m 0755 "$API" "/usr/local/lib/librehub/releases/librehub-api-$VERSION"
install -m 0755 "$ADMIN" "/usr/local/lib/librehub/releases/librehub-admin-$VERSION"
ln -sfn "/usr/local/lib/librehub/releases/librehub-api-$VERSION" /usr/local/bin/librehub-api
ln -sfn "/usr/local/lib/librehub/releases/librehub-admin-$VERSION" /usr/local/bin/librehub-admin
echo "stage 6/7: start (preflight, then migrations, then listeners)"
systemctl start librehub-api.service
for _ in $(seq 1 60); do
  if curl -fsS "http://${LIBREHUB_BIND}/ready" >/dev/null 2>&1; then break; fi
  sleep 2
done
echo "stage 7/7: smoke"
if "$HERE/smoke.sh"; then
  echo "upgrade to $VERSION complete"
else
  echo "smoke failed: do not reopen traffic; see docs/upgrades.md (roll forward or restore the pre-upgrade backup)" >&2
  exit 1
fi
