#!/usr/bin/env bash
# Preflight: every check that must pass before an upgrade or a first start. Read-only.
set -euo pipefail
ENV_FILE=${LIBREHUB_ENV_FILE:-/etc/librehub/librehub.env}
failures=0
check() { if "$@"; then echo "ok    $*"; else echo "FAIL  $*"; failures=$((failures + 1)); fi; }

[ -r "$ENV_FILE" ] || { echo "FAIL  $ENV_FILE is not readable"; exit 1; }
set -a
# The environment file is chosen at run time (LIBREHUB_ENV_FILE), so it cannot be followed statically.
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a
check /usr/local/bin/librehub-api --check-config
for secret in /etc/librehub/secrets/flat-manager-config.json /etc/librehub/secrets/flat-manager-db-password \
              /etc/librehub/secrets/flat-manager-token-secret /etc/librehub/secrets/attestor-seed \
              /etc/librehub/secrets/publisher.token /var/lib/librehub/data/webhook.key; do
  check test -f "$secret"
  if [ -f "$secret" ]; then check test -z "$(find "$secret" -perm /077)"; fi
done
check test -d /etc/librehub/gpg
check test -z "$(find /etc/librehub/gpg -perm /077 -not -type d)"
check nginx -t
check systemctl cat librehub-backup.timer
if [ "${1:-}" = --upgrade ]; then
  check systemctl is-enabled librehub-backup.timer
fi
check sh -c "df -P /var/lib/librehub | awk 'NR==2{exit !(\$4>1048576)}'"
if [ -n "${LIBREHUB_COMPOSE_FILE:-}" ]; then
  check docker compose -f "$LIBREHUB_COMPOSE_FILE" --env-file "${LIBREHUB_COMPOSE_ENV:-/etc/librehub/compose.env}" config --quiet
fi
echo "$failures check(s) failed"
exit "$failures"
