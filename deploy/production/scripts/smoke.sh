#!/usr/bin/env bash
# Post-start checks against the real listeners. Read-only. Exits non-zero on the first failure.
set -euo pipefail
ENV_FILE=${LIBREHUB_ENV_FILE:-/etc/librehub/librehub.env}
set -a
# The environment file is chosen at run time (LIBREHUB_ENV_FILE), so it cannot be followed statically.
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a
API="http://${LIBREHUB_BIND:?}"
METRICS="http://${LIBREHUB_METRICS_BIND:?}"
PUBLIC_API=${LIBREHUB_PUBLIC_API_URL:-https://api.librehub.example}
REPO=${LIBREHUB_PUBLIC_BASE_URL:-https://repo.librehub.example/repo}
expect() { # description, expected status, command...
  local description=$1 want=$2; shift 2
  local got
  got=$("$@" 2>/dev/null || true)
  if [ "$got" = "$want" ]; then echo "ok    $description ($got)"; else echo "FAIL  $description (got '${got:-none}', want $want)" >&2; exit 1; fi
}
expect "API liveness"            200 curl -s -o /dev/null -w '%{http_code}' "$API/live"
expect "API readiness"           200 curl -s -o /dev/null -w '%{http_code}' "$API/ready"
expect "metrics on operator port" 200 curl -s -o /dev/null -w '%{http_code}' "$METRICS/metrics"
expect "metrics refused publicly" 404 curl -s -o /dev/null -w '%{http_code}' "$PUBLIC_API/metrics"
expect "plain HTTP redirects"    301 curl -s -o /dev/null -w '%{http_code}' "http://${PUBLIC_API#https://}/live"
expect "repository index served" 200 curl -s -o /dev/null -w '%{http_code}' "$REPO/stable/summary"
