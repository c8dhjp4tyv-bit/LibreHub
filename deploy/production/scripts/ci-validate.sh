#!/usr/bin/env bash
# CI gate for the production profile. Validates the shipped environment template against the
# production rules, with generated stand-in files, and proves that unsafe settings are refused.
# The stand-ins are not secrets. Usage: ci-validate.sh <librehub-api binary>
set -euo pipefail
API=${1:?usage: ci-validate.sh <librehub-api binary>}
HERE=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SECRETS="$WORK/secrets"; PUBLIC="$WORK/public"; DATA="$WORK/data"
mkdir -p "$SECRETS" "$PUBLIC" "$DATA"
for name in publisher.token attestor-seed flat-manager-config.json flat-manager-db-password flat-manager-token-secret; do
  printf 'ci-stand-in\n' > "$SECRETS/$name"; chmod 0400 "$SECRETS/$name"
done
printf 'ci-stand-in\n' > "$PUBLIC/repository.gpg"; printf '{}\n' > "$PUBLIC/attestor-keys.json"
chmod 0644 "$PUBLIC/repository.gpg" "$PUBLIC/attestor-keys.json"
head -c 32 /dev/urandom > "$DATA/webhook.key"; chmod 0400 "$DATA/webhook.key"
# The generated environment file exists only at run time, so it cannot be followed statically.
load_env() {
  set -a
  # shellcheck source=/dev/null
  . "$WORK/librehub.env"
  set +a
}
# The shipped template, with its paths pointed at the stand-ins. Placeholders must be replaced by
# the operator; CI only needs them to be syntactically valid.
sed -e "s/__DOCKER_HOST_GATEWAY__/172.18.0.1/g" -e "s|/etc/librehub/secrets/|$SECRETS/|g" -e "s|/etc/librehub/public/|$PUBLIC/|g" \
    -e "s|^LIBREHUB_DATA_DIR=.*|LIBREHUB_DATA_DIR=$DATA|" \
    -e "s|^LIBREHUB_DATABASE_PATH=.*|LIBREHUB_DATABASE_PATH=$DATA/builds.sqlite3|" \
    -e "s|^LIBREHUB_SIGNING_FINGERPRINT=.*|LIBREHUB_SIGNING_FINGERPRINT=0123456789ABCDEF0123456789ABCDEF01234567|" \
    "$HERE/env.example" > "$WORK/librehub.env"
(load_env; "$API" --check-config) \
  || { echo "FAIL  the shipped production template was rejected" >&2; exit 1; }
echo "ok    shipped template passes production validation"

refused() { # description, environment overrides...
  local description=$1; shift
  local status=0
  (load_env; env "$@" "$API" --check-config >/dev/null 2>&1) || status=$?
  if [ "$status" -eq 2 ]; then
    echo "ok    refused: $description"
  else
    echo "FAIL  not refused: $description (exit $status)" >&2; exit 1
  fi
}
printf 'loose\n' > "$SECRETS/loose-token"; chmod 0644 "$SECRETS/loose-token"
refused "a test-only switch" LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS=1
refused "an inline flat-manager token" LIBREHUB_FLAT_MANAGER_TOKEN=inline
refused "a development supply-chain policy" LIBREHUB_SUPPLY_CHAIN_POLICY=development
refused "a plain-HTTP public origin" LIBREHUB_API_PUBLIC_URL=http://api.librehub.example
refused "a secret readable by other users" LIBREHUB_FLAT_MANAGER_TOKEN_FILE="$SECRETS/loose-token"
