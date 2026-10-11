#!/usr/bin/env bash
# Provision a LibreHub production host. Run once as root on a prepared Linux host, and again after
# upgrades: directories and templates are reconciled, but an existing key or secret is never
# replaced. Secrets are created with restrictive modes and are never printed.
#
# Usage: provision.sh <flat-manager-image-digest> <repository-gpg-uid>
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then echo "provision.sh must run as root" >&2; exit 1; fi
FLAT_MANAGER_IMAGE=${1:?usage: provision.sh <flat-manager-image> <repository-gpg-uid>}
GPG_UID=${2:?usage: provision.sh <flat-manager-image> <repository-gpg-uid>}
HERE=$(cd "$(dirname "$0")/.." && pwd)
SECRETS=/etc/librehub/secrets
PUBLIC=/etc/librehub/public
DATA=/var/lib/librehub/data
REPO=/var/lib/librehub/repository

id librehub >/dev/null 2>&1 || useradd --system --home-dir /var/lib/librehub --shell /usr/sbin/nologin librehub

install -d -m 0750 -o root -g librehub /etc/librehub "$SECRETS"
install -d -m 0755 -o root -g root "$PUBLIC" /etc/librehub/proxy
install -d -m 0700 -o root -g root /etc/librehub/gpg
install -d -m 0750 -o librehub -g librehub /var/lib/librehub "$DATA" "$REPO"
install -d -m 0700 -o librehub -g librehub /var/backups/librehub

# Secrets: created once. A second run keeps every existing value.
new_secret() { # name, mode, owner
  local path="$SECRETS/$1"
  if [ -e "$path" ]; then echo "kept existing $1"; return; fi
  openssl rand -base64 32 | tr -d '\n' > "$path"
  chown "$3" "$path"; chmod "$2" "$path"; echo "created $1"
}
new_secret flat-manager-db-password 0400 root:root
new_secret flat-manager-token-secret 0400 root:root
new_secret grafana-admin-password 0400 root:root

if [ ! -e "$DATA/webhook.key" ]; then
  head -c 32 /dev/urandom > "$DATA/webhook.key"
  chown librehub:librehub "$DATA/webhook.key"; chmod 0400 "$DATA/webhook.key"; echo "created webhook.key (encryption key, data directory)"
else
  echo "kept existing webhook.key"
fi

# Repository signing key (M2). Created only if no key exists for this UID.
if ! gpg --homedir /etc/librehub/gpg --batch --list-secret-keys "$GPG_UID" >/dev/null 2>&1; then
  gpg --homedir /etc/librehub/gpg --batch --pinentry-mode loopback --passphrase '' \
      --quick-generate-key "$GPG_UID" ed25519 sign 5y
  echo "created repository signing key for $GPG_UID"
fi
FINGERPRINT=$(gpg --homedir /etc/librehub/gpg --batch --with-colons --list-secret-keys "$GPG_UID" | awk -F: '$1=="fpr"{print $10; exit}')
gpg --homedir /etc/librehub/gpg --batch --export "$FINGERPRINT" > "$PUBLIC/repository.gpg"
chmod 0644 "$PUBLIC/repository.gpg"

# Publisher token: a scoped credential for the API, minted from the flat-manager token secret.
if [ ! -e "$SECRETS/publisher.token" ]; then
  docker run --rm --entrypoint flat-manager-client \
    -v "$SECRETS/flat-manager-token-secret:/run/secret:ro" "$FLAT_MANAGER_IMAGE" \
    gentoken --base64 --secret-file /run/secret --name librehub-api-publisher --duration 31536000 \
    --scope build --scope upload --scope publish --repo stable --repo beta --branch '' \
    > "$SECRETS/publisher.token"
  chown librehub:librehub "$SECRETS/publisher.token"; chmod 0400 "$SECRETS/publisher.token"; echo "created publisher.token"
else
  echo "kept existing publisher.token"
fi

# Attestor seed (M6). The provisioner refuses to overwrite an existing seed or bundle.
if [ ! -e "$SECRETS/attestor-seed" ]; then
  /usr/local/bin/librehub-admin attestor provision "$SECRETS/attestor-seed" "$PUBLIC/attestor-keys.json"
  chown librehub:librehub "$SECRETS/attestor-seed"; chmod 0400 "$SECRETS/attestor-seed"
  chmod 0644 "$PUBLIC/attestor-keys.json"; echo "created attestor seed and public key bundle"
else
  echo "kept existing attestor seed"
fi

# flat-manager configuration, rendered from the template. The rendered file is a secret.
python3 - "$HERE/flat-manager/config.json.template" "$SECRETS/flat-manager-config.json" "$SECRETS" "$FINGERPRINT" <<'PY'
import json, sys, pathlib
template, target, secrets, fingerprint = sys.argv[1:]
secrets = pathlib.Path(secrets)
db = (secrets / "flat-manager-db-password").read_text().strip()
token_secret = (secrets / "flat-manager-token-secret").read_text().strip()
text = pathlib.Path(template).read_text()
text = text.replace("__FLAT_MANAGER_DB_PASSWORD__", db).replace("__FLAT_MANAGER_TOKEN_SECRET__", token_secret)
text = text.replace("__REPOSITORY_GPG_FINGERPRINT__", fingerprint)
json.loads(text)  # the rendered configuration must be valid JSON before it is written
pathlib.Path(target).write_text(text)
PY
chown root:root "$SECRETS/flat-manager-config.json"; chmod 0400 "$SECRETS/flat-manager-config.json"

# Host configuration: environment template, TLS proxy, units and the backup script.
[ -e /etc/librehub/librehub.env ] || { install -m 0640 -o root -g librehub "$HERE/env.example" /etc/librehub/librehub.env; echo "installed /etc/librehub/librehub.env (review it before starting)"; }
install -m 0644 "$HERE/proxy/tls.conf" "$HERE/proxy/security-headers.conf" "$HERE/proxy/proxy-headers.conf" /etc/librehub/proxy/
install -m 0644 "$HERE/proxy/nginx.conf" /etc/nginx/conf.d/librehub.conf
install -m 0644 "$HERE"/systemd/librehub-* /etc/systemd/system/
install -m 0755 "$HERE/scripts/librehub-backup.sh" /usr/local/bin/librehub-backup.sh
install -m 0755 "$HERE/scripts/restore.sh" /usr/local/bin/librehub-restore.sh
systemctl daemon-reload
echo "provisioning complete; fingerprint $FINGERPRINT"
echo "next: review /etc/librehub/librehub.env, install certificates, run scripts/preflight.sh"
