# Production deployment (single-controller reference)

This is the supported production profile for LibreHub at M8. It is a **single-controller** deployment: one API and build supervisor owns one SQLite control-plane database. Multi-controller operation is not supported (see [Supported deployment declaration](#supported-deployment-declaration)).

## Topology

```
Internet ──TLS──► nginx (host, :443)            ──► web (container, 127.0.0.1:3000)
                    │  api.librehub.example     ──► API (host, 172.17.0.1:8080)
                    │  repo.librehub.example    ──► /var/lib/librehub/repository (static)
                    ▼
     librehub-api.service (host, User=librehub)
        ├─ durable control plane: SQLite (WAL, synchronous=FULL) in /var/lib/librehub/data
        ├─ build supervisor ──► rootless daemon of the librehub-builder account ──► worker containers
        ├─ publisher ──► flat-manager (container, 127.0.0.1:8081) ──► PostgreSQL (internal network)
        └─ operator metrics (host, 172.17.0.1:9464) ──► Prometheus (container)
```

- Only nginx is reachable from the internet. The API, metrics, flat-manager and PostgreSQL are never published on a public address.
- The API runs on the host, as in development, so **no container and no Docker socket is granted to the public-facing service**. The build daemon runs under a separate account (`librehub-builder`), and the API reaches it through its socket.
- Signing keys and the flat-manager configuration are secret files. They are mounted only where they are needed. The web container receives no secret at all.

## Supported platform

| Item | Supported |
| --- | --- |
| Operating system | Ubuntu 24.04 LTS (x86_64) and Debian 12 (x86_64). Other systemd distributions are untested. |
| CPU architecture | x86_64 only. aarch64 is not tested and not supported in M8. |
| Container runtime | Docker Engine 26 or later, with Compose v2.24 or later, for the web, flat-manager, PostgreSQL and monitoring containers. Rootless Docker or Podman for the build daemon (see below). |
| Reverse proxy | nginx 1.24 or later (the configuration uses `listen … http2`). Validated with nginx 1.24 and the pinned `nginx:1.28.0-alpine` image in CI. |
| Database | SQLite 3.45+ (bundled) for the control plane, PostgreSQL 17 for flat-manager only. |
| Filesystem | ext4 or XFS on local disk. Never NFS, SMB or any network filesystem for `/var/lib/librehub`. |
| Time | NTP-synchronised clock. Webhook signatures and OIDC token validation depend on it. |

## Prerequisites

1. A dedicated host with at least 4 vCPU, 8 GiB RAM, and a data disk sized with [capacity planning](capacity-planning.md).
2. DNS records for `librehub.example`, `api.librehub.example` and `repo.librehub.example` pointing at the host.
3. Certificates for those names from your ACME client (for example `certbot`), installed under `/etc/letsencrypt/live/librehub.example/`.
4. An off-host location for backups, and an age recipient public key for encryption (see [backups](backups.md)).
5. A GitHub App or OIDC audience only if you use the CI federation features ([OIDC federation](oidc-federation.md)).

## Installation

Run these as root on the prepared host. Each command exists in this repository.

```bash
# 1. Build the release binaries from a tagged, verified source checkout.
cargo build --release --locked -p librehub-api --bin librehub-api --bin librehub-admin
install -m 0755 target/release/librehub-api target/release/librehub-admin /usr/local/bin/

# 2. Provision the host: service account, directories, secrets, signing key, templates, units.
#    Secrets are created once and never printed. A second run keeps every existing value.
deploy/production/scripts/provision.sh "$FLAT_MANAGER_IMAGE_DIGEST" "LibreHub Repository <repo@librehub.example>" "https://repo.librehub.example"

# 3. Review the host configuration. Every value is documented in deploy/production/env.example.
$EDITOR /etc/librehub/librehub.env

# 4. Build the build-daemon account (rootless Docker for librehub-builder), then start the daemon.
#    Follow the Docker rootless documentation for your distribution; the API reads DOCKER_HOST
#    from /etc/librehub/librehub.env. The API must never run as root.

# 5. Start the containers (web, flat-manager, PostgreSQL, monitoring) with pinned digests.
export LIBREHUB_WEB_IMAGE=... LIBREHUB_FLAT_MANAGER_IMAGE=... LIBREHUB_POSTGRES_IMAGE=...
export LIBREHUB_PROMETHEUS_IMAGE=... LIBREHUB_ALERTMANAGER_IMAGE=... LIBREHUB_GRAFANA_IMAGE=...
docker compose --env-file /etc/librehub/librehub.env -f deploy/production/compose.yaml up -d

# 6. Install the TLS configuration and reload nginx (the provisioning script installs the files).
nginx -t && systemctl reload nginx

# 7. Preflight, then start the API. The unit runs --check-config before it binds anything.
deploy/production/scripts/preflight.sh
systemctl enable --now librehub-api.service librehub-backup.timer

# 8. Smoke test the public and private listeners.
deploy/production/scripts/smoke.sh
```

Provisioning resolves the default Docker bridge gateway for the API, metrics and nginx upstream. If the daemon sets a custom `host-gateway-ip`, pass the same private IPv4 address as `LIBREHUB_HOST_GATEWAY_IP` to provisioning. On existing installations, update `LIBREHUB_BIND`, `LIBREHUB_METRICS_BIND` and `LIBREHUB_TRUSTED_PROXIES` to match; provisioning preserves the existing environment file. The web API endpoint can be overridden with `LIBREHUB_API_URL`. Replace the example repository origin in the provisioning command and keep `LIBREHUB_PUBLIC_BASE_URL` set to that origin plus `/repo`. Replace the three example hostnames in nginx and install the matching certificates before reloading.

The smoke test checks that `/live` and `/ready` answer, that metrics are served only on the operator listener and refused publicly, that plain HTTP redirects, and that the repository index is served. `/ready` returns 200 only after publishing is configured and the first signed publication exists.

## Configuration rules

`librehub-api --check-config` enforces the production profile (`LIBREHUB_ENVIRONMENT=production`), and the unit refuses to start when it fails. The rules and their rejection messages are documented in [production security](production-security.md#configuration-rules). Secrets are supplied only as `*_FILE` paths; an inline secret is rejected.

## Build isolation

Worker containers are launched by the API through the build account's rootless daemon. This is the strongest isolation the reference profile supports on a shared kernel: rootless containers, no privileged mode, `network none` for builds, and the hardened worker policy from M6. It is **not** a virtual-machine boundary. The kernel is shared between the build workloads and the host, and a kernel escape would expose the host. See [production security](production-security.md#shared-kernel-risk).

## Where to go next

- [Operations runbook](operations.md) for day-to-day commands.
- [Monitoring](monitoring.md) for metrics, dashboards and alerts.
- [Backups](backups.md) and [disaster recovery](disaster-recovery.md) before go-live.
- [Upgrades](upgrades.md) before the first upgrade.
- [Capacity planning](capacity-planning.md) for sizing and limits.

## Supported deployment declaration

- **Controllers:** exactly one `librehub-api` process per data directory. The data directory lock enforces this at start; a second start fails with "Another LibreHub supervisor owns this data directory".
- **Database backend:** SQLite for the control plane. A PostgreSQL backend for the control plane is not implemented in M8, so multi-controller operation is not offered.
- **TLS:** required. Public origins must be `https://`. HSTS is sent only over HTTPS.
- **Worker isolation guarantees:** as stated above. No VM isolation, and no protection from kernel vulnerabilities.
- **Storage assumptions:** local filesystem, sufficient free space (see [capacity planning](capacity-planning.md)), durable storage that honours `fsync`.
- **Backup prerequisites:** the `librehub-admin` backup command, `age` for encryption, and an off-host destination for the encrypted archives.
- **Known kernel and security-module limitations:** the M6 compatibility limitation with certain Fedora SELinux environments still applies. Do not deploy the build daemon on a host where rootless containers are unavailable.
