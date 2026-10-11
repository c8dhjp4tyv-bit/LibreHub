# Production security

This document states what the production profile enforces, where the enforcement lives, and what it does **not** protect against. Read [the shared-kernel risk](#shared-kernel-risk) before exposing the service.

## Configuration rules

`librehub-api --check-config` (and the start of `librehub-api.service`) applies these rules when `LIBREHUB_ENVIRONMENT=production`. Every violation is printed by variable name; values are never printed. The rules are implemented in `services/api/src/production.rs` and unit-tested there. `deploy/production/scripts/ci-validate.sh` proves the shipped template passes and that each unsafe setting is refused.

| Rule | Why |
| --- | --- |
| `LIBREHUB_ENVIRONMENT` is `production`, `development` or `test` | an unknown value is an error |
| No `LIBREHUB_TEST_*` or `*_FOR_TESTS` variable may be set | test-only switches are never valid in production |
| `LIBREHUB_FLAT_MANAGER_TOKEN` must not be set inline | secrets come from `*_FILE` paths |
| `LIBREHUB_SUPPLY_CHAIN_POLICY=enforce` | untrusted images cannot enter strict publication |
| `LIBREHUB_WORKER_ISOLATION=hardened` | the hardened worker policy from M6 |
| `LIBREHUB_API_PUBLIC_URL`, `LIBREHUB_WEB_PUBLIC_URL`, `LIBREHUB_PUBLIC_BASE_URL` are `https://` origins with no credentials | TLS everywhere |
| `LIBREHUB_DATA_DIR` is absolute | no relative state |
| `LIBREHUB_TRUSTED_PROXIES` lists IP addresses | forwarded client addresses are honoured only from listed proxies |
| `LIBREHUB_METRICS_BIND` is loopback or private | metrics are never public |
| `LIBREHUB_LOG_FORMAT` is `json` or `text` | |
| Every `*_FILE` path exists, is a regular file, and is private unless it is public material | secrets are owner-readable only; public keys and CA files may be shared |
| A start never creates `webhook.key` | encryption identities are provisioned, not generated silently |

## Test-only switches

These variables exist only for the test harness. In a release build, `librehub_common::test_hooks::test_env` ignores **every** `LIBREHUB_TEST_*` variable, so a deployment cannot enable:

- the publisher's DNS TXT override (`LIBREHUB_TEST_DNS_TXT`), which could otherwise replace publisher verification;
- the vulnerability fixture and outage switches (`LIBREHUB_TEST_VULNERABILITY_*`), which could otherwise replace security verdicts;
- the source-repository fixture (`LIBREHUB_TEST_SOURCE_*`);
- fault barriers (`LIBREHUB_TEST_*_FAULT_STAGE`);
- loopback webhook destinations (`LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS`) and plain-HTTP identity metadata (`LIBREHUB_OIDC_INSECURE_FOR_TESTS`).

Debug builds still honour them for the test suite. Production uses release builds only (`cargo build --release`), and the production container images are built the same way.

## Network boundaries

| Component | Reachable from | Never reachable from |
| --- | --- | --- |
| nginx | the internet (443; 80 redirects) | — |
| web | nginx only (127.0.0.1:3000) | the internet |
| API | nginx (172.17.0.1:8080) and the web container | the internet directly |
| metrics | Prometheus container (172.17.0.1:9464) | nginx (returns 404 for `/metrics`), the internet |
| flat-manager | the API host process (127.0.0.1:8081) | the internet |
| PostgreSQL | the flat-manager network only (internal) | any host or public address |
| Grafana, Prometheus, Alertmanager | loopback only, for operator access through a tunnel | the internet |

Firewall: allow inbound 80 and 443 only. Deny inbound on every other port, including 8080, 8081, 9090, 9093, 9464 and 3001. Keep the Docker bridge (`172.17.0.0/16`) unrouted from outside the host.

## Browser and request controls

- nginx sends HSTS (`max-age=31536000; includeSubDomains`) on every TLS server, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a strict referrer policy and a restricted permissions policy.
- The web store sends a Content-Security-Policy. **It permits inline scripts** because the current Next.js build emits them. Tightening it to nonces is a follow-up; the policy is therefore weaker than an ideal one.
- Request bodies are limited to 64 KiB on the web host and 1 MiB on the API host.
- Rate limits: 20 requests per second per client address for general traffic (burst 60 on the web host, 100 on the API), and 2 per second with a burst of 5 for the OIDC exchange. Limits are per address; a client behind a shared NAT shares its budget.
- The API applies its own admission quotas for OIDC exchanges, automation runs and webhook subscriptions (`services/api/src/automation_store.rs`).
- Forwarded addresses are set by nginx (`X-Forwarded-For` is replaced, not appended), and the API trusts them only from `LIBREHUB_TRUSTED_PROXIES`.

**Not verified in M8:** CSRF protection on every privileged cookie-based dashboard mutation, and the dashboard's behaviour in a real browser. The dashboard acceptance test was not added in this milestone; treat dashboard sessions as unverified.

## Secrets

| Secret | Location | Owner and mode | Used by |
| --- | --- | --- | --- |
| flat-manager database password | `/etc/librehub/secrets/flat-manager-db-password` | root, 0400 | PostgreSQL, flat-manager config |
| flat-manager token secret and config | `/etc/librehub/secrets/flat-manager-config.json` | root, 0400 | flat-manager |
| publisher token | `/etc/librehub/secrets/publisher.token` | librehub, 0400 | API (scoped to build, upload and publish) |
| repository GPG key | `/etc/librehub/gpg` | root, 0700 | flat-manager only |
| attestor seed | `/etc/librehub/secrets/attestor-seed` | librehub, 0400 | API (M6 attestor) |
| webhook encryption key | `/var/lib/librehub/data/webhook.key` | librehub, 0400 | API |
| Grafana admin password | `/etc/librehub/secrets/grafana-admin-password` | root, 0400 | Grafana |

Compose receives these as file-backed secrets. No secret is written in a Compose file, an environment file, a unit file or a log line. Build workers receive none of them: the build containers have no mounts of these paths, and the M6 hardened policy applies to them. The GitHub OIDC exchange credential is minted per run and is revoked when its connection is changed (see [OIDC federation](oidc-federation.md)).

## Build workers never receive

- GPG private keys, the attestor seed, or any other signing material;
- flat-manager administrative credentials or the publisher token;
- GitHub OIDC exchange material, developer API tokens, or webhook signing secrets;
- production database credentials.

The build container is created with a read-only root filesystem, no host or volume mounts, and a single tmpfs at `/work`; the executor inspects each container and refuses one with any other mount (`services/builder/src/docker.rs`). Build containers have no network and no privileges. A runtime inspection test on a live build is **not** part of M8; check it with `docker inspect` as part of acceptance.

## Shared-kernel risk

Build workers share the host kernel. Rootless containers, dropped capabilities, `network none` and the M6 policy reduce the attack surface, and they do not make the host a security boundary against a hostile workload. Assume that a kernel or runtime vulnerability can let a build escape to the build account, and design accordingly:

- run the build daemon under a dedicated, unprivileged account, never the API account;
- keep the host kernel patched, and enable unattended security updates;
- keep the signing key on the publisher path only, so an escaped build cannot sign;
- accept that a build escape can read build inputs, but not the keys above.

LibreHub does not claim hostile multi-tenant isolation. Use separate hosts for separate trust domains.

## Supply chain for LibreHub itself

- All CI actions in `.github/workflows/ci.yml` are pinned to full commit SHAs.
- The production images are pinned by digest in `compose.yaml`, which fails to render without them.
- Release binaries are built with `--locked` from a reviewed tag. Checksums and signatures for release artifacts are **not** published in M8; add them in your release process before production use.
- Production signing keys are never used in pull-request workflows. The CI in this repository uses only generated stand-ins.
