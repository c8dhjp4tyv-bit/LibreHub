# Repository deployment and signing

Stable and beta are separate flat-manager repositories, retaining each manifest's
Flatpak branch (default `master`). This allows independent publication and trust
configuration without conflating release channel with Flatpak branch. Only these
two validated channels are accepted in M2; the enum/adapter boundary can support
more channels in a later migration.

## Local stack

On a dedicated Linux host with Docker daemon access, Compose, Rust, Flatpak,
OSTree and GnuPG, from the repository root:

```bash
export LIBREHUB_DEV_UID=$(id -u) LIBREHUB_DEV_GID=$(id -g)
docker compose up -d --build
sh scripts/wait-repository-bootstrap.sh
# After bootstrap exits successfully:
. data/dev/publisher.env
cargo run -p librehub-api --bin librehub-api
```

Compose builds the native M1 worker image and the pinned manager. PostgreSQL uses
explicit development-only credentials and has no host port. The manager API binds
host localhost:8081, nginx binds localhost:8090, and the LibreHub API defaults to
localhost:8080. The API runs on the host to invoke the container CLI, preserving
M1's rule that no container gets a Docker socket. Compose bootstrap generates the
public descriptor and exports **only** a scoped publishing token and public key to
`data/dev/`; source its environment file after initialization. The build worker
gets no mounts, publishing environment, credentials or signing keys.

Submit/build/publish/install with the README commands. For a full automated local
reproduction, stop any API already listening on 8080, keep Compose running, source
the generated environment, then:

```bash
cargo build --workspace --locked
python3 scripts/test-publish-install.py
docker compose down --volumes
```

The test starts its own API with a temporary SQLite/build directory and removes
its isolated Flatpak installation. Compose volume removal destroys the disposable
repository/signing/database state; do not use that command on valuable production
data. Delete the obsolete local `data/dev/` credentials after removing the stack.
Development keys and tokens expire after one day. Recreate disposable volumes and
rerun bootstrap to generate a new key and token; remove/re-add client development
remotes when the trusted key changes.

## Storage and HTTP layout

```text
Host data/
  builds/<build-uuid>/artifacts/application.flatpak
  publishes/publish-<random>/application.flatpak + repo/  (private temporary import)
  publishes/verify-<random>/repo/                        (temporary signed pull)
  builds.sqlite3                                       (build/publication records)
  dev/publisher.token + repository.gpg + publisher.env   (development only)

Trusted manager-state volume/
  config.json + token-secret
  gnupg/                                               (PRIVATE signing keys)
  builds/<flat-manager-build-number>/                   (staged upload/commit)

Public repository-data volume/
  librehub.flatpakrepo
  librehub-beta.flatpakrepo
  repository.gpg                                       (public key)
  repo/stable/{config,objects/,refs/,summary,summary.sig,...}
  repo/beta/{config,objects/,refs/,summary,summary.sig,...}
```

Normal completion removes private temporary imports/verifications via RAII.
SIGKILL may leave private temporary directories; remove stale `publish-*`/`verify-*`
workspaces only while LibreHub is stopped. Recovery always constructs fresh
workspaces and never trusts leftover imports. Total retention/disk capacity remain
operator-managed, as in M1. The publisher caps artifacts at 1 GiB and object
inventories at 32,768 objects / 2 GiB; aggregate repository retention is not bounded.

flat-manager alone writes public OSTree repository refs/commits/summaries. nginx
mounts only public repository data read-only and serves ordinary static files.
The API serves equivalent descriptors and public-key bytes for deployments that
prefer its trust endpoints. Production can mirror/upload manager-generated
immutable objects plus updated summaries to S3-compatible storage/CDN while
retaining the same `RepositoryConfig` and publishing domain. Ensure atomic snapshot
visibility of refs/summary/signatures and invalidate summary caches. The publisher's
public URL verification must target the actual client-facing origin. M2 does not
implement an S3 adapter or CDN synchronization.

## Signing and authentication boundary

The development bootstrap dynamically generates an RSA-2048 signing key named
`LibreHub DEVELOPMENT ONLY (ephemeral)` with a one-day expiration. CI uses this
same fresh key-generation path with disposable volumes and no production secret.
No private key is checked in or copied into either image. Key generation occurs
at container runtime, inside the trusted manager volume. The public key is binary
exported, embedded as base64 `GPGKey` in `.flatpakrepo`, and served at
`/repository.gpg`. flat-manager signs staged commits, published commits and updated
summaries using its `build-gpg-key`, per-repository `gpg-key` and `gpg-homedir`.

Production must replace bootstrap with operator provisioning: a durable,
protected signing key store accessible only to flat-manager or a signing boundary,
encrypted backups, restricted filesystem permissions and a documented rotation
procedure. Do not reuse the development identity, passphrase-free key, PostgreSQL
password or token secret. No API endpoint accepts a private key. Builders never
receive the key store or manager credentials. Keep the publishing API behind a
trusted gateway; M3 adds developer authentication and owned-build publication checks.

The bootstrap also generates a random manager JWT signing secret inside its
private state volume. It invokes upstream `flat-manager-client gentoken` to issue
a one-day publisher token with only `build`, `upload`, `publish`, repositories
`stable`/`beta`, and allowed Flatpak branches. LibreHub uses build-scoped job
endpoints, so `jobs`, `republish`, `generate`, `reviewcheck`, `download` and
`tokenmanagement` scopes are unnecessary. Production tokens should further
constrain app IDs/prefixes and branches according to deployment policy. Load them
through a protected token file or secret environment, rotate/revoke out of band,
and use TLS for any nonlocal manager/public traffic. Never pass credentials on CLI
arguments or publish them as an artifact. CI's uploaded proof contains only public
IDs/checksums/fingerprint, never tokens or private keys.

Configuration reference is in the README. Public URLs are validated HTTP(S)
operator values, with no userinfo/query/fragment or INI line injection. The API
never allows clients to choose filesystem paths, repository names or signing keys.

## Readiness and limits

`/health` retains M1 liveness. `/ready` returns 200 only when SQLite responds, the
publisher supervisor is running, private staging storage supports write/sync, the
scoped manager can answer an authenticated build query, and signed summary files
are reachable for stable and beta through the configured public origin. Otherwise
it returns 503 with component `ok`/`unavailable` values, without diagnostics/secrets.
Actual publication additionally verifies summary/commit GPG trust and checksums.

M2 remains one LibreHub instance per local SQLite/data directory, native architecture,
trusted operators and manual retention. It does not provide administrative uncertain
state resolution, rollback, key rotation automation, multi-tenant authentication,
multi-architecture fleet scheduling or automatic runtime mirroring. Clients get
Freedesktop runtimes from the independently trusted Flathub remote.
