# M1 security model and limitations

M1 is a prototype for a trusted development/build host. It is not a hardened
public service for hostile multi-tenant workloads. M5 will extend policy and
isolation. Default HTTP binding is loopback; there is no authentication,
authorization, per-user rate limiting, or tenant boundary in this milestone.

## Build isolation

The API is a host supervisor with Docker access. Docker authority is powerful;
run this supervisor on a dedicated build host under a dedicated account. The
submitted manifest is copied into a fresh container. **No host directories,
Docker socket, SSH keys, GitHub tokens, signing keys, or host `/home` are mounted
or injected into the build container.** It only receives manifest data, a trusted
worker image (including runtimes), native architecture, and validated app ID.
The image has its own disposable home directory, unrelated to the host home.

The build runs as UID/GID 10001, with all Linux capabilities dropped and
no-new-privileges enabled. M1 does not use privileged mode, host namespaces,
host devices, or SYS_ADMIN. Containers get a two-CPU quota, 4 GiB memory with no
extra swap, a 512-PID cap, and a 4096-descriptor cap. A total build timeout
includes artifact collection. Docker's own log driver is disabled, since the
service persists bounded output itself.

Flatpak's bubblewrap requires nested unprivileged namespaces. M1 relaxes Docker
seccomp, AppArmor, and protected system paths (`seccomp=unconfined`,
`apparmor=unconfined`, `systempaths=unconfined`) so it can create those namespaces
and mount a nested `/proc` while retaining a nonroot outer container. Docker's
masked/read-only proc paths otherwise prevent bubblewrap's proc mount. This
weakens the outer syscall/LSM boundary and removes Docker's system-path masks;
it does not grant capabilities or share the host PID namespace. The host must
permit unprivileged user namespaces;
some Ubuntu hosts also restrict them through AppArmor. **Do not solve namespace
failures by adding privileged mode or SYS_ADMIN.** Use a dedicated host configured
for this workload, or a stronger VM executor. See
[Docker seccomp documentation](https://docs.docker.com/engine/security/seccomp/),
[Docker's system-path option](https://docs.docker.com/reference/cli/docker/container/run/#security-configuration),
[Moby's nested rootless configuration](https://github.com/moby/buildkit/blob/master/docs/rootless.md),
and [Flatpak's sandbox option](https://docs.flatpak.org/en/latest/flatpak-builder-command-reference.html).

The default build network is `none`. Runtime installation happens only while
provisioning the trusted image, from Flathub. Enabling `bridge` permits arbitrary
HTTPS source downloads and outbound connectivity, including potentially internal
services. There is no destination allowlist, DNS policy, SSRF defense, or malware
scan in M1. The validator's HTTPS restriction is not a network security policy.
Do not use bridge mode on a host with reachable sensitive services.

The container writable layer is disposable but has **no portable disk quota**.
CPU/memory/PID limits and timeouts do not prevent a build from exhausting daemon
storage. Artifact/log limits protect retained output, not working disk use.
Operators must use a dedicated bounded storage pool, monitor free space, and
apply daemon/filesystem quotas where available. Successful artifacts and
terminal metadata also have no global retention limit; remove old jobs/artifacts
operationally until a retention feature is implemented.

## Input and artifact boundaries

Manifests are limited to 1 MiB; HTTP bodies to 2 MiB. YAML is scanned before
materialization: anchors/aliases, nesting over 32 levels, and over 50,000 tokens
are rejected. JSON parser recursion limits and semantic nesting checks apply.
Errors are capped at 100. Core fields and source kinds are typed. Application
IDs must use reverse-DNS notation. Module names, command, runtime-version, and
branch cannot contain path traversal or command flags.

M1 accepts standalone manifests. Local source paths, included module files,
`build-args`, runtime/extension builds, bases, and selected unsupported extension
options are rejected. Destination paths cannot be absolute, parent-relative,
or Windows-style. Remote file/archive/patch sources require SHA-256 and HTTPS;
Git sources require HTTPS. Filesystem grants in finish-args are unsupported.
Other Flatpak options remain extensible. Commands are executable build input,
not harmless data: validation does not prove a package is safe.

`flatpak-builder --sandbox` disables manifest-specified sandbox build arguments.
It does not make arbitrary source processing safe for the host. The outer
container remains required. Container options, paths, and entrypoint are fixed;
app ID and architecture are validated and passed as separate command arguments.
There is no host shell interpolation of a manifest.

Container output is never unpacked as a directory tree. The service accepts one
exactly named regular `application.flatpak` file from a bounded tar stream,
rejects symlinks/hardlinks/extra entries, hashes it, and uses atomic nonoverwriting
persistence. Its host path uses a parsed UUID and fixed filename. Bundles remain
untrusted unsigned output; do not install them on a sensitive machine. M1 does
not serve, sign, publish, or automatically install these artifacts.

The configured data directory and Docker binary/image are trusted operator
configuration. Protect their ownership and permissions from other local users.
Logs may contain secrets supplied in build input/output; access to the API/data
must be restricted by the operator. There is no log secret-redaction promise.

## Failure, cancellation, and recovery

Cancellation is persisted and propagated to the actual executor. Container stop
attempts SIGTERM, then Docker escalates after five seconds; forced removal is a
fallback. Docker CLI commands have kill-on-drop behavior and cleanup operations
have bounded deadlines. If the daemon cannot confirm cleanup, the active record
is preserved for recovery and the supervisor stops. This intentionally favors
visible failure over silently abandoning execution environments.

SQLite state and logs use transactions. An exclusive lock prevents supervisors
from sharing one data directory. After restart, active containers are removed
before status recovery; queued jobs remain eligible. A machine/daemon outage can
leave containers until the supervisor is restarted with access to the same
Docker daemon. Operators should monitor `librehub-<UUID>` containers after hard
failures. The supervisor is not a distributed lease manager.

Executor task panics are caught at the task boundary and trigger teardown; normal
nonzero builds do not crash the API. Database failures and unverified teardown
are fatal supervisor errors. This prototype does not retry failed builds or
silently rerun interrupted work.

Signing keys, public OSTree publishing, flat-manager, `.flatpakrepo`, and public
installation are deferred to M2. Full adversarial policy, VM isolation, egress
controls, tenancy, and audits remain later work.
