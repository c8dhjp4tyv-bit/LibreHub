# M1 security and deployment boundaries

M1 is intended for a trusted development operator on a dedicated Linux build host.
Manifest build commands execute arbitrary code. Validation improves developer
feedback and blocks obvious unsafe configuration; it is not a complete security
policy. Authentication, per-user authorization/quotas, scanning and hardened VM
isolation belong to later milestones (including M5). Keep the unauthenticated API
on localhost, or provide authentication and admission controls at a trusted gateway.

## Container boundary

Each job runs as UID/GID 10001 in a fresh container. No host directories are mounted.
Only normalized manifest data is copied in; only the regular bundle file is copied
out. Containers receive no host environment variables, SSH keys, GitHub tokens,
signing keys, host `/home`, or Docker socket. The image's `/home/builder` is private
container content containing runtime tooling, not a mounted host home.

The supervisor alone invokes the container CLI. Docker daemon access is equivalent
to host administrative capability; isolate the supervisor account and use a
dedicated host. Rootless Podman is an alternative on compatible Linux hosts, selected
with `LIBREHUB_DOCKER=podman`. It uses the same no-mount worker command path.

Workers drop all Linux capabilities, enable no-new-privileges, cap memory/swap at
4 GiB, CPUs at 2, process count at 512 and file descriptors at 4096. Docker logging
is disabled to avoid duplicate unbounded daemon logs. Builds have a deadline.
No privileged mode, host PID namespace, host networking or SYS_ADMIN is used.
`flatpak-builder --sandbox` also disables manifest-provided build-args.

Bubblewrap needs nested unprivileged user/mount namespaces. M1 disables Docker's
seccomp and AppArmor profiles **for workers only** to support these namespaces.
This weakens the container boundary and exposes more of the shared host kernel.
Containers are not sufficient isolation for a hostile multi-tenant public build
service. Run M1 on a dedicated disposable machine; do not place credentials or
other sensitive workloads there. A VM executor and a narrow tested syscall policy
are future hardening work.

Some hosts disable unprivileged user namespaces globally or enforce AppArmor
restrictions despite per-container flags. Such hosts should fail the opt-in test;
do not repair this by using privileged workers. CI uses a disposable runner and
explicitly disables its AppArmor user-namespace restriction to run the test.
Host configuration must be evaluated by the operator.

## Inputs, network and files

UUID job IDs are parsed before filesystem use. Manifest IDs and destination paths
are validated; no arbitrary request paths reach the host. Only self-contained
inline modules are supported. Local files/includes, filesystem finish grants,
build-args, BaseApps and runtime/extension builds are rejected. Remote file/archive
sources require HTTPS URLs without credentials and SHA-256 checksums. Shell/build
commands remain intentionally executable code inside the container.

Default worker networking is `none`. Enabling `bridge` permits source downloads
and potential access to private networks, metadata services and redirects; HTTPS
validation is not an SSRF or egress firewall. Git revisions are not automatically
pinned. Supply trusted manifests or enforce external network policy. Runtime/SDK
remotes are provisioned only by the operator's image build.

Artifacts are untrusted bytes and are never executed on the host. The copy archive
is bounded and parsed without unpacking a directory tree. Links and unexpected
paths are rejected, and destination files are atomically created without overwrite.
The configured data directory, SQLite files, image and container executable must
be operator-owned and protected from other local users. Run the API with a private
umask (for example `umask 077`) if manifests/logs may contain confidential data.

## Resource and recovery limits

HTTP body, manifest depth, queue, log rows/bytes, artifact bytes and build duration
have explicit caps. Streaming continues after the log quota to avoid pipe deadlock.
Logs include arbitrary compiler text; clients must escape it before HTML display.
Retention and aggregate database/artifact capacity remain manual. A worker can
fill its writable layer before exporting an artifact: container memory limits do
not bound disk. Apply filesystem quotas/monitoring to the build host and restrict
submission volume. Image/runtime downloads need several GiB too.

Cancellation terminates the actual container and client, with forceful removal if
needed. Cleanup errors are visible and startup fails if interrupted containers
cannot be removed. SIGKILL/power loss cannot guarantee immediate cleanup; restart
recovery removes deterministic UUID container names before marking jobs failed.
Service-owned temporary workspaces are then removed. Preserve backups of metadata
and artifacts together; M1 does not provide a backup or automatic retention service.

M2 adds flat-manager, OSTree publication, signing, `.flatpakrepo`, and public
installation. M1 stores unsigned private bundles and possesses no signing keys.
