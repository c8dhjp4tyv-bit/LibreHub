# Operational worker isolation profiles

`LIBREHUB_WORKER_ISOLATION=compatibility` preserves M1 Docker/Podman behavior.
Seccomp/AppArmor and masked procfs protections are relaxed for nested bubblewrap.
Bridge networking is unrestricted egress, including potential internal-service
access. HTTPS source validation does not contain arbitrary build-script networking.
Use a dedicated disposable development host. Compatibility has no writable-layer
quota and is rejected by production supply-chain enforcement.

`LIBREHUB_WORKER_ISOLATION=hardened` requires `LIBREHUB_DOCKER=podman`, rootless
execution, cgroup v2 and seccomp. The worker uses an immutable local image ID,
read-only rootfs, ignores image volumes, has no user host mounts, retains Podman's
seccomp policy, and verifies the generated OCI seccomp/no-new-privileges
configuration before starting. Actual inspect data must reject privileged mode,
unconfined security options and unexpected bind/volume mounts. Writable `/work`
is a 2 GiB tmpfs; `/tmp` is a 64 MiB tmpfs; implicit writable tmpfs is disabled.
Memory/swap: 4 GiB, CPUs: 2, processes: 512, descriptors: 4096. Logs and artifacts
retain M1 limits. Read-only image runtime data remains available; writable caches
must live in the bounded work area. The detached idle container allows copying
inputs into the mounted tmpfs before running the fixed build helper.

Networking is `none` and hardened mode rejects bridge/host networking. This denies
IPv4/IPv6 egress, metadata/internal-service access and arbitrary network fetches
rather than pretending URL validation is a firewall. Runtimes come from the pinned
image; fixtures use local/inline sources. Remote dependencies must already be
available/offline-compatible; a controlled fetch/cache stage is not implemented.
Compatibility remains available for network-dependent development workflows.

Targeted `unmask=/proc/*` is still required by nested bubblewrap; no
`systempaths=unconfined`, `seccomp=unconfined`, `apparmor=unconfined` or privileged
fallback is allowed in hardened mode. Rootless/default seccomp/resource checks
are materially stronger than M1 compatibility but share the host kernel. This is
not a VM or microVM executor and not a claim of safe hostile multi-tenant hosting.
Podman, OCI runtime, LSM/cgroup delegation and kernel configuration remain trusted
host dependencies. An unsupported platform fails closed.

Cancel/timeout removes the deterministic UUID container through existing M1
cleanup; restart removes interrupted workers before resuming the queue. Ephemeral
writable mounts disappear with removal. Aggregate source/artifact/database/image
retention still requires operator quotas and backup policy. M3 snapshots retain
64 MiB/4096-file bounds and M2 artifacts retain 1 GiB bounds.

Real platform acceptance:

```bash
LIBREHUB_DOCKER=podman cargo test -p librehub-builder --test flatpak \
  builds_hello_under_hardened_rootless_podman -- --ignored --nocapture
```

Normal CI runs the original M1 Docker compatibility build and separate real
rootless Podman acceptance. Neither demonstrates a VM boundary. Policy unit
tests always run. See m6-verification.md for the actual observed outcome.

## LSM support and observed platform limits

The tested Ubuntu 24.04 rootless Podman reports AppArmor unavailable. The supported
profile's required protections are rootless user namespaces, retained OCI seccomp,
no-new-privileges, private PID/IPC/UTS/network namespaces, read-only image storage,
bounded tmpfs and verified cgroup limits. It does not claim AppArmor enforcement.
An engine reporting AppArmor active is rejected until a compatible enforcing
profile is proven. There is no AppArmor-unconfined fallback.
On SELinux hosts the executor selects/verifies maintained `container_userns_t`,
preserving MCS labeling. Fedora container-selinux 2.251.0 denies the nsfs remount
needed by Flatpak, so that combination currently fails closed. No LSM boolean,
label disabling, privileged mode or automatic downgrade is used. The selected
SELinux type is recorded when applicable. CI runs actual rootless/seccomp builds,
cancellation and abandoned-worker cleanup and the full pipeline in enforcement.
