# M6 verification and recovery

Local gates are the unchanged Rust fmt/strict Clippy/workspace tests/locked build,
Compose config and frontend npm-ci/lint/types/tests/production build. Additional
checks cover DSSE byte encoding, real Ed25519/OpenSSL signatures, bounded schema
validation, substitution/unknown/revoked keys, isolation admission and source/SBOM
integrity. `scripts/validate-attestation.py` uses pinned upstream protobufs and
SPDX 2.3 JSON schema with reference/checksum validation independently of Rust DTOs.

The mandatory CI acceptance `scripts/test-supply-chain.py` creates a real HTTPS
Git fixture, resolves its SHA, builds M1's actual Flatpak, rehashes the artifact,
signs build provenance, verifies PAE/signatures with OpenSSL, publishes using M2,
verifies public evidence using the offline CLI, downloads/validates the SBOM,
installs/runs with normal Flatpak, checks the installed checksum and tests exact
evidence retention across API restart. Debug-only fault barriers stop the real
process during evidence collection, after bundle verification, after signing and
after persistence for builds and releases; the acceptance script kills/restarts
at each barrier and checks immutable identities. Release builds compile out
these operator-only test hooks. It exercises tampered payload/signature,
wrong artifact/checksum/key/subject/SBOM/material/publication identities and deterministic/nondeterministic rebuilds.
Test attestor seeds remain in temporary operator storage and are never uploaded.
Proof/artifacts are in `data/m6-proof/`, labeled with GitHub commit SHA and retained
for seven days. Existing M1–M5 acceptance steps remain mandatory.

Run against the existing ephemeral signed Compose environment:

```bash
cargo build --workspace --locked
python3 -m pip install protobuf==6.33.5 jsonschema==4.25.1 spdx-tools==0.8.3
. data/dev/publisher.env
python3 scripts/test-supply-chain.py
# Platform-specific: use the rootless Podman worker image and a compatible host.
LIBREHUB_M6_HARDENED=1 python3 scripts/test-supply-chain.py
```

CI first attests Docker compatibility in audit mode, then runs the actual
rootless Podman/seccomp profile and repeats the full pipeline in enforcement
mode. The tested engine reports AppArmor unavailable; AppArmor enforcement and
a VM boundary are not claimed. Fedora SELinux 2.251.0 fails closed as documented
in build-isolation.md. No fixture/mock substitutes for Flatpak, signing, install
or operational hardened execution evidence.

## Recovery and operational limits

Migration 006 is additive. Typed attestation payloads and normalized identity/digest/
key columns are committed together in SQLite transactions. Signing before a crash
can be repeated with deterministic Ed25519 and fixed build/publication timestamps;
persistence is immutable/idempotent and conflicting payload digests fail. There
are no half-written envelope files to trust. Audit events and failed/pending job
state survive restart. Signing retry never republishes an already successful release.
SBOMs use atomic no-overwrite placement, retain their original creation time on
identical retries, reject changed composition and are rehashed on every download.

Back up SQLite/WAL consistently with build bundles, retained source snapshots,
SBOMs and the original public key bundle; back up private signing seeds separately
in encrypted protected storage. Restore identifiers intact. Do not regenerate
statements to replace signed history. Catalog rebuild is derived metadata only.
Lost seeds stop signing/readiness; retire a replaced key and retain its public
record, or explicitly revoke after compromise. Historical unattested releases
remain installable without fabricated build evidence.

No transparency log, HSM service, measured/remote builder attestation, VM boundary,
controlled dependency mirror, exhaustive fetched-material inventory, universal
reproducibility or automatic aggregate retention is implemented. Those limits must
be considered during human review and deployment.
