# Supply-chain evidence and policy

M6 adds an Ed25519 attestor in the trusted host control plane and an offline
`librehub-verify` executable. Source/build containers receive neither attestor
keys nor publisher credentials. See [the threat model](m6-threat-model.md).

The build attestor resolves a terminal successful build from SQLite, rehashes the
retained M3 archive, reparses its selected manifest and compares the normalized
manifest to M1's stored input. It uses M2's independent bounded bundle copy,
Flatpak import, identity checks and OSTree fsck. No developer-supplied statement
or worker-declared checksum alone can authorize signing.

Build statements bind the original bundle SHA-256, immutable Git revision,
snapshot and manifest digests, runtime/SDK commits, image configuration digest,
builder implementation Git revision, execution dates, architecture, isolation and
network policy. Declared manifest sources are a separate list: they are not
represented as observed fetches. Source, image and installed runtimes are known
materials; arbitrary script downloads and exhaustive composition are not observed.

Release statements use a distinct, versioned LibreHub predicate. They bind the
final published OSTree checksum/ref/channel/repository/publication ID to the
SHA-256 of the signed build payload, original bundle digest, pre-publication
OSTree commit, and M5 SBOM digest. The final and original digests are different
kinds of objects and need not match. The attestor repeats signed public repository
verification and verifies the bundle import agrees with M2's source commit.

`LIBREHUB_SUPPLY_CHAIN_POLICY` accepts `development` (default), `audit_only` or
`enforce`. When signing is configured, admission records structured violations.
Enforcement requires explicitly hardened workers, a configured signing key and
`LIBREHUB_ALLOWED_WORKER_IMAGE_IDS` (comma-separated `sha256:<image-config-id>`).
It denies missing/invalid evidence, mutable declared remote sources and unallowed
or compatibility environments. Admission and the publisher both check the policy;
an ambiguous remote publication is suspended rather than declared rolled back.
Authorized build owners can read the latest decision at
`GET /api/v1/builds/:id/supply-chain-policy`.

Remote publication success remains authoritative even if release signing fails.
The independent `attestation_jobs` lifecycle is pending/verified/failed; failures
retry on restart or after offline `librehub-admin attestations retry`. Signing
retry never calls flat-manager's publish operation. Enforcement delays indexing
new attested builds until release evidence exists; legacy releases remain
installable and display `legacy_unattested`. Cryptographic verification remains
separate from publisher verification, vulnerabilities and moderation.

Public read-only routes:

- `/api/v1/supply-chain/keys`
- `/api/v1/catalog/apps/:app_id/releases/:release_id/provenance`
- `/api/v1/catalog/apps/:app_id/releases/:release_id/attestation`
- `/api/v1/catalog/apps/:app_id/releases/:release_id/attestation/download`

Evidence routes enforce application/release association, catalog presence and
removal moderation. They verify bounded stored signatures and current key states;
they do not import entire Flatpaks on catalog requests. No positive verification
cache survives a key change. Downloaded bundles contain both original DSSE
envelopes, not a server-supplied assertion that a signature is valid.

## Dependency update procedure

Critical Actions use reviewed commit SHAs, Rust/npm use committed lockfiles,
flat-manager uses its existing pinned source commit and pinned Rust image, and
worker/manager Debian bases use content digests. The worker pins Flatpak,
flatpak-builder, bubblewrap, Git and jq package versions plus per-architecture
runtime/SDK commits. New image builds explicitly deploy and check those commits;
a runtime branch change requires coordinated commit-pin updates. Other Debian
packages are not a fully reproducible snapshot of the package repository.

Review upstream security/release notes before updates; do not replace pins with
floating tags. Resolve new runtime commits with the normal trusted Flatpak remote,
update the architecture-specific Dockerfile pins, rebuild the image, run the real
M1–M6 and hardened acceptance checks, inspect recorded SDK/runtime/tool versions,
and deliberately update the operator's allowed image configuration ID. Preserve
old images for intended rebuilds. Changing a tag alone cannot rewrite historical
build evidence, and a missing old image yields an inconclusive rebuild.
