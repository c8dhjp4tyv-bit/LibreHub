# Attestations, DSSE and trust bootstrap

Build predicates use [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)
inside an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
The required `buildDefinition` and `runDetails` structures use the standard
lowerCamelCase field names. The release predicate URI is
`https://librehub.org/attestations/release/v1`; it is not labeled as a SLSA build
predicate. `buildType` and `builder.id` identify the LibreHub container build
implementation documented here and in build-pipeline.md, not certification.

Payloads use compact UTF-8 JSON with lexicographically sorted object keys, no
floating point parameters and the typed version-1 LibreHub parameter profile.
The signature authenticates exact payload bytes. DSSE PAE is
`DSSEv1 <byte-length(type)> <type> <byte-length(payload)> <payload>`.
`payloadType` is `application/vnd.in-toto+json`; Ed25519 signatures and payloads
use standard base64. One explicitly identified signature is accepted per
envelope. Bounds: 256 KiB payload, 384 KiB envelope, 32 keys, 10 MiB SBOM,
1 GiB original bundle. Unknown predicates, invalid schema, duplicate signatures,
unknown/revoked keys, altered bytes and noncanonical payloads fail verification.

This profile validates LibreHub statements; it is not a general verifier for
arbitrary third-party SLSA build types. The independent schema test uses pinned
upstream in-toto/SLSA generated protobufs, not LibreHub's Rust types. Ed25519
verification is also exercised with OpenSSL. No SLSA Build Level is claimed:
shared-kernel workers, administrative access to the control plane, incomplete
material observation and lack of independently measured builder identity leave
stronger isolation/completeness requirements unproven.

Provision keys explicitly while the API is stopped:

```bash
umask 077
mkdir -p operator-keys
./target/debug/librehub-admin attestor provision \
  operator-keys/attestor.seed operator-keys/trusted-keys.json
export LIBREHUB_ATTESTOR_KEY_FILE="$PWD/operator-keys/attestor.seed"
export LIBREHUB_ATTESTOR_KEYS_FILE="$PWD/operator-keys/trusted-keys.json"
```

The private file is a raw 32-byte Ed25519 seed and must be mode 0600. Provisioning
refuses overwrite. The key ID is `ed25519:sha256:<hash-of-raw-public-key>`.
Keys have active/retired/revoked states. Only active keys sign; retired keys verify
history; revoked keys never verify and revocation cannot be undone in the same
store. Key additions/state changes are audited in SQLite. Historical public keys
are retained. Removing the signing seed causes startup/readiness/signing failure,
never automatic regeneration. Production operators provision, encrypt/back up and
protect seeds separately from data. CI uses disposable explicit test keys only.

For rotation, provision a new pair in fresh paths, append its public record to
the authenticated existing bundle, mark the former signing key retired (or revoked
when compromised), switch the seed path and restart. Do not replace public bytes
under an existing key ID. Distribute the new trusted bundle/fingerprints through
an authenticated operator channel; the API key endpoint alone is not trust bootstrap.
The attestor identity is separate from M2's repository GPG key.

Offline verification (replace values with independently expected release identity):

```bash
curl --fail -o attestations.json \
  https://hub.example/api/v1/catalog/apps/org.example.App/releases/PUBLICATION_UUID/attestation/download
# Obtain trusted-keys.json from the operator's authenticated distribution channel.
# Compare ed25519:sha256:... IDs with the separately authenticated fingerprints.
flatpak info --user --show-ref org.example.App
flatpak info --user --show-commit org.example.App
./target/debug/librehub-verify attestations.json trusted-keys.json \
  --ref app/org.example.App/x86_64/master \
  --checksum EXPECTED_INSTALLED_OSTREE_SHA256 --publication-id PUBLICATION_UUID \
  --source https://github.com/example/app.git --image sha256:EXPECTED_IMAGE_CONFIG_DIGEST
# Optional: --artifact original.flatpak --sbom release.spdx.json
python3 -c 'import json,base64; b=json.load(open("attestations.json")); print(base64.b64decode(b["build"]["payload"]).decode())'
```

Use a normal GPG-verifying Flatpak remote to authenticate the installed commit.
The verifier checks supplied expected identity, both signatures and build/release
linkage locally and exits nonzero with machine-readable failure on mismatch.
It never calls LibreHub. Trust-on-first-use is not silently implemented.
