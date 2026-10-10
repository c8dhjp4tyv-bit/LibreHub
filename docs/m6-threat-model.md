# M6 threat model (before implementation)

Developer source, manifests, build scripts, worker output, remote responses and
downloaded envelopes are untrusted. The operator-owned supervisor/database,
source resolver, configured worker image, attestor process, publishing verifier,
flat-manager and protected key configuration form the trusted computing base.

The attestor must resolve records itself, rehash controlled source/artifact bytes,
verify imported Flatpak identity, and sign only bounded typed statements. Workers
cannot select statements or access signing keys. Build subjects are bundle digests;
release subjects are final signed OSTree checksums, linked by the signed build
payload digest. Source snapshots and image identities cannot drift across retries.

Publication policy must check the trusted store on admission and before remote
side effects. Remote success survives subsequent signing failure; a separate durable
attestation state is reconciled without republishing. Historical evidence is never
fabricated. Key removal fails startup; retired public keys preserve history and
revocation invalidates verification. Offline users supply authenticated trust keys
and expected subjects explicitly.

Compatibility Docker exposes a shared host kernel with disabled seccomp/AppArmor
and relaxed procfs paths. It is not a hostile multi-tenant sandbox. A stricter
rootless Podman profile must preserve seccomp, require offline networking, remove
writable image layers, bound writable tmpfs, check actual runtime configuration,
and fail rather than downgrade. Targeted procfs relaxation and nested user
namespaces still expose shared-kernel attack surface; no VM boundary is claimed.

Provenance verifies recorded origin and linkage, never malware absence. Declared
manifest dependencies differ from observed source/image/runtime inputs. A rebuild
compares pre-publication OSTree content, excludes commit/signature timestamps,
and separately records differing/inconclusive results.
