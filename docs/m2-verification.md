# M2 acceptance and review evidence

The automated normal-client installation succeeded in
[CI run 37150088918](https://github.com/c8dhjp4tyv-bit/LibreHub/actions/runs/37150088918)
on reviewed PR commit `3f4da1e7bff7ff6f41c797e6a50c51d255299f72`.
Its `signed-flatpak-installation-proof` artifact records:

| Evidence | Value |
| --- | --- |
| Build UUID | `35dc0964-b49d-48e8-8a7b-5387ac506cc5` |
| Publication UUID | `7c130e8b-53d4-4de8-85c1-22d55a5a18a7` |
| flat-manager build | `1` (exactly one correlated creation) |
| Installed ref | `app/org.librehub.Hello/x86_64/master` |
| Installed/published commit | `e8745f4d99cda99c4b0bd150db027ffebcadf84a241f84745092f77669b6ac83` |
| Ephemeral DEVELOPMENT signing fingerprint | `EA6FA8270DD0E54EB3AFB106535A08307908510C` |
| Signed summary SHA-256 before | `cdd4d9c87726e15f6cd2e91efc4d4e15d3eaab58036e8451cae9a4189944288b` |
| Signed summary SHA-256 after | `cf74c6a5e81f2894c38409585027312d3a1e67f8fc994e968654c87a79454e93` |

The test submitted the Hello manifest through the real M1 API/executor, published
through the M2 API and real pinned flat-manager/PostgreSQL, then installed from
nginx's signed repository using `flatpak remote-add` and `flatpak install` in an
isolated normal user installation. It matched installed origin/ref/checksum,
explicitly verified the GPG commit signature against the distributed key, and
executed the installed Hello application. It also verified beta discovery,
summary refresh and duplicate publication identity. GPG verification was enabled
throughout.

The API was SIGKILLed after real backend acceptance in `preparing`, `uploading`,
`committing` and `publishing`. Four restarts resumed the original publication,
with exactly one matching manager build. Neither the backend nor installation
steps were mocked. The test's temporary key was generated at runtime and destroyed
with Compose volumes; the fingerprint above is public evidence, not a production
trust recommendation.

## Checks

- `cargo fmt --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --locked`: 67 passed, zero failed; one opt-in real M1
  test intentionally ignored in this command and executed separately in CI.
- `cargo build --workspace --locked`: passed.
- `docker compose config --quiet`: passed.
- Python compilation for bootstrap/fault injection/installation scripts: passed.
- Real M1 executor test: one passed in CI.
- Real signed M2 build/publish/restart/install/run scenario: passed in CI.
- `cargo tree -d`: reviewed; duplicate base64, getrandom, syn and hash-map crate
  versions are transitive compatibility boundaries. No manager SDK was added;
  reqwest supplies the small HTTP/multipart adapter with Rustls TLS.

## Human review focus

Review the correlation-marker handling of ambiguous creation, the journal-before-
side-effect order, transaction/cancellation races, serialized same-ref releases,
bundle snapshot/hash/path validation, deployed and summary app metadata checks,
private-key rejection before serving trust endpoints, public summary/commit GPG
verification and separation of signing volumes from build containers. Inspect
the actual installation proof artifact, not only mocked/unit test output.

## Limits and deferred work

M2 supports a trusted operator, one LibreHub instance per local data/SQLite
directory and the native worker architecture. Aggregate retention, signing key
rotation and administrative resolution of uncertain/failed backend jobs remain
operator responsibilities. Cancellation ends at worker claim. Stable/beta use
separate repositories and manifest-defined branches. Runtime downloads use the
independently trusted Flathub remote. S3/CDN replication, automatic promotion and
rollback are documented foundations, not implemented endpoints.

Developer authentication/ownership verification, moderation, web store/catalog,
multi-tenant hardening, automatic source discovery, additional package formats,
multi-architecture fleets and update webhooks remain deferred to M3+.

This acceptance record is tied to the exact commit and artifact cited above.
Subsequent changes must pass their own CI checks and real installation scenario;
the PR description links the latest successful run.
