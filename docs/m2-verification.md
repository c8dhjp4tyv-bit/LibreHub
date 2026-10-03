# M2 acceptance and review evidence

The automated normal-client installation succeeded in
[CI run 37149615887](https://github.com/c8dhjp4tyv-bit/LibreHub/actions/runs/37149615887)
on implementation commit `1eee4701680675a033c1cc400dea3bfefed43b1e`.
Its `signed-flatpak-installation-proof` artifact records:

| Evidence | Value |
| --- | --- |
| Build UUID | `2bbae05f-0ef4-47e4-9c65-a87e9efd1e3f` |
| Publication UUID | `078f9da7-224b-4db2-9d4a-2b493a409271` |
| flat-manager build | `1` (exactly one correlated creation) |
| Installed ref | `app/org.librehub.Hello/x86_64/master` |
| Installed/published commit | `84f0fd99a8638367fb32222acba802e6d5ae8b21f78837d7d3097b9602b8984d` |
| Ephemeral DEVELOPMENT signing fingerprint | `13DF07D2822D9617DA941F3D5BDF226831741188` |
| Signed summary SHA-256 before | `70482e2c19426c9b4b5fbf200ba662f31665eed35ab6d48ed8d23f946d30fcd6` |
| Signed summary SHA-256 after | `950d0edec7a7256afb9cfe2ed0171bd7a1a6fba807a39a298afc7984408fce03` |

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

No M2 acceptance item is left unproven by the automated installation scenario
and supporting checks. The subsequent documentation-only acceptance record and
trailing-manifest-whitespace cleanup do not alter the implementation tested above.
