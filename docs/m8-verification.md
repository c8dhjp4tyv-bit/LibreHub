# M8 verification

This record states what M8 verified, where, and what it did not. Commands are reproducible from the repository.

## M7 defects fixed in this milestone

| Defect | Fix | Regression tests |
| --- | --- | --- |
| An outbound webhook delivery error ended the outbound supervisor and cancelled the shared shutdown token. | Every task outcome is settled explicitly (success, error, panic, cancellation). Attempts are recovered with their identity intact, dead-letter after their budget, and are fenced so a stale result cannot overwrite a newer one. Storage errors back off; only corrupt storage degrades the worker. | `services/api/tests/webhook_isolation.rs` (5 tests) and the classifier unit tests in `outbound_worker.rs` |
| A changed OIDC policy (for example a removed branch or workflow, a restricted environment or event, a changed owner, or a shorter lifetime) did not revoke existing credentials. | Any real change to the normalised policy revokes every credential of that connection in the same transaction. Authentication re-checks the owning integration on every request. | `services/api/tests/policy_revocation.rs` (8 tests) |
| (Found in M8) The automation supervisor had the same defect: one failed tick, or one panicked run, ended the process. | Failures back off and retry; only corrupt storage degrades the worker; the shared token is never cancelled. | `services/api/tests/worker_isolation.rs` and the process-level run described below |

## Other M8 defects fixed

- Test-only switches (`LIBREHUB_TEST_*`, including the publisher DNS TXT override and the vulnerability fixture and outage switches) were read by release builds. They are now ignored in release builds (`librehub_common::test_hooks`).
- The production profile did not exist; it is validated before anything binds (`services/api/src/production.rs`, 10 unit tests, and `deploy/production/scripts/ci-validate.sh`).
- The `public` secret-permission check would have rejected correctly shared public keys; it now exempts public material (unit test).

## Commands and results (this environment)

| Check | Command | Result |
| --- | --- | --- |
| Formatting | `cargo fmt --check` | pass |
| Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass |
| Workspace tests | `cargo test --workspace --locked --no-fail-fast` | 50 suites pass; one fails in this sandbox: `dns_resolver_uses_ipv6_nameserver` requires IPv6 loopback, which the sandbox lacks. It is environmental and runs in CI. |
| API suites (M1–M8) | `cargo test -p librehub-api --locked` | pass, including the M7 regressions above |
| Production profile | `deploy/production/scripts/ci-validate.sh target/debug/librehub-api` | the shipped template passes; five unsafe settings are refused with status 2 |
| Compose file | `docker compose -f deploy/production/compose.yaml config --quiet` with pinned placeholders | valid; a missing image variable fails with a named error |
| TLS proxy | `nginx -t` with nginx 1.24 and a test certificate | syntax ok (stapling warning for the self-signed test certificate; no IPv6 in the sandbox) |
| Real process | start, `/live`, `/ready`, `/metrics` on both listeners, SIGTERM | live 200 with a request id; public `/metrics` 404; operator `/metrics` 200; SIGTERM exit 0; restart on the same data directory serves |
| Process under a poison outbox row | 200,000-event database with malformed rows | the API stays up; retries back off; metrics and liveness answer |

## Not verified in M8

These requirements are **not** met by M8. Each is listed so a reviewer can decide whether to accept the gap.

- **Production deployment end to end** (`scripts/test-production-deployment.py`). Not written. It needs a container runtime, Flatpak and a repository, none of which this environment has. The existing CI jobs prove the M1–M7 pipeline on the development stack.
- **Full-stack M7 acceptance** (Scenario A and B with a real automation and a real receiver). The Rust integration tests cover the same invariants in-process; the full-stack run is not automated.
- **Backup restore to an installable Flatpak.** The restore test checks records, bytes and integrity. It does not install an app or verify a restored DSSE attestation.
- **Browser dashboard acceptance.** Not added. The dashboard's CSRF and cookie behaviour is unverified.
- **Load tests, capacity measurements on the reference deployment, and SLOs.** Only the single-process figures in [capacity planning](capacity-planning.md) exist.
- **Versioned signed release artifacts** and published checksums.
- **Runtime proof that build containers hold no secrets** on a running build.
- **Restart tests for each in-flight state** (pending publication awaiting attestation, catalog indexing, approval waiting, webhook in flight) beyond the unit and integration coverage.
- **PostgreSQL control plane.** Not implemented; single-controller SQLite is the only supported backend.

## Reproducing the checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
deploy/production/scripts/ci-validate.sh target/debug/librehub-api
```
