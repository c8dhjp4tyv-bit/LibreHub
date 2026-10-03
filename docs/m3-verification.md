# M3 verification

M3 acceptance requires the mandatory worker-image CI job, including the retained
M1 real executor and M2 signed install/recovery tests, followed by
scripts/test-developer-platform.py. A successful unit suite alone is insufficient.

The M3 test uses a dynamically initialized Git repository served over real HTTPS
smart Git with a disposable CA, without personal GitHub credentials. It bootstraps
a developer/token, creates an owned project, resolves main, discovers the manifest,
prepares a hashed snapshot with a repository-local file, executes M1, publishes to
beta through real flat-manager and installs/runs the app with a normal Flatpak
client with GPG verification enabled. It commits a changed source file, signs a
realistic GitHub push using HMAC-SHA256, checks the second exact commit/digest,
auto-publishes beta and installs/runs the update. A duplicate delivery after an API
restart must retain exactly two source events/builds overall.

Before the first M1 handoff, the API is SIGKILLed at deterministic queued, fetching
and handoff barriers. Each restart reuses the same event/build identity, with one
immutable SHA after resolution and one database M1 record. Fixture-only barriers
are compiled out of release builds. Existing M2 restart coverage still tests actual
backend acceptance at preparing, uploading, committing and publishing.

CI uploads developer-platform-git-workflow-proof (`data/m3-proof.json`), recording
developer/project IDs, two source commits, two snapshot digests, build/publication
IDs, webhook delivery UUID, installed ref/checksum, verified signing and execution,
and recovery stages. It excludes API tokens/webhook secrets/keys. CI also retains
signed-flatpak-installation-proof for the existing M2 scenario. A run URL and final
head commit are recorded in the PR; this document does not claim success before
that run passes.

## Reproduction

After README Compose/signing bootstrap, stop any API on port 8080, source
`data/dev/publisher.env`, then:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
docker compose config --quiet
python3 scripts/test-publish-install.py
python3 scripts/test-developer-platform.py
cargo tree -d
```

Source transport tests in the normal Rust suite launch their own temporary HTTPS
fixture (Python, OpenSSL and Git required) and check immutable revision fetch,
manifest discovery, local inputs, deterministic snapshot digest and symlink rejection.
API regressions cover token hash/non-persistence, one-time output, scopes,
revocation, header removal, cross-owner paths, Unicode-safe HMAC, signature-before-
parse, concurrent duplicates, filters/disabled projects, secret rotation, recovery,
archival, source errors, policy suppression and additive M2 migration.

## Review focus and limitations

Review shared middleware route scope/ownership selection, offline-only legacy
operator scope, ciphertext/project binding and rotation race checks, normalized
URL/DNS pinning and smart-HTTP enforcement, bare Git/environment/resource policy,
archive paths/type/count/size/digest checks, database handoff/delivery uniqueness,
and policy rechecks before automatic publication claim. Check actual proof artifacts.

New crypto dependencies are getrandom, hmac/subtle and chacha20poly1305. They provide
OS entropy, constant-time HMAC/digest checks and AEAD secret storage. Existing
sha2/tar/tempfile/reqwest/Axum machinery is reused; url supplies real URL parsing.
No Git hosting SDK is introduced. cargo tree -d includes transitive version splits
for base64/getrandom/hash maps/syn and ChaCha/rand-core families; AEAD and UUID's
random implementation currently require distinct compatible versions.

Public repositories/HTTPS smart Git only, native architecture and one instance per
local SQLite/data directory. No source cache, Git submodules, LFS smudge, symlinks,
parent-traversing local source paths or external manifest includes. Aggregate disk
retention, operator signing/key backup and gateway rate controls remain deployment
responsibilities. M1 container isolation still needs a dedicated disposable host.
Private Git credentials/OAuth/GitHub Apps, store/catalog/search, moderation,
ratings/reviews/badges, SBOM/permission UI, teams/billing, other providers' UI flows
and additional package formats are deferred to M4+ or later hardening.
