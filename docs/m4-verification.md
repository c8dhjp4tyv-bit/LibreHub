# M4 verification

M4 completion requires real stable publication → indexing → actual store → standard
signed Flatpak installation. Passing unit tests alone does not satisfy acceptance.

The mandatory worker-image CI job preserves M1's real executor, M2's signing/
install/crash scenarios and M3's real Git/HMAC/deduplication/recovery scenarios. It
then builds the actual web app, installs Chromium and runs
`scripts/test-public-store.py`. The test uses the M3 disposable HTTPS smart-Git
fixture with committed metainfo/desktop/PNG files and an actual M1 Flatpak build.
It verifies the unpublished successful build stays hidden, publishes stable through
real flat-manager, waits for indexing, checks public metadata/source commit/version/
checksum/permissions/categories/search, and executes a real failed build which
must remain hidden. Private project APIs must still reject unauthenticated clients.

It restarts an interrupted catalog job, performs the offline rebuild, and checks
there is one release row. It starts the production Next.js store and verifies SSR
metadata/security headers. One focused Playwright test uses that same live public
API/catalog: open store at mobile width, search by ID, open app, inspect provenance
and permissions, click Install and receive the reference file. No network mocks or
hardcoded production catalog are used. Finally the normal Flatpak client installs
the generated reference, compares installed ref/checksum to the publication,
verifies GPG signature trust and runs the app.

The CI transport fixture uses a reserved .test DNS identity mapped only by trusted
operator configuration. Its immutable source commit is public provenance; the
reserved fixture repository hyperlink is deliberately omitted by URL classification.
Ordinary public GitHub source URLs are retained and safe commit links are covered
by API/frontend tests. The fixture's declared homepage is a normal public URL.

Artifacts: `public-store-signed-installation-proof` contains data/m4-proof.json and
a real mobile screenshot data/m4-store-mobile.png. Proof contains public IDs and
checksums, never developer tokens, webhook secrets or private signing keys. The
Rust and web CI jobs separately enforce locked dependencies and lint/type/test/build.

## Reproduce

On a dedicated Linux host supporting Docker and nested unprivileged user namespaces:

```bash
export LIBREHUB_DEV_UID=$(id -u) LIBREHUB_DEV_GID=$(id -g)
docker compose up -d --build
sh scripts/wait-repository-bootstrap.sh
. data/dev/publisher.env
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
docker compose config --quiet
cd apps/web
npm ci
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install --with-deps chromium
cd ../..
# Stop an existing host API and Compose web before acceptance takes their ports.
docker compose stop web
python3 scripts/test-publish-install.py
python3 scripts/test-developer-platform.py
python3 scripts/test-public-store.py
```

## Review gates

Check proof artifacts and CI for the exact PR head. Pay particular attention to
public route/auth separation; stable/beta eligibility; immutable publication
identity; atomic last-good refresh/FTS; signed-checksum permission extraction;
AppStream XML resource bounds/no DTD; no raw HTML; URL/DNS validation; default-deny
Docker contexts; CSP and external screenshot privacy; and real reference installation.
An environment without Docker/namespaces or Unix sockets for gpg-agent cannot
prove signing/build/install, and must not be reported as M4 completion.

## Deliberate limits

One host/index worker and local SQLite; native builds but multi-architecture public
contracts; default-language canonical AppStream filenames; bundled PNG/monogram
UI icons; plain-text descriptions; bounded first-100 sitemap; no asset proxy;
external screenshots may change; public ETags still query/serialize; operator disk
retention and signing provisioning. Failed refresh leaves last-good metadata until
repair/rebuild, so catalog metadata may lag the latest repository ref. New indexes
need retained bundles/repository objects. No metadata-quality enforcement/moderation
is claimed. Ratings/reviews/likes/comments, badges, moderation/reporting, teams,
organizations/billing, recommendations, install telemetry and additional packaging
formats remain M5+.

This document describes executable verification, not an unearned success claim.
The PR records the actual checked head, results and CI proof URL.
