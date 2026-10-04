# Public catalog (M4)

The catalog derives from **successful M2 publications**, never builds, branch names
or frontend fixtures. M3 ownership and M2 signing remain unchanged.

## Model and persistence

Additive migration 004 creates catalog_apps (canonical app ID + channel identity,
normalized bounded JSON, safe publisher/project IDs, timestamps and optional PNG),
catalog_releases (unique publication ID, build ID, architecture, channel, published
checksum and public release JSON), catalog_categories, catalog_jobs and FTS5
catalog_search. Screenshots/keywords are finite ordered arrays in normalized app
JSON rather than additional tables. Each release retains its own permissions and
immutable Git provenance. Different architectures have independent current releases;
a public singular current release is the most recently published architecture.
Application URLs use `/apps/<Flatpak application ID>` and survive renaming.

Only stable publications enter default listings/categories/publisher pages. Beta
has independent metadata, accessed with `channel=beta`; beta-only apps return 404
on the default stable detail route. An indexed stable app can explicitly show beta
availability and actual beta history. Queued/failed/cancelled publications and
unpublished builds never enter public tables.

Disabled/archived projects and disabled publishers retain indexed apps and signed
releases. DTOs immediately mark them archived/inactive using current platform
status. M3 blocks new source work/automatic admission; already claimed builds or
M2 publications retain M3/M2 semantics. Explicit authenticated manual publication
of historical builds remains available, as in M3; M4 does not secretly revoke that
API. Archival is not moderation or repository removal. Publisher/project UUIDs and
build/publication UUIDs are intentionally public provenance identities; token IDs,
secrets, policy, audit and email data are never catalog DTO fields.

## Indexing and recovery

A single bounded catalog supervisor runs in the existing host API service. Every
second it discovers successful publications without catalog jobs and materializes
at most 64 active jobs. Publication records themselves are the durable overflow
backlog, so indexing overload cannot invalidate signing/publication. The worker
claims pending → indexing transactionally. Extraction is outside request handlers
and outside the SQLite lock. A transaction persists the release, newest eligible
app metadata, categories, icon and FTS document, then marks the job ready.

An extraction error becomes failed/metadata_index_failed internally; publication
remains succeeded and previous public metadata remains intact. Failure is not a
busy retry loop. Operators repair input/storage/trust then rebuild. Interrupted
indexing returns to pending on startup, reusing publication identity. Older jobs
can add history but cannot overwrite newer app metadata (publication timestamp +
ID ordering). Repeated indexing updates one release, never duplicates it.

Stop the API, preserve its data/signing environment, then run:

```bash
./target/debug/librehub-admin catalog rebuild
```

This offline command rebuilds FTS from last-good app records and clears catalog job
states. Restart repopulates the bounded queue from publication history. It never
changes builds, publications, checksums, signing or live repository refs. Retain
source bundles/public repository objects to support reindexing. Previous catalog
metadata is available during rebuild. Aggregate catalog/publication retention and
SQLite disk quotas remain operator responsibilities.

## Public API

All catalog endpoints are unauthenticated read-only GETs under `/api/v1/catalog`:

| Path | Response |
| --- | --- |
| `/apps` | Compact card page |
| `/search` | Server-ranked card page |
| `/apps/{app_id}` | Rich app detail + current per-architecture releases/install |
| `/apps/{app_id}/releases` | Actual published release history page |
| `/categories` | Standard categories with stable app counts |
| `/publishers/{developer_id}` | Public publisher and stable card page |
| `/apps/{app_id}/flatpakref` | Standard reference to real signed repository |
| `/apps/{app_id}/icon` | Bounded bundled PNG, if available |

Lists/search accept q (maximum 200 UTF-8 bytes/16 literal tokens), category,
architecture (x86_64/aarch64), channel (stable default/beta), sort, limit (1–100,
default LIBREHUB_CATALOG_PAGE_SIZE=24), offset (0–100000). Supported sorts are
recently_updated, recently_published and name. Every sort ends with canonical app
ID for deterministic ties. Search overrides sort with relevance. Invalid filters
or bounds return structured 400 errors; unknown apps return 404
catalog_app_not_found. Error bodies preserve existing `{code,message}` convention.
Release/publisher pages use bounded limit/offset; detail/icon/reference accept
channel. A requested unavailable reference architecture returns 404.

## Search

SQLite FTS5 unicode61 + diacritic normalization and 2/3/4 prefix indexes cover app
ID, name, summary, description, publisher, keywords and categories. The parser
reduces input to literal Unicode alphanumeric tokens, quotes every term and adds
prefix matching; all terms must match. User FTS syntax/SQL is never interpolated.
Empty/only-punctuation queries behave as ordinary listings, with selected sort.

Ranking is deterministic: exact app ID, exact name, name prefix, then weighted
FTS bm25 (ID=12, name=10, summary=6, keywords/categories=4, publisher=3,
description=1), canonical app ID as tie breaker. No popularity, install counts,
tracking or machine-learning rank is fabricated. Offset pagination is stable for
a fixed catalog; concurrent publications can change subsequent page boundaries.

## Cache, configuration and readiness

Successful public GETs use SHA-256 ETag, If-None-Match (including weak/list values)
and `Cache-Control: public,max-age=30,must-revalidate`. They intentionally permit
public read-only CORS (`*`), with no credentials; authenticated routes do not inherit
this policy or public caching. ETags avoid transfer, but M4 still queries/serializes
before computing them. Last-Modified and revision-based pre-query ETags are deferred.

Typed API configuration validates LIBREHUB_API_PUBLIC_URL (default local API origin)
and LIBREHUB_CATALOG_PAGE_SIZE before listening. Installation URLs use this trusted
configuration plus existing RepositoryConfig, never request Host. `/ready` includes
catalog database/search and running catalog worker and refuses full readiness when
indexing is unavailable. Metadata work has a 300-second overall deadline, 60-second
subprocess deadline and bounded output. Concurrency is deliberately one in M4.
