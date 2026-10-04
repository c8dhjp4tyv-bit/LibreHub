# Application metadata and permissions

Application metadata is untrusted developer content. Only the bounded catalog
worker parses it. Public HTTP requests read persisted catalog DTOs.

## Standard extraction and version precedence

The worker reuses the M2 artifact verifier/importer: regular controlled bundle,
size/hash validation, Flatpak identity and OSTree fsck. Its source checksum/ref must
match the successful publication's immutable pre-rewrite checksum/ref. It reads
only canonical paths in that built tree:

1. `/files/share/metainfo/<app-id>.metainfo.xml`
2. `/files/share/appdata/<app-id>.appdata.xml`
3. `/files/share/applications/<app-id>.desktop` (fallback)
4. Flatpak app ID fallback when standard presentation metadata is absent.

An existing malformed/oversized AppStream file fails indexing instead of silently
making up metadata. The extracted component ID must match the app ID. Root-level
component/application and components container forms are supported. The default
(unlocalized) name, summary, description, developer_name/developer/name,
project_license, homepage URL, categories, keywords, screenshots, release notes
and content rating are used. Metadata is not copied into project settings.
Localization, remote AppStream caches, arbitrary custom metainfo filenames and
SVG conversion are outside M4. Standard canonical metainfo naming is recommended.

Version: valid nonempty bounded AppStream release display version (newest declared
ISO date order) → explicit `refs/tags/...` source tag → 12-character immutable Git
commit → publication UTC date. No fake semantic version is generated. AppStream
versions need not be semantic. Release-history dates/checksums always come from
actual M2 publications, regardless of a declared AppStream date/version.

## Bounds

| Input | Limit |
| --- | --- |
| AppStream XML | 256 KiB, 4096 element nodes, depth 32, 16 attributes/element |
| XML DTD/custom entities | Forbidden; only predefined/numeric references |
| Desktop/deployed Flatpak metadata | 64 KiB each |
| Name / declared developer / display version | 120 bytes |
| Summary / screenshot caption | 240 bytes |
| Description / release notes | 16 KiB / 4 KiB |
| License | 160 bytes |
| Screenshots | 8 |
| Declared categories / keywords | 32 each; canonical categories capped at 12 |
| Keyword | 64 bytes |
| AppStream release entries | 64 |
| URL | 2048 bytes |
| Icon | 256 KiB PNG, positive IHDR dimensions ≤1024×1024 |
| Structured permissions | 256 entries, bounded values |

Strings truncate on UTF-8 boundaries, remove control bytes and remain text. Unknown
categories are discarded; standard desktop `Game` maps to public `Games`. Multiple
canonical categories are sorted/deduplicated. Unknown content-rating attributes
are bounded technical strings, not a trust/safety score.

## Browser and asset boundary

Descriptions/release notes become plain text with paragraph/list spacing. Script,
style, iframe, object and SVG content is dropped, and attributes never enter the
rendered description. React escapes all text, including encoded HTML. There is no
raw HTML, dangerous innerHTML or Markdown renderer. Malicious inline events cannot
inject DOM.

Metadata links/images require normalized credential-free HTTPS, bounded length,
standard port, no localhost/private/reserved IP literals or local/test/internal
hostnames. Screenshot/homepage/remote-icon DNS is checked by the worker with a
3-second deadline; all returned addresses must be public. URLs that fail checks
are omitted. No backend image fetching, caching or arbitrary proxy is present.
The immutable M3 source repository is normalized by its existing admission
boundary and classified again before public display. GitHub commit links are
constructed only for exact github.com two-component repository paths + 40-hex
commits; other providers still show repository and commit text without guessing
custom templates.

Bundled icons use fixed canonical app-ID PNG paths at 128/64/256 sizes. Developer
Icon filenames/absolute paths are never used as filesystem paths. SVG/HTML icons
are not accepted by the public asset endpoint. PNG bytes are capped and their
signature/IHDR dimensions checked, served image/png with nosniff; this is a format
boundary, not a full image decoder/security audit. Missing icons use an app-name
monogram. HTTPS remote-icon metadata is retained as a fallback API value; the
initial UI uses bundled PNG or monogram to keep listing CSP narrowly scoped.

External screenshots load directly in the user's browser with lazy loading and
no-referrer. The host sees the user's IP and normal browser traffic. DNS can change
after indexing, and remote content/redirects can change; LibreHub neither proxies
nor vouches for remote pixels. Browser private-network protections are independent
of LibreHub's ingestion validation. Use a controlled screenshot host in deployment.
The store generates detail-page img-src from the bounded catalog screenshot origins,
plus self and the trusted configured API asset origin; it does not use img-src *.

## Permissions from the actual signed release

The indexer creates a temporary independent OSTree repository, imports the operator's
public signing key and enables both commit and summary GPG verification. It pulls
only `/metadata` at the **exact published checksum**, then checks the application
identity and parses that deployed file. It does not infer access from finish-args
or a mutable source manifest. Shared resources, network, filesystems (including
access mode), devices, sockets, session/system D-Bus policy and other Context
entries become finite structured fields. Permissions are stored per publication
and architecture. UI uses neutral technical descriptions, never safe/unsafe labels.

AppStream/icon extraction uses the verified immutable built tree tied to M2's
pre-rewrite source checksum; permissions use the actual rewritten signed tree.
M2 changes commit metadata/signing, not application file content. Any future
publisher that changes the application tree must supply a matching extraction
adapter rather than reuse this assumption.
