# Software Bill of Materials (SBOM)

LibreHub Milestone 5 generates and persists a canonical Software Bill of Materials for every signed release.

---

## 1. Canonical Standard: SPDX 2.3 JSON

LibreHub generates SBOMs adhering to the **SPDX 2.3 JSON** specification (`SPDX-2.3`).

### Core Provenance Linkage

The root SPDX Package is cryptographically bound to the publication and build artifacts:

- **`SPDXID`**: `SPDXRef-Application`
- **`name`**: Application ID (e.g., `org.librehub.CatalogHello`)
- **`versionInfo`**: Runtime version or application release version
- **`packageFileName`**: Flatpak ref (e.g., `app/org.librehub.CatalogHello/x86_64/stable`)
- **`checksums`**:
  - `SHA256`: OSTree commit checksum
- **`externalRefs`**:
  - Package URL (purl): `pkg:flatpak/org.librehub.CatalogHello@version`
- **`annotations`**:
  - `LibreHub-Publication-Id`: Publication UUID
  - `LibreHub-Build-Commit`: Git commit hash that produced the build

---

## 2. Component Extraction Sources

LibreHub extracts SBOM components from the actual build and published artifacts:

1. **Flatpak Metadata**:
   - Runtime name and branch (e.g., `org.freedesktop.Platform/x86_64/23.08`).
   - SDK name and branch (e.g., `org.freedesktop.Sdk/x86_64/23.08`).
2. **Build Manifest Modules**:
   - All modules declared in the build manifest are recorded with their source URLs, versions, tags, and checksums.
3. **Normalized Component Model**:
   - `name`: Component identifier
   - `version`: Version string (if declared or extractable)
   - `package_type`: Library, runtime, application, or dependency
   - `purl`: Standardized Package URL
   - `license`: Declared license identifier (SPDX format)
   - `hashes`: SHA-256 digests where available
   - `scope`: `direct` vs. `runtime`

---

## 3. Storage Architecture & Safety

- **Storage Path**:
  Full SBOM documents are saved in a partitioned, controlled security directory:
  ```text
  $LIBREHUB_DATA_DIR/security/<publication_id>/sbom.spdx.json
  ```
- **Bounds & Protection**:
  - Publication IDs are strict UUIDs; path traversal is impossible.
  - File reading in the API enforces a strict 10MB upper limit (`bounded_read_to_string`).
  - Summary metadata (component count, SHA-256 digest, generation timestamp) is indexed in SQLite (`release_security` table) for fast catalog querying without reading disk files.

---

## 4. Public SBOM APIs

### Summary Information
```http
GET /api/v1/catalog/apps/:app_id/releases/:release_id/sbom
```
Response:
```json
{
  "publication_id": "pub_01...",
  "format": "SPDX-2.3",
  "component_count": 42,
  "sha256": "3a8c7b...",
  "download_url": "/api/v1/catalog/apps/org.example.App/releases/pub_01.../sbom/download",
  "generated_at": "2026-02-01T12:00:00Z"
}
```

### Full Document Download
```http
GET /api/v1/catalog/apps/:app_id/releases/:release_id/sbom/download
```
Returns `application/spdx+json` with `Content-Disposition: attachment; filename="sbom-...spdx.json"`.

## M6 supply-chain evidence

See [supply-chain policy](supply-chain.md), [attestations and offline verification](attestations.md), [worker isolation](build-isolation.md), [rebuild verification](reproducible-builds.md), and [verification/recovery](m6-verification.md).
Cryptographic provenance is separate from publisher identity, vulnerability analysis,
moderation and application safety. Legacy releases carry no fabricated build evidence.
