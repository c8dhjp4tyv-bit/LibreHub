# M5 Verification: Trust, Security & Moderation

Milestone 5 adds the first serious trust, security, and moderation layer to LibreHub. Passing unit tests alone does not satisfy acceptance.

The verification harness enforces the full chain:
```text
Developer publishes release
        ↓
Signed publication committed
        ↓
Security job queued
        ↓
Permissions extracted from real metadata
        ↓
Previous stable release compared (PermissionDiff)
        ↓
SPDX 2.3 JSON SBOM generated & cryptographically hashed
        ↓
Vulnerabilities evaluated against components
        ↓
Publisher domain ownership verified (DNS TXT challenge)
        ↓
Catalog trust state computed
        ↓
Moderation state & visibility controls applied
        ↓
Web store displays trust badge, permission diffs & security details
```

---

## 1. Test Architecture & Coverage

The M5 verification strategy operates across four complementary tiers:

### 1. Domain & Library Unit Tests (`librehub-common`, `librehub-security`)
- **Domain state machines**: Valid transitions, severity ordering, and serde round-trips for `TrustState`, `ModerationState`, `PermissionSeverity`, and `ReportStatus`.
- **Permission parsing & diffing**: Robust extraction from Flatpak INI `[Context]` and manifest `finish-args`; neutral change classification (`none`, `low`, `moderate`, `significant`).
- **SPDX 2.3 SBOM generator**: Document generation tied cryptographically to publication ID, ref, commit hash, and OSTree checksum; bounded artifact writer.
- **Publisher domain verification**: Strict RFC 1035 / RFC 1123 domain syntax validation, bounded DNS packet generation/parsing, and 256-bit token verification.
- **Vulnerability matching**: OSV-compatible component lookup and deterministic fixture fallback with graceful outage handling (`analysis unavailable`).

### 2. Rust In-Process Integration Tests (`services/api/tests/trust_security.rs`)
Runs deterministic integration tests covering all subsystems against real SQLite instances and Axum HTTP routes:
1. `test_domain_syntax_validation`: Rejects invalid TLDs, IP addresses, traversal, credentials, and non-ASCII characters.
2. `test_publisher_domain_verification_lifecycle`: Full cycle of challenge creation, token verification, re-verification protection, and revocation.
3. `test_permission_extraction_and_diffing`: Accurately detects newly added network, filesystem (`home`), and session bus access between sequential releases.
4. `test_spdx_sbom_generation_and_storage`: Generates and writes canonical SPDX 2.3 JSON, hashes with SHA-256, and verifies bounded retrieval.
5. `test_vulnerability_matching_and_outage_handling`: Matches known vulnerable components; transitions gracefully to `analysis unavailable` during upstream feed outage.
6. `test_moderation_actions_and_catalog_gating`: Verifies `normal`, `flagged`, `restricted` (hidden from browse/search, visible on direct URL), and `removed` (returns 404).
7. `test_user_reports_lifecycle`: Submits abuse report, lists open reports, and resolves with operator note and audit event.
8. `test_security_http_routes`: End-to-end HTTP validation through Axum router of all public, developer, and admin endpoints.

### 3. Store Frontend Unit & Integration Tests (`apps/web/tests/`)
- `apps/web/tests/store.test.tsx`: Validates rendering of `TrustBadge` (`Verified Publisher`, `Community`, `Unverified`, `Restricted`, `Removed`), `PermissionDiffNotice` (moderate/significant alerts), `SecurityDetailsSection` (vulnerabilities and SPDX SBOM download), and `ReportForm` modal.
- `apps/web/tests/pages.test.tsx`: Validates server page integration consuming catalog DTOs.
- `npm run typecheck` & `npm run build`: Enforces full TypeScript type safety and production Next.js compilation.

### 4. End-to-End Acceptance Script (`scripts/test-trust-security.py`)
Executes against live containerized services (flat-manager, PostgreSQL, and OSTree repository):
- Publishes initial v1.0.0 and subsequent v1.1.0 with widened permissions.
- Verifies background `security_worker` processes jobs and writes SPDX SBOM.
- Checks permission diff computation on latest release.
- Submits and verifies DNS TXT verification challenge.
- Confirms catalog moderation transitions (`flag`, `restrict`, `remove`, `restore`).

---

## 2. Review Gates & Security Guarantees

When evaluating pull requests for M5, verify that:
1. **Clear Trust Boundaries**: Identity verification proves domain/source control, *not* malware-free status. The web store and documentation clearly display: "Verification confirms domain control, not application safety."
2. **Fail-Safe Vulnerability Matching**: If the vulnerability database or upstream API is unreachable, the release security state transitions to `analysis temporarily unavailable`. It is never falsely classified as safe.
3. **No Silent Permission Escalation**: When an application introduces broader permissions (e.g. `filesystem=home`, `share=network`), the release notes and web UI prominently display a permission difference alert.
4. **Reports as Signals**: An accumulation of user reports can never autonomously delist or remove an application without explicit operator evaluation.
5. **No History Deletion**: Removing an application delists it from the public catalog and store, but preserves the cryptographic build records and signed OSTree history for forensic auditing.
6. **DNS Safety**: DNS queries use bounded UDP packet sizes (512 bytes), bounded lookup timeouts, and strict label parsing to prevent DNS rebinding or amplification.

---

## 3. Deliberate Limits & Out-of-Scope Items

In accordance with M5 design criteria, the following features are intentionally out of scope:
- User star ratings, written reviews, comments, and follower feeds.
- Arbitrary machine-learning malware heuristics or proprietary scoring algorithms.
- Payment processing, subscription billing, and enterprise organizations.
- Non-Flatpak packaging formats (Snap, AppImage, Debian, RPM).
- Full legal/compliance ticketing workflows.
