# Trust & Verification Architecture

LibreHub Milestone 5 (M5) establishes the foundational trust, verification, and auditability layer for the platform.

```text
source repository
        ↓
immutable build
        ↓
signed publication
        ↓
security analysis queued
        ↓
SBOM generated & permissions extracted
        ↓
permission diff computed against previous release
        ↓
vulnerability feeds queried (OSV)
        ↓
publisher verification & moderation applied
        ↓
transparent public catalog & web store
```

---

## 1. Core Principle: Verification vs. Safety

A critical architectural tenet of LibreHub is that **publisher verification answers identity control, not malware absence**:

```text
Is this publisher identity/domain ownership verified? -> YES / NO
Is this application guaranteed bug-free or malware-free? -> NEVER CLAIMED
```

LibreHub explicitly refrains from claiming software is "100% safe", "virus free", or "guaranteed secure". Security states are descriptive, factual, and derived directly from immutable build and publication artifacts.

---

## 2. Public Trust States

Every catalog application resolves to a deterministic `TrustState`:

| Trust State | Criteria | Meaning to Users |
| :--- | :--- | :--- |
| **`VerifiedPublisher`** | Developer has verified ownership of their domain via DNS TXT challenge, app has normal moderation status. | Publisher identity/domain is confirmed. Does not guarantee flawless code. |
| **`Community`** | Valid signed publication from an unverified domain/publisher, normal moderation status. | Standard community release built and signed through LibreHub. |
| **`Unverified`** | Missing or unassociated publisher account. | Public release without associated publisher identity. |
| **`Restricted`** | Placed under restricted visibility by operator moderation action. | Delisted from search and browse lists. Direct access presents a warning notice. |
| **`Removed`** | Delisted from the catalog due to critical policy violation or malware. | Direct access returns 404; existing installed references remain cryptographically verifiable in OSTree. |

---

## 3. Publisher Verification Foundation

### 3.1 DNS TXT Verification Mechanism

M5 implements automated domain ownership verification through DNS TXT records:

1. **Request Verification**:
   Developer submits target domain (`POST /api/v1/verification/domains`):
   ```json
   {
     "domain": "example.org"
   }
   ```
2. **Challenge Issuance**:
   LibreHub validates domain syntax (rejecting IP addresses, localhost, ports, credentials, and reserved TLDs). It generates a cryptographically secure random token (32 bytes hex, 64 characters) with a 24-hour expiration (`expires_at`).
   ```text
   TXT Record Name:  example.org
   TXT Record Value: librehub-verification=8f4a3c2e1b...
   ```
3. **Verification Check**:
   Developer triggers check (`POST /api/v1/verification/domains/:id/check`).
   LibreHub queries DNS TXT records for the domain using a bounded RFC 1035 UDP resolver.
4. **Result State Transition**:
   - If a TXT record matches `librehub-verification=<token>`, the verification status transitions to `verified`, `verified_at` is timestamped, and an audit event is logged.
   - If not found or expired, remains `pending` or returns an error.
5. **Revocation**:
   Developers can revoke verification (`DELETE /api/v1/verification/domains/:id`). Operators can revoke verifications during moderation.

### 3.2 DNS Security Protections

The DNS resolver implementation (`SystemUdpDnsResolver`):
- Uses bounded buffers (512 bytes for standard RFC 1035 UDP queries) to prevent packet flooding and resource exhaustion.
- Enforces a strict 3-second deadline per lookup attempt.
- Handles truncated (`TC=1`) responses cleanly without infinite loops.
- Normalizes and validates domain labels to prevent injection or malformed requests.
- Does NOT rely on client-supplied `Host` headers.

---

## 4. Permission Diffing & Auditability

Every signed publication automatically extracts the Flatpak `/metadata` file committed to OSTree.

### 4.1 Permission Snapshots

Snapshots capture:
- Network access (`network: bool`)
- Filesystem permissions (e.g., `xdg-download:ro`, `home`, `host`)
- Devices (e.g., `dri`, `all`, `kvm`)
- Sockets (e.g., `wayland`, `x11`, `fallback-x11`, `pulseaudio`, `session-bus`)
- D-Bus names and session bus ownership
- Shared resources and technical arguments

### 4.2 Permission Diff Engine

When a new stable release is published, the security worker retrieves the previous stable release for that application and architecture, generating a structured diff:

```json
{
  "from_publication_id": "pub_01...",
  "to_publication_id": "pub_02...",
  "severity": "significant",
  "network_changed": null,
  "added": {
    "filesystem": ["home"],
    "devices": ["all"],
    "sockets": [],
    "dbus": [],
    "shared": [],
    "other": []
  },
  "removed": {
    "filesystem": [],
    "devices": [],
    "sockets": [],
    "dbus": [],
    "shared": [],
    "other": []
  },
  "notes": [
    "Broad filesystem access added: home",
    "Direct device access added: all"
  ]
}
```

### 4.3 Neutral Severity Heuristics

Changes are categorized neutrally to inform users without sensationalism:
- **`significant`**: Adding broad filesystem access (`home`, `host`, `/`), direct device access (`all`), enabling network access when previously disabled, or acquiring system bus ownership.
- **`moderate`**: Adding specific subdirectories, display sockets (`x11`), sound devices, or session D-Bus interfaces.
- **`low`**: Narrow technical flags or non-sensitive modifications.
- **`none`**: No permission changes between releases.

A new release cannot silently broaden permissions without being recorded and exposed on the public store page.
