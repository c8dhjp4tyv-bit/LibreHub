import Link from "next/link";
import Image from "next/image";
import {
  publicApiBase,
  type Card,
  type Page,
  type Permissions,
  type PermissionDiff,
  type Release,
  type TrustSummary,
  date,
  commitLink,
} from "../lib/catalog";
export function Icon({ app }: { app: Card }) {
  return (
    <span className="app-icon" aria-hidden="true">
      {app.icon?.startsWith("/api/v1/catalog/") ? (
        <Image
          src={`${publicApiBase}${app.icon}`}
          alt=""
          width={56}
          height={56}
          unoptimized
        />
      ) : (
        app.name.slice(0, 2).toUpperCase()
      )}
    </span>
  );
}
export function AppCard({ app }: { app: Card }) {
  // App-specific image CSP requires a fresh document, not client router navigation.
  return (
    <a
      className="app-card"
      href={`/apps/${encodeURIComponent(app.app_id)}${app.channel === "beta" ? "?channel=beta" : ""}`}
    >
      <Icon app={app} />
      <div>
        <h3>{app.name}</h3>
        <p>{app.summary || app.app_id}</p>
        <span className="byline">{app.publisher.display_name}</span>
      </div>
      <span className="card-arrow" aria-hidden="true">
        ↗
      </span>
      {app.trust && <TrustBadge trust={app.trust} />}
      {app.archived && <span className="badge">Archived</span>}
      {app.channel === "beta" && <span className="badge">Beta</span>}
    </a>
  );
}
export function Grid({ page }: { page: Page<Card> }) {
  return page.items.length ? (
    <div className="app-grid">
      {page.items.map((a) => (
        <AppCard key={`${a.app_id}/${a.channel}`} app={a} />
      ))}
    </div>
  ) : (
    <div className="empty">
      <h2>No applications here yet</h2>
      <p>
        Try another query or category. Applications appear after a successful
        signed publication is indexed.
      </p>
    </div>
  );
}
export function Pagination({
  page,
  pathname,
  params,
}: {
  page: Page<unknown>;
  pathname: string;
  params: Record<string, string>;
}) {
  const href = (offset: number) => {
    const q = new URLSearchParams({ ...params, offset: String(offset) });
    return `${pathname}?${q}`;
  };
  return (
    <nav className="pagination" aria-label="Pagination">
      {page.offset > 0 && (
        <Link href={href(Math.max(0, page.offset - page.limit))}>
          ← Previous
        </Link>
      )}
      <span>
        {page.total === 0
          ? "0 results"
          : `${page.offset + 1}–${Math.min(page.total, page.offset + page.limit)} of ${page.total}`}
      </span>
      {page.offset + page.limit < page.total && (
        <Link href={href(page.offset + page.limit)}>Next →</Link>
      )}
    </nav>
  );
}
export function SearchForm({
  q = "",
  category = "",
  architecture = "",
  sort = "recently_updated",
  channel = "stable",
}: {
  q?: string;
  category?: string;
  architecture?: string;
  sort?: string;
  channel?: string;
}) {
  return (
    <form action="/search" className="search-form">
      <div className="search-input">
        <label htmlFor="q" className="sr-only">
          Search applications
        </label>
        <input
          id="q"
          name="q"
          defaultValue={q}
          placeholder="Search apps, publishers, or ideas…"
          maxLength={200}
        />
        <button type="submit">
          Search <span aria-hidden="true">↗</span>
        </button>
      </div>
      <div className="filters">
        <label>
          Category
          <select name="category" defaultValue={category}>
            <option value="">All categories</option>
            {[
              "Development",
              "Games",
              "Graphics",
              "AudioVideo",
              "Education",
              "Network",
              "Office",
              "Science",
              "System",
              "Utility",
            ].map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
        <label>
          Architecture
          <select name="architecture" defaultValue={architecture}>
            <option value="">All architectures</option>
            <option>x86_64</option>
            <option>aarch64</option>
          </select>
        </label>
        <label>
          Sort
          <select name="sort" defaultValue={sort}>
            <option value="recently_updated">Recently updated</option>
            <option value="recently_published">Recently published</option>
            <option value="name">Name</option>
          </select>
        </label>
        <label>
          Channel
          <select name="channel" defaultValue={channel}>
            <option value="stable">Stable</option>
            <option value="beta">Beta (preview)</option>
          </select>
        </label>
      </div>
    </form>
  );
}
export function PermissionList({
  permissions: p,
}: {
  permissions: Permissions;
}) {
  const rows: [string, string[]][] = [
    ["Filesystem access", p.filesystem],
    ["Devices", p.devices],
    ["Display and other sockets", p.sockets],
    ["D-Bus names", p.dbus],
    ["Shared resources", p.shared.filter((s) => s !== "network")],
    ["Other technical permissions", p.other],
  ];
  return (
    <div className="permissions">
      <p>{p.network ? "Network access" : "No network access declared"}</p>
      {rows
        .filter(([, v]) => v.length)
        .map(([name, values]) => (
          <div key={name}>
            <h4>{name}</h4>
            <ul>
              {values.map((v) => (
                <li key={v}>
                  <code>{v}</code>
                </li>
              ))}
            </ul>
          </div>
        ))}
      <p className="muted">
        These are the permissions declared in the signed published Flatpak. They
        describe access, rather than a safety rating.
      </p>
    </div>
  );
}
export function ReleaseHistory({ page }: { page: Page<Release> }) {
  return (
    <div className="release-list">
      {page.items.map((r) => {
        const url = commitLink(r.source_url, r.source_commit);
        return (
          <article key={r.publication_id}>
            <div>
              <strong>{r.version}</strong>
              <span className="badge">{r.channel}</span>
              <span className="muted">
                {date(r.published_at)} · {r.architecture}
              </span>
            </div>
            {r.source_commit &&
              (url ? (
                <a href={url} rel="noopener noreferrer">
                  Commit {r.source_commit.slice(0, 12)}
                </a>
              ) : (
                <code>Commit {r.source_commit.slice(0, 12)}</code>
              ))}
            <details>
              <summary>Publication details</summary>
              <p>
                Flatpak ref: <code>{r.flatpak_ref}</code>
              </p>
              <p>
                OSTree checksum: <code>{r.ostree_checksum}</code>
              </p>
              <p>
                Publication: <code>{r.publication_id}</code>
              </p>
              {r.release_notes && (
                <p className="description">{r.release_notes}</p>
              )}
            </details>
          </article>
        );
      })}
    </div>
  );
}

export function TrustBadge({ trust }: { trust?: TrustSummary }) {
  if (!trust) return null;
  if (trust.moderation_state === "restricted") {
    return <span className="badge badge-restricted">Restricted</span>;
  }
  if (trust.moderation_state === "under_review") {
    return <span className="badge badge-warning">Under Review</span>;
  }
  if (trust.trust_state === "verified_publisher") {
    return (
      <span
        className="badge badge-verified"
        title="Publisher domain ownership is verified. This does not imply an endorsement or guarantee of complete safety."
      >
        ✓ Verified Publisher{trust.verified_domain ? ` (${trust.verified_domain})` : ""}
      </span>
    );
  }
  return <span className="badge">{trust.trust_state === "removed" ? "Removed" : trust.trust_state === "unverified" ? "Unverified Publisher" : "Community"}</span>;
}

export function PermissionDiffNotice({ diff }: { diff?: PermissionDiff | null }) {
  if (!diff || diff.severity === "none") return null;

  return (
    <div className={`permission-diff-banner diff-${diff.severity}`}>
      <div className="diff-header">
        <h4>
          Permission changes in this release{" "}
          <span className={`badge badge-${diff.severity}`}>
            {diff.severity.toUpperCase()} IMPACT
          </span>
        </h4>
        <span className="muted">{date(diff.generated_at)}</span>
      </div>

      {diff.changed_network && (
        <p>
          <strong>Network access:</strong>{" "}
          {diff.changed_network.to ? "Enabled (previously disabled)" : "Disabled (previously enabled)"}
        </p>
      )}

      {diff.added.filesystem.length > 0 && (
        <div>
          <strong>Added filesystem access:</strong>
          <ul>
            {diff.added.filesystem.map((f) => (
              <li key={f}>
                <code>{f}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.added.devices.length > 0 && (
        <div>
          <strong>Added device access:</strong>
          <ul>
            {diff.added.devices.map((d) => (
              <li key={d}>
                <code>{d}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.added.sockets.length > 0 && (
        <div>
          <strong>Added socket access:</strong>
          <ul>
            {diff.added.sockets.map((s) => (
              <li key={s}>
                <code>{s}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.added.dbus.length > 0 && (
        <div>
          <strong>Added D-Bus access:</strong>
          <ul>
            {diff.added.dbus.map((b) => (
              <li key={b}>
                <code>{b}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.removed.filesystem.length > 0 && (
        <div>
          <strong>Removed filesystem access:</strong>
          <ul>
            {diff.removed.filesystem.map((f) => (
              <li key={f}>
                <del><code>{f}</code></del>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.summary_notes && diff.summary_notes.length > 0 && (
        <ul className="diff-notes">
          {diff.summary_notes.map((note, i) => (
            <li key={i}>{note}</li>
          ))}
        </ul>
      )}

      <p className="muted">
        LibreHub tracks permission snapshots across releases so security changes are transparent and auditable.
      </p>
    </div>
  );
}

export function SecurityDetailsSection({
  release,
  trust,
}: {
  release: Release;
  trust?: TrustSummary;
}) {
  const security = release.security;

  return (
    <section className="security-section">
      <h2>Trust & Security Analysis</h2>

      {/* Moderation Warning if applicable */}
      {trust && (trust.moderation_state === "under_review" || trust.moderation_state === "restricted") && (
        <div className={`notice notice-${trust.moderation_state}`}>
          <strong>
            {trust.moderation_state === "restricted"
              ? "Catalog Notice: Restricted Visibility"
              : "Catalog Notice: Under Operator Review"}
          </strong>
          <p>{trust.moderation_notice || "This application is undergoing platform moderation review."}</p>
        </div>
      )}

      {/* Permission Diff */}
      {security?.permission_diff && (
        <PermissionDiffNotice diff={security.permission_diff} />
      )}

      {/* Vulnerability Scanning */}
      <div className="security-card">
        <h3>Vulnerability Assessment</h3>
        {!security || security.vulnerabilities_status === "pending" ? (
          <p className="muted">Security analysis is currently queued or in progress for this release.</p>
        ) : security.vulnerabilities_status === "unavailable" ? (
          <div className="status-unavailable">
            <p><strong>Analysis temporarily unavailable</strong></p>
            <p className="muted">
              Vulnerability feed query could not be completed at this time. This does not indicate the application is verified safe.
            </p>
          </div>
        ) : security.vulnerabilities_status === "clean" ? (
          <div className="status-clean">
            <p><strong>✓ No known vulnerabilities matched in database</strong></p>
            <p className="muted">
              Scanned against the open OSV database at {security.vulnerabilities_checked_at ? date(security.vulnerabilities_checked_at) : "build time"}.
              Absence of known CVEs does not constitute a formal code audit or complete safety guarantee.
            </p>
          </div>
        ) : (
          <div className="status-vulnerable">
            <p>
              <strong>⚠️ {Object.values(security.vulnerability_counts).reduce((total, count) => total + count, 0)} known vulnerability finding(s) detected</strong>
              {security.vulnerability_counts.critical > 0 && (
                <span className="badge badge-critical"> {security.vulnerability_counts.critical} Critical</span>
              )}
              {security.vulnerability_counts.high > 0 && (
                <span className="badge badge-high"> {security.vulnerability_counts.high} High</span>
              )}
            </p>
            <div className="findings-list">
              {security.findings.map((f) => (
                <article key={`${f.vulnerability_id}-${f.component_name}`} className="finding-item">
                  <div className="finding-header">
                    <strong>{f.component_name} @ {f.component_version}</strong>
                    <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
                  </div>
                  <p className="finding-id">
                    {f.reference_url ? (
                      <a href={f.reference_url} target="_blank" rel="noopener noreferrer">
                        {f.vulnerability_id} ↗
                      </a>
                    ) : (
                      <code>{f.vulnerability_id}</code>
                    )}
                  </p>
                  {f.summary && <p className="finding-summary">{f.summary}</p>}
                </article>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* SBOM Artifact */}
      {security && security.sbom_download_url && (
        <div className="security-card sbom-card">
          <h3>Software Bill of Materials (SBOM)</h3>
          <p>
            A standardized <strong>SPDX 2.3 JSON</strong> SBOM was generated from the signed build artifact.
          </p>
          <dl className="sbom-meta">
            <dt>Components inventory</dt>
            <dd>{security.sbom_component_count} package(s)</dd>
            <dt>SHA-256 Digest</dt>
            <dd><code className="checksum">{security.sbom_sha256}</code></dd>
          </dl>
          <a
            className="download-link-button"
            href={`${publicApiBase}${security.sbom_download_url}`}
            download={`sbom-${release.flatpak_ref.replace(/\//g, "-")}.spdx.json`}
          >
            Download SBOM (SPDX 2.3 JSON) ↓
          </a>
        </div>
      )}
    </section>
  );
}

