import Link from "next/link";
import Image from "next/image";
import {
  publicApiBase,
  type Card,
  type Page,
  type Permissions,
  type Release,
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
  return (
    <Link
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
      {app.archived && <span className="badge">Archived</span>}
      {app.channel === "beta" && <span className="badge">Beta</span>}
    </Link>
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
