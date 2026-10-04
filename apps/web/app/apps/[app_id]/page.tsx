export const dynamic = "force-dynamic";
import type { Metadata } from "next";
import Link from "next/link";
import Image from "next/image";
import { notFound } from "next/navigation";
import {
  getCatalog,
  type App,
  type Page,
  type Release,
  date,
  commitLink,
} from "../../../lib/catalog";
import {
  Icon,
  PermissionList,
  ReleaseHistory,
  Pagination,
} from "../../../components/store";
type Props = {
  params: Promise<{ app_id: string }>;
  searchParams: Promise<{ channel?: string; offset?: string }>;
};
async function application(p: Props) {
  const { app_id } = await p.params;
  const { channel } = await p.searchParams;
  return getCatalog<App>(
    `/api/v1/catalog/apps/${encodeURIComponent(app_id)}${channel === "beta" ? "?channel=beta" : ""}`,
  );
}
export async function generateMetadata(p: Props): Promise<Metadata> {
  const app = await application(p);
  if (!app) return { title: "Application not found" };
  const canonical = `/apps/${encodeURIComponent(app.app_id)}${app.channel === "beta" ? "?channel=beta" : ""}`;
  return {
    title: app.name,
    description: app.summary,
    alternates: { canonical },
    openGraph: {
      title: app.name,
      description: app.summary,
      url: canonical,
      type: "website",
    },
  };
}
export default async function AppPage(props: Props) {
  const app = await application(props);
  if (!app) notFound();
  const { offset } = await props.searchParams;
  const history = await getCatalog<Page<Release>>(
    `/api/v1/catalog/apps/${encodeURIComponent(app.app_id)}/releases?channel=${app.channel}&offset=${encodeURIComponent(offset || "0")}`,
  );
  if (!history) throw new Error("Release history unavailable");
  const release =
    app.channel === "stable"
      ? app.current_stable_release
      : app.current_beta_release;
  if (!release) notFound();
  const commit = commitLink(release.source_url, release.source_commit);
  return (
    <>
      <Link className="back" href="/search">
        ← Explore applications
      </Link>
      <section className="app-heading">
        <Icon app={app} />
        <div>
          <div className="badges">
            <span className="badge">
              {app.channel === "stable" ? "Stable" : "Beta preview"}
            </span>
            {app.archived && <span className="badge">Archived / inactive</span>}
          </div>
          <h1>{app.name}</h1>
          <p>{app.summary || app.app_id}</p>
          <p className="byline">
            By{" "}
            {app.publisher.id ? (
              <Link href={`/publishers/${app.publisher.id}`}>
                {app.publisher.display_name}
              </Link>
            ) : (
              app.publisher.display_name
            )}
          </p>
        </div>
        <a
          className="install-button"
          href={app.install.flatpakref_url}
          download
        >
          Install with Flatpak <span aria-hidden="true">↓</span>
        </a>
      </section>
      {app.channel === "beta" && (
        <p className="notice">
          This is a beta preview.{" "}
          {app.current_stable_release && (
            <Link href={`/apps/${app.app_id}`}>View stable release →</Link>
          )}
        </p>
      )}
      {app.channel === "stable" && app.current_beta_release && (
        <p className="notice">
          A beta preview is also available.{" "}
          <Link href={`/apps/${app.app_id}?channel=beta`}>View beta →</Link>
        </p>
      )}
      {app.archived && (
        <p className="notice">
          This project or publisher is inactive. Existing signed releases remain
          installable.
        </p>
      )}
      <div className="detail-grid">
        <div>
          <section className="screenshots" aria-label="Application screenshots">
            {app.screenshots.map((s, i) => (
              <figure key={s.url}>
                <Image
                  src={s.url}
                  alt={s.caption || `${app.name} screenshot ${i + 1}`}
                  width={960}
                  height={600}
                  unoptimized
                  loading="lazy"
                  referrerPolicy="no-referrer"
                />
                <figcaption>{s.caption}</figcaption>
              </figure>
            ))}
          </section>
          <section>
            <h2>About this app</h2>
            <p className="description">
              {app.description ||
                "The publisher has not supplied an AppStream description."}
            </p>
            <div className="badges">
              {app.categories.map((c) => (
                <Link className="badge" key={c} href={`/categories/${c}`}>
                  {c}
                </Link>
              ))}
            </div>
          </section>
          <section id="install">
            <span className="eyebrow">STANDARD LINUX INSTALLATION</span>
            <h2>Make it yours</h2>
            <p>
              The Install button downloads a Flatpak reference to the signed
              LibreHub repository. Open it with a compatible desktop software
              manager, or use the terminal.
            </p>
            <h3>1. Add the repository</h3>
            <pre>
              <code>{`flatpak remote-add --user --if-not-exists ${app.install.remote} ${app.install.remote_descriptor_url}`}</code>
            </pre>
            <h3>2. Install the application</h3>
            <pre>
              <code>{app.install.command}</code>
            </pre>
            <p className="muted">
              Available for {app.architectures.join(", ")}. Your normal Flatpak
              client verifies the repository signing key.
            </p>
          </section>
          <section>
            <h2>Application permissions</h2>
            {app.current_releases.map((r) => (
              <details
                key={r.publication_id}
                open={r.architecture === release.architecture}
              >
                <summary>
                  {r.architecture} · {r.version}
                </summary>
                <PermissionList permissions={r.permissions} />
              </details>
            ))}
          </section>
          <section>
            <h2>Release history</h2>
            <ReleaseHistory page={history} />
            <Pagination
              page={history}
              pathname={`/apps/${app.app_id}`}
              params={{ channel: app.channel }}
            />
          </section>
        </div>
        <aside className="provenance">
          <span className="eyebrow">OPEN BY DESIGN</span>
          <h2>Trace this release</h2>
          <dl>
            <dt>Source</dt>
            <dd>
              {release.source_url ? (
                <a href={release.source_url} rel="noopener noreferrer">
                  Source repository ↗
                </a>
              ) : (
                "Public source link unavailable"
              )}
            </dd>
            <dt>Build commit</dt>
            <dd>
              {release.source_commit ? (
                commit ? (
                  <a href={commit} rel="noopener noreferrer">
                    <code>{release.source_commit.slice(0, 12)} ↗</code>
                  </a>
                ) : (
                  <code>{release.source_commit}</code>
                )
              ) : (
                "No Git provenance (manifest build)"
              )}
            </dd>
            <dt>Publisher</dt>
            <dd>{app.publisher.display_name}</dd>
            <dt>License</dt>
            <dd>{app.license || "Not declared"}</dd>
            <dt>Version</dt>
            <dd>{release.version}</dd>
            <dt>Updated</dt>
            <dd>{date(app.updated_at)}</dd>
            <dt>Architectures</dt>
            <dd>{app.architectures.join(", ")}</dd>
            <dt>Application ID</dt>
            <dd>
              <code>{app.app_id}</code>
            </dd>
            {app.project_id && (
              <>
                <dt>Project ID</dt>
                <dd>
                  <code>{app.project_id}</code>
                </dd>
              </>
            )}
            {app.developer_name && (
              <>
                <dt>Declared developer</dt>
                <dd>{app.developer_name}</dd>
              </>
            )}
          </dl>
          {app.homepage && (
            <a href={app.homepage} rel="noopener noreferrer">
              Project homepage ↗
            </a>
          )}
          <p className="muted">
            Source provenance identifies the build input. It does not imply
            publisher verification or a security audit.
          </p>
        </aside>
      </div>
    </>
  );
}
