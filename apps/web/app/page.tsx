export const dynamic = "force-dynamic";
import Link from "next/link";
import {
  getCatalog,
  type Page,
  type Card,
  type Category,
} from "../lib/catalog";
import { Grid, SearchForm } from "../components/store";
export default async function Home() {
  const [updated, published, categories] = await Promise.all([
    getCatalog<Page<Card>>(
      "/api/v1/catalog/apps?limit=6&sort=recently_updated",
    ),
    getCatalog<Page<Card>>(
      "/api/v1/catalog/apps?limit=6&sort=recently_published",
    ),
    getCatalog<Category[]>("/api/v1/catalog/categories"),
  ]);
  if (!updated || !published || !categories)
    throw new Error("Catalog unavailable");
  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">THE OPEN APPLICATION STORE</span>
          <h1>
            A home for software
            <br />
            <em>you can see through.</em>
          </h1>
          <p>
            Discover apps for Linux. Know the publisher, inspect the source, and
            install through a signed Flatpak repository.
          </p>
          <div className="hero-facts">
            <span>↗ Public source</span>
            <span>◇ Signed releases</span>
            <span>⌘ Standard Flatpak</span>
          </div>
        </div>
        <aside className="source-card">
          <span className="eyebrow">FROM SOURCE TO YOUR DESKTOP</span>
          <h2>
            Nothing behind
            <br />
            the curtain.
          </h2>
          <ol>
            <li>Explore an application</li>
            <li>Inspect its source & permissions</li>
            <li>Install with Flatpak</li>
          </ol>
          <Link href="/search">Explore the catalog →</Link>
        </aside>
      </section>
      <SearchForm />
      <section>
        <div className="section-heading">
          <div>
            <span className="eyebrow">THE LATEST</span>
            <h2>Recently updated</h2>
          </div>
          <Link href="/search?sort=recently_updated">View all →</Link>
        </div>
        <Grid page={updated} />
      </section>
      <section>
        <div className="section-heading">
          <div>
            <span className="eyebrow">FRESH ARRIVALS</span>
            <h2>New on LibreHub</h2>
          </div>
          <Link href="/search?sort=recently_published">View all →</Link>
        </div>
        <Grid page={published} />
      </section>
      <section>
        <div className="section-heading">
          <h2>Find your next tool</h2>
          <Link href="/categories">All categories →</Link>
        </div>
        <div className="category-grid">
          {categories.map((c) => (
            <Link key={c.id} href={`/categories/${c.id}`}>
              <span>{c.id}</span>
              <span>
                {c.count} {c.count === 1 ? "app" : "apps"} ↗
              </span>
            </Link>
          ))}
        </div>
        {!categories.length && (
          <p className="muted">
            Categories appear when applications are published.
          </p>
        )}
      </section>
    </>
  );
}
