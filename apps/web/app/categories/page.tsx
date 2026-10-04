export const dynamic = "force-dynamic";
import Link from "next/link";
import { getCatalog, type Category } from "../../lib/catalog";
export const metadata = {
  title: "Categories",
  alternates: { canonical: "/categories" },
};
export default async function Categories() {
  const categories = await getCatalog<Category[]>("/api/v1/catalog/categories");
  if (!categories) throw new Error("Catalog unavailable");
  return (
    <>
      <div className="page-heading">
        <span className="eyebrow">MAKE IT YOURS</span>
        <h1>Browse categories</h1>
        <p>Tools for work, play, and everything in between.</p>
      </div>
      <div className="category-grid">
        {categories.map((c) => (
          <Link key={c.id} href={`/categories/${c.id}`}>
            <h2>{c.id}</h2>
            <span>{c.count} applications ↗</span>
          </Link>
        ))}
      </div>
      {!categories.length && (
        <div className="empty">
          <h2>No categories yet</h2>
          <p>
            Publish a stable application with AppStream categories to start the
            catalog.
          </p>
        </div>
      )}
    </>
  );
}
