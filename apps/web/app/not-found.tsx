import Link from "next/link";
export default function Missing() {
  return (
    <div className="empty">
      <span className="eyebrow">404</span>
      <h1>Application not found</h1>
      <p>This page may not have a published release in the selected channel.</p>
      <Link href="/search">Explore the catalog →</Link>
    </div>
  );
}
