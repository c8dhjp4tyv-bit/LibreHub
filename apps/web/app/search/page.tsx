export const dynamic = "force-dynamic";
import type { Metadata } from "next";
import { getCatalog, listPath, type Page, type Card } from "../../lib/catalog";
import { Grid, Pagination, SearchForm } from "../../components/store";
export const metadata: Metadata = {
  title: "Explore applications",
  robots: { index: false, follow: true },
};
export default async function Search({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = await searchParams;
  const params: Record<string, string> = {};
  for (const k of [
    "q",
    "category",
    "architecture",
    "sort",
    "channel",
    "offset",
  ])
    if (typeof raw[k] === "string") params[k] = raw[k];
  const page = await getCatalog<Page<Card>>(listPath(params, true));
  if (!page) throw new Error("Catalog unavailable");
  return (
    <>
      <div className="page-heading">
        <span className="eyebrow">DISCOVER</span>
        <h1>Explore applications</h1>
        <p>
          {params.channel === "beta"
            ? "Beta releases are previews, shown separately from stable applications."
            : "Find software by name, purpose, publisher, or category."}
        </p>
      </div>
      <SearchForm {...params} />
      <Grid page={page} />
      <Pagination page={page} pathname="/search" params={params} />
    </>
  );
}
