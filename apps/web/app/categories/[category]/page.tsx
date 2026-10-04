export const dynamic = "force-dynamic";
import { notFound } from "next/navigation";
import {
  getCatalog,
  listPath,
  type Page,
  type Card,
} from "../../../lib/catalog";
import { Grid, Pagination } from "../../../components/store";
const categories = [
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
];
export async function generateMetadata({
  params,
}: {
  params: Promise<{ category: string }>;
}) {
  const { category } = await params;
  return {
    title: categories.includes(category) ? category : "Category not found",
    alternates: { canonical: `/categories/${encodeURIComponent(category)}` },
  };
}
export default async function Category({
  params,
  searchParams,
}: {
  params: Promise<{ category: string }>;
  searchParams: Promise<{ offset?: string }>;
}) {
  const { category } = await params;
  if (!categories.includes(category)) notFound();
  const { offset } = await searchParams;
  const page = await getCatalog<Page<Card>>(listPath({ category, offset }));
  if (!page) notFound();
  return (
    <>
      <div className="page-heading">
        <span className="eyebrow">CATEGORY</span>
        <h1>{category}</h1>
        <p>Stable applications in {category}.</p>
      </div>
      <Grid page={page} />
      <Pagination
        page={page}
        pathname={`/categories/${category}`}
        params={{}}
      />
    </>
  );
}
