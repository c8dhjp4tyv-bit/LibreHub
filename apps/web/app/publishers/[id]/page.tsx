export const dynamic = "force-dynamic";
import { notFound } from "next/navigation";
import {
  getCatalog,
  type Publisher,
  type Page,
  type Card,
} from "../../../lib/catalog";
import { Grid, Pagination } from "../../../components/store";
export default async function PublisherPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ offset?: string }>;
}) {
  const { id } = await params;
  const { offset } = await searchParams;
  const data = await getCatalog<{ publisher: Publisher; apps: Page<Card> }>(
    `/api/v1/catalog/publishers/${encodeURIComponent(id)}?offset=${encodeURIComponent(offset || "0")}`,
  );
  if (!data) notFound();
  return (
    <>
      <div className="page-heading">
        <span className="eyebrow">PUBLISHER</span>
        <h1>{data.publisher.display_name}</h1>
        <p>
          Public stable applications. Publisher identity is a platform account,
          without a verification badge.
        </p>
      </div>
      <Grid page={data.apps} />
      <section>
        <h2>Projects & sources</h2>
        <ul>
          {data.apps.items.map((app) => (
            <li key={app.app_id}>
              {app.source_url ? (
                <a href={app.source_url} rel="noopener noreferrer">
                  {app.name} · Source repository
                </a>
              ) : (
                app.name
              )}
              {app.project_id && (
                <span className="muted"> · Project {app.project_id}</span>
              )}
            </li>
          ))}
        </ul>
      </section>
      <Pagination page={data.apps} pathname={`/publishers/${id}`} params={{}} />
    </>
  );
}
