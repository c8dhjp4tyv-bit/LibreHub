import Link from "next/link";
import { RunTable } from "../../../../../components/dashboard";
import { devFetch, uuid, type Run } from "../../../../../lib/developer";

const LIMIT = 25;
export default async function Runs({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ offset?: string }>;
}) {
  const project = uuid((await params).id);
  const offset = Math.min(Math.max(Number.parseInt((await searchParams).offset ?? "0", 10) || 0, 0), 1_000_000);
  const runs = await devFetch<Run[]>(`/api/v1/projects/${project}/runs?limit=${LIMIT}&offset=${offset}`);
  return (
    <section>
      <h1>Run history</h1>
      <RunTable runs={runs} project={project} />
      <p className="row">
        {offset > 0 ? <Link href={`?offset=${Math.max(offset - LIMIT, 0)}`}>← Newer</Link> : null}
        {runs.length === LIMIT ? <Link href={`?offset=${offset + LIMIT}`}>Older →</Link> : null}
      </p>
    </section>
  );
}
