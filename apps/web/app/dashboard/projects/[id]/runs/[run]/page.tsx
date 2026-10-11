import Link from "next/link";
import { cancelRun } from "../../../../actions";
import { ApprovalForm } from "../../../../../../components/dashboard-forms";
import { ApprovalSummary, FailureNotice, Pipeline, RunFacts, StatusBadge, Time } from "../../../../../../components/dashboard";
import { devFetch, uuid, type Approval, type Run } from "../../../../../../lib/developer";

export default async function RunDetail({ params }: { params: Promise<{ id: string; run: string }> }) {
  const { id, run: runId } = await params;
  const project = uuid(id);
  const run = uuid(runId);
  const [view, events, approvals] = await Promise.all([
    devFetch<Run>(`/api/v1/projects/${project}/automations/runs/${run}`),
    devFetch<{ id: number; at: string; kind: string; detail: Record<string, unknown> }[]>(`/api/v1/projects/${project}/automations/runs/${run}/events`),
    devFetch<Approval[]>(`/api/v1/projects/${project}/approvals?limit=100`),
  ]);
  const mine = approvals.filter((a) => a.run_id === run);
  const active = !["completed", "failed", "cancelled"].includes(view.status);
  return (
    <section>
      <h1>
        Run {view.id.slice(0, 8)} <StatusBadge status={view.status} />
      </h1>
      <FailureNotice run={view} />
      <h2>Pipeline</h2>
      <Pipeline run={view} />
      {active ? (
        <form action={cancelRun}>
          <input type="hidden" name="project" value={project} />
          <input type="hidden" name="run" value={run} />
          <button className="danger">Cancel run</button>
          <p className="muted">
            Cancelling stops future steps. A signed release that was already published is not rolled back.
          </p>
        </form>
      ) : null}
      <h2>Details</h2>
      <RunFacts run={view} />
      {mine.length > 0 ? (
        <>
          <h2>Approvals</h2>
          {mine.map((approval) => (
            <article key={approval.id} className="card-lite">
              <h3>
                Approval <code>{approval.id.slice(0, 8)}</code> — {approval.status}
              </h3>
              <ApprovalSummary approval={approval} />
              {approval.decided_at ? (
                <p>
                  Decided <Time value={approval.decided_at} /> by {approval.decided_by ?? "—"} ({approval.decided_role ?? "—"})
                  {approval.reason ? <> — “{approval.reason}”</> : null}
                </p>
              ) : approval.status === "requested" ? (
                <ApprovalForm approval={approval.id} />
              ) : null}
            </article>
          ))}
        </>
      ) : null}
      <h2>History</h2>
      <ol className="history">
        {[...events].reverse().map((event) => (
          <li key={event.id}>
            <Time value={event.at} /> <strong>{event.kind}</strong> <code>{JSON.stringify(event.detail)}</code>
          </li>
        ))}
      </ol>
      <p>
        <Link href={`/dashboard/projects/${project}/runs`}>← All runs</Link>
      </p>
    </section>
  );
}
