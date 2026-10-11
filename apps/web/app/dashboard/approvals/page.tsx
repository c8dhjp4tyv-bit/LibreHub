import Link from "next/link";
import { ApprovalForm } from "../../../components/dashboard-forms";
import { ApprovalSummary } from "../../../components/dashboard";
import { devFetch, type Approval } from "../../../lib/developer";

export default async function Approvals() {
  const pending = await devFetch<Approval[]>("/api/v1/approvals?status=requested&limit=50");
  return (
    <section>
      <h1>Release approvals</h1>
      <p className="muted">
        Approvals bind to one exact build, source commit and source snapshot and can be used once. They are enforced by the
        server, not by this page.
      </p>
      {pending.length === 0 ? <p>No releases are waiting for approval.</p> : null}
      {pending.map((approval) => (
        <article key={approval.id} className="card-lite">
          <h2>
            {approval.candidate.app_id}{" "}
            <Link href={`/dashboard/projects/${approval.project_id}/runs/${approval.run_id}`}>run {approval.run_id.slice(0, 8)}</Link>
          </h2>
          <ApprovalSummary approval={approval} />
          <ApprovalForm approval={approval.id} />
        </article>
      ))}
    </section>
  );
}
