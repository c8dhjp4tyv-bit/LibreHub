import Link from "next/link";
import {
  RUN_STATUS_TEXT,
  STATUS_SYMBOL,
  STATUS_TEXT,
  pipelineRows,
  runTone,
} from "../lib/pipeline";
import type { Approval, Automation, Run } from "../lib/developer";

export function StatusBadge({ status }: { status: string }) {
  const text = RUN_STATUS_TEXT[status] ?? status.replace(/_/g, " ");
  return (
    <span className={`badge tone-${runTone(status)}`} data-status={status}>
      {text}
    </span>
  );
}

/**
 * Each row states its status in words (not only colour or symbol) so the pipeline is
 * readable with a screen reader and in forced-colour modes.
 */
export function Pipeline({ run }: { run: Run }) {
  const rows = pipelineRows(run);
  return (
    <ol className="pipeline" aria-label="Release pipeline">
      {rows.map((row) => (
        <li key={row.key} className={`pipe-row pipe-${row.status}`} data-step={row.key} data-status={row.status}>
          <span className="pipe-symbol" aria-hidden="true">
            {STATUS_SYMBOL[row.status]}
          </span>
          <span className="pipe-label">
            {row.label}
            {row.detail ? <small> · {row.detail}</small> : null}
          </span>
          <span className="pipe-status">
            <span className="visually-hidden">Status: </span>
            {STATUS_TEXT[row.status]}
            {row.attempts > 0 ? ` · ${row.attempts} retr${row.attempts === 1 ? "y" : "ies"}` : ""}
          </span>
          {row.error ? (
            <span className="pipe-error" role="note">
              {row.error}
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

export function Time({ value }: { value: string | null | undefined }) {
  if (!value) return <>—</>;
  return <time dateTime={value}>{value.replace("T", " ").replace(/\.\d+Z?$/, "Z").replace(/\+00:00$/, "Z")}</time>;
}

export function RunTable({ runs, project }: { runs: Run[]; project: string }) {
  if (runs.length === 0) return <p className="muted">No runs yet.</p>;
  return (
    <table className="data-table">
      <caption className="visually-hidden">Automation runs, newest first</caption>
      <thead>
        <tr>
          <th scope="col">Run</th>
          <th scope="col">Status</th>
          <th scope="col">Trigger</th>
          <th scope="col">Commit</th>
          <th scope="col">Started</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((run) => (
          <tr key={run.id}>
            <td>
              <Link href={`/dashboard/projects/${project}/runs/${run.id}`}>{run.id.slice(0, 8)}</Link>
            </td>
            <td>
              <StatusBadge status={run.status} />
            </td>
            <td>{run.trigger}</td>
            <td>
              <code>{run.source_commit ? run.source_commit.slice(0, 12) : "—"}</code>
            </td>
            <td>
              <Time value={run.created_at} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RunFacts({ run }: { run: Run }) {
  const facts: [string, React.ReactNode][] = [
    ["Trigger", run.trigger],
    ["Workflow version", `v${run.definition_version}`],
    ["Source ref", run.source_ref ?? "—"],
    ["Source commit", <code key="c">{run.source_commit ?? "—"}</code>],
    ["Build", run.build_id ? <code key="b">{run.build_id}</code> : "—"],
    ["Beta publication", run.beta_publication_id ? <code key="p">{run.beta_publication_id}</code> : "—"],
    ["Stable publication", run.stable_publication_id ? <code key="s">{run.stable_publication_id}</code> : "—"],
    ["Started", <Time key="st" value={run.started_at ?? run.created_at} />],
    ["Finished", <Time key="f" value={run.finished_at} />],
    ["Chain depth", String(run.chain_depth)],
  ];
  return (
    <dl className="facts">
      {facts.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function FailureNotice({ run }: { run: Run }) {
  if (!run.error) return null;
  return (
    <p className="alert" role="alert">
      <strong>{run.status === "cancelled" ? "Cancelled" : "Failed"}:</strong> {run.error.message}{" "}
      <code>{run.error.code}</code>
    </p>
  );
}

export function AutomationCard({ automation, project }: { automation: Automation; project: string }) {
  return (
    <article className="card-lite">
      <h3>
        <Link href={`/dashboard/projects/${project}/automations/${automation.id}`}>{automation.name}</Link>
      </h3>
      <p className="muted">
        Version {automation.current_version} · {automation.enabled ? "enabled" : "disabled"} · triggers:{" "}
        {automation.spec.triggers.map((t) => t.type).join(", ")}
      </p>
    </article>
  );
}

export function ApprovalSummary({ approval }: { approval: Approval }) {
  return (
    <dl className="facts">
      <div>
        <dt>Application</dt>
        <dd>{approval.candidate.app_id}</dd>
      </div>
      <div>
        <dt>Source commit</dt>
        <dd>
          <code>{approval.candidate.source_commit}</code>
        </dd>
      </div>
      <div>
        <dt>Build</dt>
        <dd>
          <code>{approval.candidate.build_id}</code>
        </dd>
      </div>
      <div>
        <dt>Source snapshot</dt>
        <dd>
          <code>{approval.candidate.snapshot_sha256}</code>
        </dd>
      </div>
      <div>
        <dt>Target channel</dt>
        <dd>{approval.candidate.target_channel}</dd>
      </div>
      <div>
        <dt>Requested by</dt>
        <dd>{approval.requested_by}</dd>
      </div>
      <div>
        <dt>Expires</dt>
        <dd>
          <Time value={approval.expires_at} />
        </dd>
      </div>
    </dl>
  );
}
