import type { Run, RunStep, StepStatus } from "./developer";

export interface PipelineRow {
  key: string;
  label: string;
  status: StepStatus | "resolved";
  detail: string | null;
  attempts: number;
  error: string | null;
}

/** Friendly names for the supported step kinds. */
export const STEP_LABELS: Record<string, string> = {
  "librehub/build": "Build completed",
  "librehub/verify-provenance": "Provenance verified",
  "librehub/publish": "Published to beta",
  "librehub/check-security": "Security analysis",
  "librehub/approval": "Approval",
  "librehub/promote": "Published to stable",
};
export const STATUS_TEXT: Record<StepStatus | "resolved", string> = {
  pending: "Not started",
  running: "Running",
  waiting: "Waiting",
  succeeded: "Succeeded",
  failed: "Failed",
  skipped: "Skipped",
  cancelled: "Cancelled",
  resolved: "Resolved",
};
export const STATUS_SYMBOL: Record<StepStatus | "resolved", string> = {
  pending: "—",
  running: "▶",
  waiting: "…",
  succeeded: "✓",
  failed: "✗",
  skipped: "–",
  cancelled: "⊘",
  resolved: "✓",
};

function detailFor(step: RunStep): string | null {
  const o = step.output ?? {};
  const pick = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : null);
  switch (step.kind) {
    case "librehub/build":
      return pick("build_status") ? `build ${pick("build_status")}${o["reused"] ? " (reused existing build)" : ""}` : null;
    case "librehub/verify-provenance":
      return pick("attestation");
    case "librehub/publish":
    case "librehub/promote":
      return pick("flatpak_ref") ?? pick("publication_status");
    case "librehub/check-security":
      return pick("analysis") ?? pick("vulnerabilities");
    case "librehub/approval":
      return pick("approval_status");
    default:
      return null;
  }
}

/**
 * The visible pipeline is exactly the persisted step state: the source row is derived from
 * the pinned commit and every other row mirrors one step. A failed step is never rendered as
 * successful because the run itself is still active.
 */
export function pipelineRows(run: Run): PipelineRow[] {
  const rows: PipelineRow[] = [
    {
      key: "source",
      label: "Source resolved",
      status: run.source_commit ? "resolved" : run.status === "queued" ? "pending" : "running",
      detail: run.source_commit ? run.source_commit.slice(0, 12) : null,
      attempts: 0,
      error: null,
    },
  ];
  for (const step of run.steps ?? []) {
    rows.push({
      key: step.id,
      label: STEP_LABELS[step.kind] ?? step.kind,
      status: step.status,
      detail: detailFor(step),
      attempts: step.attempts,
      error: step.error ? `${step.error.code}: ${step.error.message}` : null,
    });
  }
  return rows;
}

export function runTone(status: string): "ok" | "bad" | "wait" | "idle" {
  if (status === "completed") return "ok";
  if (status === "failed" || status === "cancelled") return "bad";
  if (status.startsWith("waiting") || status === "running") return "wait";
  return "idle";
}
export const RUN_STATUS_TEXT: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  waiting_for_build: "Waiting for build",
  waiting_for_publication: "Waiting for publication",
  waiting_for_security: "Waiting for security analysis",
  waiting_for_approval: "Waiting for approval",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};
