import React from "react";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const cookieStore = { set: vi.fn(), get: vi.fn(), delete: vi.fn() };
vi.mock("next/headers", () => ({ cookies: async () => cookieStore }));
vi.mock("next/navigation", () => ({
  redirect: (path: string) => {
    throw new Error(`REDIRECT:${path}`);
  },
  notFound: () => {
    throw new Error("NOT_FOUND");
  },
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

import { ApprovalSummary, Pipeline, RunTable, StatusBadge } from "../components/dashboard";
import { pipelineRows, runTone } from "../lib/pipeline";
import { uuid, type Approval, type Run, type RunStep } from "../lib/developer";
import { decideApproval, login } from "../app/dashboard/actions";

const ID = "11111111-1111-4111-8111-111111111111";
function step(over: Partial<RunStep> & Pick<RunStep, "id" | "kind" | "status">): RunStep {
  return {
    needs: [],
    attempts: 0,
    next_attempt_at: null,
    started_at: null,
    finished_at: null,
    output: {},
    error: null,
    ...over,
  };
}
function run(over: Partial<Run> = {}): Run {
  return {
    id: ID,
    automation_id: ID,
    project_id: ID,
    definition_version: 3,
    status: "waiting_for_approval",
    trigger: "ci",
    trigger_key: "k",
    trigger_detail: {},
    source_ref: "main",
    source_commit: "0123456789abcdef0123456789abcdef01234567",
    source_event_id: ID,
    build_id: ID,
    beta_publication_id: ID,
    stable_publication_id: null,
    current_step: "approval",
    chain_depth: 0,
    cancel_requested: false,
    error: null,
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: null,
    steps: [
      step({ id: "build", kind: "librehub/build", status: "succeeded", output: { build_status: "succeeded", reused: true } }),
      step({ id: "verify", kind: "librehub/verify-provenance", status: "succeeded", output: { attestation: "verified" } }),
      step({ id: "beta", kind: "librehub/publish", status: "succeeded", output: { flatpak_ref: "app/org.example.App/x86_64/master" } }),
      step({ id: "security", kind: "librehub/check-security", status: "succeeded", output: { analysis: "ready" } }),
      step({ id: "approval", kind: "librehub/approval", status: "waiting", output: { approval_status: "requested" } }),
      step({ id: "stable", kind: "librehub/promote", status: "pending" }),
    ],
    ...over,
  };
}

describe("pipeline presentation", () => {
  it("shows the real status of every step in words", () => {
    render(<Pipeline run={run()} />);
    const list = screen.getByRole("list", { name: "Release pipeline" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows.map((r) => r.getAttribute("data-step"))).toEqual(["source", "build", "verify", "beta", "security", "approval", "stable"]);
    expect(rows[0]).toHaveTextContent("Source resolved");
    expect(rows[0]).toHaveTextContent("0123456789ab");
    expect(rows[5]).toHaveTextContent("Approval");
    expect(rows[5]).toHaveTextContent("Waiting");
    expect(rows[6]).toHaveTextContent("Published to stable");
    expect(rows[6]).toHaveTextContent("Not started");
    expect(rows[1]).toHaveTextContent("reused existing build");
  });
  it("never presents a failed step as successful while the run is still active", () => {
    const failing = run({
      status: "running",
      steps: [step({ id: "build", kind: "librehub/build", status: "failed", error: { code: "build_failed", message: "The build failed" } })],
    });
    render(<Pipeline run={failing} />);
    const row = document.querySelector('[data-step="build"]') as HTMLElement;
    expect(row).toHaveAttribute("data-status", "failed");
    expect(row).toHaveTextContent("Failed");
    expect(row).not.toHaveTextContent("Succeeded");
    expect(row).toHaveTextContent("build_failed: The build failed");
  });
  it("does not claim a source was resolved before a commit is pinned", () => {
    expect(pipelineRows(run({ source_commit: null, status: "queued", steps: [] }))[0].status).toBe("pending");
    expect(pipelineRows(run({ source_commit: null, status: "running", steps: [] }))[0].status).toBe("running");
  });
  it("reports retries and skipped steps", () => {
    const rows = pipelineRows(
      run({ steps: [step({ id: "a", kind: "librehub/publish", status: "waiting", attempts: 2 }), step({ id: "b", kind: "librehub/promote", status: "skipped" })] }),
    );
    render(<Pipeline run={run({ steps: [step({ id: "a", kind: "librehub/publish", status: "waiting", attempts: 2 })] })} />);
    expect(rows[1].attempts).toBe(2);
    expect(screen.getByText(/2 retries/)).toBeInTheDocument();
    expect(rows[2].status).toBe("skipped");
  });
});

describe("status badges and tables", () => {
  it("labels runs with text and a machine-readable status", () => {
    render(
      <>
        <StatusBadge status="waiting_for_security" />
        <StatusBadge status="failed" />
      </>,
    );
    expect(screen.getByText("Waiting for security analysis")).toHaveAttribute("data-status", "waiting_for_security");
    expect(runTone("completed")).toBe("ok");
    expect(runTone("failed")).toBe("bad");
    expect(runTone("cancelled")).toBe("bad");
    expect(runTone("waiting_for_approval")).toBe("wait");
  });
  it("renders run history without logs and handles emptiness", () => {
    const { rerender } = render(<RunTable runs={[]} project={ID} />);
    expect(screen.getByText("No runs yet.")).toBeInTheDocument();
    rerender(<RunTable runs={[run({ status: "failed" })]} project={ID} />);
    expect(screen.getByRole("link", { name: ID.slice(0, 8) })).toHaveAttribute("href", `/dashboard/projects/${ID}/runs/${ID}`);
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });
  it("summarises the immutable release candidate for approvers", () => {
    const approval: Approval = {
      id: ID, project_id: ID, run_id: ID, step_id: "approval", status: "requested",
      candidate: { build_id: ID, source_commit: "c".repeat(40), snapshot_sha256: "d".repeat(64), app_id: "org.example.App", beta_publication_id: ID, target_channel: "stable" },
      definition_version: 1, requested_by: "ci:1296269", requested_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-04T00:00:00Z",
      decided_by: null, decided_role: null, decided_at: null, reason: null, consumed_at: null,
    };
    render(<ApprovalSummary approval={approval} />);
    expect(screen.getByText("org.example.App")).toBeInTheDocument();
    expect(screen.getByText("c".repeat(40))).toBeInTheDocument();
    expect(screen.getByText("d".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("ci:1296269")).toBeInTheDocument();
  });
});

describe("developer API boundary", () => {
  it("accepts only canonical UUIDs in route parameters", () => {
    expect(uuid(ID.toUpperCase())).toBe(ID);
    for (const bad of ["../etc/passwd", "1", `${ID}/..`, "", `${ID}?x=1`]) {
      expect(() => uuid(bad)).toThrow("NOT_FOUND");
    }
  });
});

describe("dashboard actions", () => {
  beforeEach(() => {
    cookieStore.set.mockReset();
    vi.restoreAllMocks();
  });
  it("rejects malformed tokens before any network call", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const state = await login({}, form({ token: "not-a-token" }));
    expect(state.error).toMatch(/does not look like/);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(cookieStore.set).not.toHaveBeenCalled();
  });
  it("refuses tokens the API does not accept", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    const state = await login({}, form({ token: goodToken() }));
    expect(state.error).toMatch(/not accepted/);
    expect(cookieStore.set).not.toHaveBeenCalled();
  });
  it("stores an accepted token only in a strict httpOnly cookie scoped to the dashboard", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    await expect(login({}, form({ token: goodToken() }))).rejects.toThrow("REDIRECT:/dashboard/projects");
    const [name, value, options] = cookieStore.set.mock.calls[0];
    expect(name).toBe("librehub_dev_token");
    expect(value).toBe(goodToken());
    expect(options).toMatchObject({ httpOnly: true, sameSite: "strict", path: "/dashboard" });
    expect(options.maxAge).toBeLessThanOrEqual(8 * 3600);
    // The token travels only in the Authorization header.
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).not.toContain("librehub_");
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${goodToken()}`);
  });
  it("requires an explicit approve or reject decision", async () => {
    const state = await decideApproval({}, form({ approval: ID, decision: "maybe" }));
    expect(state.error).toMatch(/approve or reject/);
  });
});

function goodToken() {
  return `librehub_${ID.replace(/4/g, "a")}_${"ab".repeat(32)}`;
}
function form(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [k, v] of Object.entries(values)) data.set(k, v);
  return data;
}
