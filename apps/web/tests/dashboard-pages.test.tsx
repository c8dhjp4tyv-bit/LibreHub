import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const devFetch = vi.fn();
vi.mock("next/navigation", () => ({
  redirect: (path: string) => {
    throw new Error(`REDIRECT:${path}`);
  },
  notFound: () => {
    throw new Error("NOT_FOUND");
  },
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("next/headers", () => ({ cookies: async () => ({ get: () => ({ value: "x" }), set: vi.fn(), delete: vi.fn() }) }));
vi.mock("../lib/developer", async (original) => ({ ...(await original<typeof import("../lib/developer")>()), devFetch: (...args: unknown[]) => devFetch(...args) }));

import RunDetail from "../app/dashboard/projects/[id]/runs/[run]/page";
import Integrations from "../app/dashboard/projects/[id]/integrations/page";
import Approvals from "../app/dashboard/approvals/page";
import Projects from "../app/dashboard/projects/page";

const ID = "11111111-1111-4111-8111-111111111111";
const baseRun = {
  id: ID, automation_id: ID, project_id: ID, definition_version: 2, status: "failed", trigger: "push", trigger_key: "delivery:x",
  trigger_detail: {}, source_ref: "main", source_commit: "a".repeat(40), source_event_id: ID, build_id: ID, beta_publication_id: null,
  stable_publication_id: null, current_step: "build", chain_depth: 0, cancel_requested: false,
  error: { code: "build_failed", message: "The build failed", retryable: false },
  created_at: "2026-01-01T00:00:00Z", started_at: "2026-01-01T00:00:01Z", finished_at: "2026-01-01T00:05:00Z",
  steps: [
    { id: "build", kind: "librehub/build", needs: [], status: "failed", attempts: 0, next_attempt_at: null, started_at: null, finished_at: null, output: {}, error: { code: "build_failed", message: "The build failed" } },
    { id: "stable", kind: "librehub/promote", needs: ["build"], status: "skipped", attempts: 0, next_attempt_at: null, started_at: null, finished_at: null, output: {}, error: null },
  ],
};
beforeEach(() => {
  devFetch.mockReset();
});

describe("dashboard pages use live API data", () => {
  it("shows a failed run honestly and offers no cancel button for finished runs", async () => {
    devFetch.mockImplementation(async (path: string) => {
      if (path.endsWith("/events")) return [{ id: 1, at: "2026-01-01T00:00:00Z", kind: "run", detail: { status: "failed" } }];
      if (path.includes("/approvals")) return [];
      return baseRun;
    });
    render(await RunDetail({ params: Promise.resolve({ id: ID, run: ID }) }));
    expect(screen.getAllByText(/build_failed/).length).toBeGreaterThan(0);
    expect(screen.getByRole("alert")).toHaveTextContent("The build failed");
    expect(screen.queryByRole("button", { name: "Cancel run" })).not.toBeInTheDocument();
    expect(devFetch).toHaveBeenCalledWith(`/api/v1/projects/${ID}/automations/runs/${ID}`);
  });
  it("offers cancellation, approval and decision history for an active run", async () => {
    const approval = {
      id: ID, project_id: ID, run_id: ID, step_id: "approval", status: "requested",
      candidate: { build_id: ID, source_commit: "b".repeat(40), snapshot_sha256: "c".repeat(64), app_id: "org.example.App", beta_publication_id: null, target_channel: "stable" },
      definition_version: 2, requested_by: "ci:7", requested_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-04T00:00:00Z",
      decided_by: null, decided_role: null, decided_at: null, reason: null, consumed_at: null,
    };
    const decided = { ...approval, id: "22222222-2222-4222-8222-222222222222", status: "approved", decided_by: "dev-1", decided_role: "project_owner", decided_at: "2026-01-02T00:00:00Z", reason: "ship it" };
    devFetch.mockImplementation(async (path: string) => {
      if (path.endsWith("/events")) return [];
      if (path.includes("/approvals")) return [approval, decided];
      return { ...baseRun, status: "waiting_for_approval", error: null };
    });
    render(await RunDetail({ params: Promise.resolve({ id: ID, run: ID }) }));
    expect(screen.getByRole("button", { name: "Cancel run" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve release" })).toBeInTheDocument();
    expect(screen.getByText(/ship it/)).toBeInTheDocument();
    expect(screen.getByText(/project_owner/)).toBeInTheDocument();
  });
  it("rejects malformed route identifiers without calling the API", async () => {
    await expect(RunDetail({ params: Promise.resolve({ id: "../x", run: ID }) })).rejects.toThrow("NOT_FOUND");
    expect(devFetch).not.toHaveBeenCalled();
  });
  it("lists pending approvals across projects", async () => {
    devFetch.mockResolvedValue([
      { id: ID, project_id: ID, run_id: ID, step_id: "approval", status: "requested",
        candidate: { build_id: ID, source_commit: "b".repeat(40), snapshot_sha256: "c".repeat(64), app_id: "org.example.Pending", beta_publication_id: null, target_channel: "stable" },
        definition_version: 1, requested_by: "ci", requested_at: "x", expires_at: "2026-01-04T00:00:00Z", decided_by: null, decided_role: null, decided_at: null, reason: null, consumed_at: null },
    ]);
    render(await Approvals());
    expect(screen.getAllByText("org.example.Pending", { exact: false }).length).toBeGreaterThan(0);
    expect(devFetch).toHaveBeenCalledWith("/api/v1/approvals?status=requested&limit=50");
  });
  it("lists projects with links to their automation views", async () => {
    devFetch.mockResolvedValue([{ id: ID, slug: "hello", display_name: "Hello", status: "active", repository: { url: "https://github.com/o/r" }, default_branch: "main" }]);
    render(await Projects());
    expect(screen.getByRole("link", { name: "Automations" })).toHaveAttribute("href", `/dashboard/projects/${ID}/automations`);
    expect(screen.getByRole("link", { name: "Integrations" })).toHaveAttribute("href", `/dashboard/projects/${ID}/integrations`);
  });
  it("never renders webhook secrets, only public fingerprints and redacted metadata", async () => {
    devFetch.mockImplementation(async (path: string) => {
      if (path.endsWith("/oidc"))
        return [{ id: ID, name: "gha", enabled: true, fingerprint: "ab12cd34ef56ab12", revoked_at: null, created_at: "x",
          policy: { repository_id: "1296269", repository_owner_id: "583231", repository: "octo/hello", allowed_refs: ["refs/heads/main"], allowed_workflows: ["octo/hello/.github/workflows/r.yml@*"], allowed_environments: [], allowed_event_types: ["push"], allowed_permissions: ["automations:run"], token_ttl_seconds: 600 } }];
      if (path.endsWith("/webhooks"))
        return [{ id: ID, url: "https://hooks.example.com/x", description: "", event_types: ["build.started"], exclude_origins: [], enabled: true, disabled_reason: null, secret_fingerprint: "0123456789ab", secret_rotated_at: null,
          last_delivery: { delivery_id: ID, status: "retry_wait", http_status: 500, at: "2026-01-01T00:00:00Z" }, secret: "whsec_MUST_NOT_RENDER" }];
      return [{ id: ID, webhook_id: ID, event_type: "build.started", status: "dead_letter", attempts: 8, last_http_status: 500, last_error: null, created_at: "2026-01-01T00:00:00Z", replay_of: null }];
    });
    const { container } = render(await Integrations({ params: Promise.resolve({ id: ID }) }));
    expect(container.textContent).not.toContain("whsec_MUST_NOT_RENDER");
    expect(screen.getByText("0123456789ab")).toBeInTheDocument();
    expect(screen.getByText("ab12cd34ef56ab12")).toBeInTheDocument();
    expect(screen.getByText(/retry_wait/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Replay" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke and remove credentials" })).toBeInTheDocument();
  });
});
