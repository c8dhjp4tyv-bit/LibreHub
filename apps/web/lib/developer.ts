// Server-side client for the authenticated developer API. The API token lives in an
// httpOnly cookie, is attached here on the server and is never rendered or sent to the browser.
import { cookies } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { apiBase } from "./catalog";

export const TOKEN_COOKIE = "librehub_dev_token";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type StepStatus =
  | "pending"
  | "running"
  | "waiting"
  | "succeeded"
  | "failed"
  | "skipped"
  | "cancelled";
export type RunStatus =
  | "queued"
  | "running"
  | "waiting_for_build"
  | "waiting_for_publication"
  | "waiting_for_security"
  | "waiting_for_approval"
  | "completed"
  | "failed"
  | "cancelled";
export interface Failure {
  code: string;
  message: string;
  retryable?: boolean;
}
export interface RunStep {
  id: string;
  kind: string;
  needs: string[];
  status: StepStatus;
  attempts: number;
  next_attempt_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  output: Record<string, unknown>;
  error: Failure | null;
}
export interface Run {
  id: string;
  automation_id: string;
  project_id: string;
  definition_version: number;
  status: RunStatus;
  trigger: string;
  trigger_key: string;
  trigger_detail: Record<string, unknown>;
  source_ref: string | null;
  source_commit: string | null;
  source_event_id: string | null;
  build_id: string | null;
  beta_publication_id: string | null;
  stable_publication_id: string | null;
  current_step: string | null;
  chain_depth: number;
  cancel_requested: boolean;
  error: Failure | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  steps?: RunStep[];
}
export interface Automation {
  id: string;
  project_id: string;
  name: string;
  enabled: boolean;
  schedules_enabled: boolean;
  current_version: number;
  min_valid_version: number;
  spec: {
    triggers: { type: string; [key: string]: unknown }[];
    steps: { id: string; uses: string; needs?: string[]; with?: Record<string, unknown> }[];
    policy?: Record<string, unknown>;
  };
  schedules?: { trigger_index: number; next_run_at: string }[];
  updated_at: string;
}
export interface Project {
  id: string;
  slug: string;
  display_name: string;
  status: string;
  repository: { url: string };
  default_branch: string;
}
export interface Approval {
  id: string;
  project_id: string;
  run_id: string;
  step_id: string;
  status: "requested" | "approved" | "rejected" | "expired" | "cancelled";
  candidate: {
    build_id: string;
    source_commit: string;
    snapshot_sha256: string;
    app_id: string;
    beta_publication_id: string | null;
    target_channel: string;
  };
  definition_version: number;
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_role: string | null;
  decided_at: string | null;
  reason: string | null;
  consumed_at: string | null;
}
export interface OidcConnection {
  id: string;
  name: string;
  enabled: boolean;
  fingerprint: string;
  revoked_at: string | null;
  created_at: string;
  policy: {
    repository_id: string;
    repository_owner_id: string;
    repository?: string | null;
    allowed_refs: string[];
    allowed_workflows: string[];
    allowed_environments: string[];
    allowed_event_types: string[];
    allowed_permissions: string[];
    token_ttl_seconds: number;
  };
}
export interface Webhook {
  id: string;
  url: string;
  description: string;
  event_types: string[];
  exclude_origins: string[];
  enabled: boolean;
  disabled_reason: string | null;
  secret_fingerprint: string;
  secret_rotated_at: string | null;
  last_delivery: { delivery_id: string; status: string; http_status: number | null; at: string } | null;
}
export interface Delivery {
  id: string;
  webhook_id: string;
  event_type: string;
  status: string;
  attempts: number;
  last_http_status: number | null;
  last_error: string | null;
  created_at: string;
  replay_of: string | null;
}

export class DeveloperApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Route parameters become API paths, so only canonical UUIDs are accepted. */
export function uuid(value: string): string {
  if (!UUID.test(value)) notFound();
  return value.toLowerCase();
}

export async function token(): Promise<string | null> {
  return (await cookies()).get(TOKEN_COOKIE)?.value ?? null;
}

export async function devFetch<T>(
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const bearer = await token();
  if (!bearer) redirect("/dashboard/login");
  let response: Response;
  try {
    response = await fetch(`${apiBase.replace(/\/$/, "")}${path}`, {
      method: init.method ?? "GET",
      headers: {
        authorization: `Bearer ${bearer}`,
        "content-type": "application/json",
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    throw new DeveloperApiError(503, "api_unavailable", "The LibreHub API is unreachable.");
  }
  if (response.status === 401) redirect("/dashboard/login?expired=1");
  if (response.status === 404) notFound();
  if (!response.ok) {
    let code = `http_${response.status}`;
    let message = "The request was rejected.";
    try {
      const body = (await response.json()) as { code?: string; message?: string };
      code = String(body.code ?? code).slice(0, 80);
      message = String(body.message ?? message).slice(0, 200);
    } catch {
      /* keep defaults */
    }
    throw new DeveloperApiError(response.status, code, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function errorText(error: unknown): string {
  if (error instanceof DeveloperApiError) return `${error.message} (${error.code})`;
  return "The operation failed.";
}
