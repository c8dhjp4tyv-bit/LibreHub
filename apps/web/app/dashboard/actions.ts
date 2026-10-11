"use server";
// Mutations performed by the developer dashboard. Each action re-authenticates with the
// httpOnly cookie on the server, validates identifiers and relies on the API for authorization.
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { apiBase, webBase } from "../../lib/catalog";
import {
  DeveloperApiError,
  TOKEN_COOKIE,
  devFetch,
  errorText,
  uuid,
} from "../../lib/developer";

export interface FormState {
  error?: string;
  ok?: string;
  /** One-time secret; shown once in the response to the submitting form and never stored. */
  secret?: string;
}

const TOKEN_SHAPE = /^librehub_[0-9a-f-]{36}_[0-9a-f]{64}$/;

export async function login(_: FormState, form: FormData): Promise<FormState> {
  const token = String(form.get("token") ?? "").trim();
  if (!TOKEN_SHAPE.test(token)) return { error: "That does not look like a LibreHub API token." };
  let ok = false;
  try {
    const response = await fetch(`${apiBase.replace(/\/$/, "")}/api/v1/whoami`, {
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
    });
    ok = response.ok;
  } catch {
    return { error: "The LibreHub API is unreachable." };
  }
  if (!ok) return { error: "The token was not accepted." };
  (await cookies()).set(TOKEN_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: new URL(webBase).protocol === "https:",
    path: "/dashboard",
    maxAge: 8 * 3600,
  });
  redirect("/dashboard/projects");
}

export async function logout(): Promise<void> {
  (await cookies()).delete({ name: TOKEN_COOKIE, path: "/dashboard" });
  redirect("/dashboard/login");
}

async function guard<T>(work: () => Promise<T>): Promise<T | FormState> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof DeveloperApiError) return { error: errorText(error) };
    throw error;
  }
}
const text = (form: FormData, key: string, max = 200) => String(form.get(key) ?? "").slice(0, max);

export async function runAutomation(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const automation = uuid(text(form, "automation"));
  const started = await devFetch<{ run: { id: string } }>(
    `/api/v1/projects/${project}/automations/${automation}/run`,
    { method: "POST", body: { idempotency_key: `ui-${crypto.randomUUID()}` } },
  );
  redirect(`/dashboard/projects/${project}/runs/${started.run.id}`);
}

export async function cancelRun(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const run = uuid(text(form, "run"));
  await devFetch(`/api/v1/projects/${project}/automations/runs/${run}/cancel`, { method: "POST" });
  revalidatePath(`/dashboard/projects/${project}/runs/${run}`);
}

export async function decideApproval(_: FormState, form: FormData): Promise<FormState> {
  const approval = uuid(text(form, "approval"));
  const decision = text(form, "decision");
  if (decision !== "approve" && decision !== "reject") return { error: "Choose approve or reject." };
  const result = await guard(() =>
    devFetch(`/api/v1/approvals/${approval}/${decision}`, {
      method: "POST",
      body: { reason: text(form, "reason", 500) || undefined },
    }),
  );
  if (result && typeof result === "object" && "error" in result) return result as FormState;
  revalidatePath("/dashboard/approvals");
  return { ok: decision === "approve" ? "Approved. The release continues." : "Rejected. The release is blocked." };
}

export async function createWebhook(_: FormState, form: FormData): Promise<FormState> {
  const project = uuid(text(form, "project"));
  const events = form.getAll("events").map(String);
  const result = await guard(() =>
    devFetch<{ secret: string }>(`/api/v1/projects/${project}/integrations/webhooks`, {
      method: "POST",
      body: { url: text(form, "url", 2048), description: text(form, "description"), event_types: events },
    }),
  );
  if ("error" in result) return result;
  revalidatePath(`/dashboard/projects/${project}/integrations`);
  return { ok: "Webhook created. Copy the signing secret now; it is never shown again.", secret: result.secret };
}

export async function rotateWebhook(_: FormState, form: FormData): Promise<FormState> {
  const project = uuid(text(form, "project"));
  const webhook = uuid(text(form, "webhook"));
  const result = await guard(() =>
    devFetch<{ secret: string }>(`/api/v1/projects/${project}/integrations/webhooks/${webhook}/rotate`, { method: "POST" }),
  );
  if ("error" in result) return result;
  revalidatePath(`/dashboard/projects/${project}/integrations`);
  return { ok: "Secret rotated. The previous secret stopped working immediately.", secret: result.secret };
}

export async function setWebhookEnabled(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const webhook = uuid(text(form, "webhook"));
  await devFetch(`/api/v1/projects/${project}/integrations/webhooks/${webhook}`, {
    method: "PATCH",
    body: { enabled: text(form, "enabled") === "true" },
  });
  revalidatePath(`/dashboard/projects/${project}/integrations`);
}

export async function deleteWebhook(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const webhook = uuid(text(form, "webhook"));
  await devFetch(`/api/v1/projects/${project}/integrations/webhooks/${webhook}`, { method: "DELETE" });
  revalidatePath(`/dashboard/projects/${project}/integrations`);
}

export async function replayDelivery(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const delivery = uuid(text(form, "delivery"));
  await devFetch(`/api/v1/projects/${project}/integrations/deliveries/${delivery}/replay`, { method: "POST" });
  revalidatePath(`/dashboard/projects/${project}/integrations`);
}

export async function setConnectionEnabled(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const connection = uuid(text(form, "connection"));
  await devFetch(`/api/v1/projects/${project}/integrations/oidc/${connection}`, {
    method: "PATCH",
    body: { enabled: text(form, "enabled") === "true" },
  });
  revalidatePath(`/dashboard/projects/${project}/integrations`);
}

export async function revokeConnection(form: FormData): Promise<void> {
  const project = uuid(text(form, "project"));
  const connection = uuid(text(form, "connection"));
  await devFetch(`/api/v1/projects/${project}/integrations/oidc/${connection}`, { method: "DELETE" });
  revalidatePath(`/dashboard/projects/${project}/integrations`);
}
