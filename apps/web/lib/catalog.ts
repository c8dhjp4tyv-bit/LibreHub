import { cache } from "react";
export type Channel = "stable" | "beta";
export interface Publisher {
  id: string | null;
  display_name: string;
}
export interface Card {
  app_id: string;
  slug: string;
  name: string;
  summary: string;
  icon: string | null;
  publisher: Publisher;
  project_id: string | null;
  source_url: string | null;
  categories: string[];
  architectures: string[];
  channel: Channel;
  archived: boolean;
  updated_at: string;
  published_at: string;
  trust?: TrustSummary;
}
export interface Permissions {
  network: boolean;
  filesystem: string[];
  devices: string[];
  sockets: string[];
  dbus: string[];
  shared: string[];
  other: string[];
}
export interface PermissionDiff {
  from_publication_id: string | null;
  to_publication_id: string;
  severity: "none" | "low" | "moderate" | "significant";
  changed_network: { from: boolean; to: boolean } | null;
  added: Permissions;
  removed: Permissions;
  summary_notes: string[];
  generated_at: string;
}
export interface VulnerabilityFinding {
  vulnerability_id: string;
  component_name: string;
  component_version: string;
  severity: "unknown" | "low" | "medium" | "high" | "critical";
  summary: string;
  reference_url: string | null;
  source_provider: string;
  checked_at: string;
}
export interface ReleaseSecurityDetails {
  publication_id: string;
  app_id: string;
  channel: string;
  status: "pending" | "analyzing" | "ready" | "failed" | "unavailable";
  sbom_format: string;
  sbom_component_count: number;
  sbom_sha256: string;
  sbom_download_url: string;
  vulnerabilities_status: "clean" | "vulnerable" | "pending" | "unavailable";
  vulnerabilities_checked_at: string | null;
  vulnerability_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  findings: VulnerabilityFinding[];
  permissions_extracted_at: string;
  permission_severity: "none" | "low" | "moderate" | "significant";
  permission_diff: PermissionDiff | null;
}
export interface TrustSummary {
  trust_state: "verified_publisher" | "community" | "unverified" | "restricted" | "removed";
  publisher_verification: string;
  verified_domain: string | null;
  source_available: boolean;
  signed_repository: boolean;
  security_analysis: string;
  known_vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  latest_permission_change: "none" | "low" | "moderate" | "significant";
  moderation_state: "normal" | "under_review" | "restricted" | "removed";
  moderation_notice: string | null;
}
export type ReportReason =
  | "malware"
  | "policy_violation"
  | "copyright_infringement"
  | "privacy_violation"
  | "broken_build"
  | "security_vulnerability"
  | "impersonation"
  | "other";
export interface Release {
  publication_id: string;
  build_id: string;
  source_commit: string | null;
  source_url: string | null;
  channel: Channel;
  architecture: string;
  flatpak_ref: string;
  ostree_checksum: string;
  published_at: string;
  version: string;
  release_notes: string;
  permissions: Permissions;
  security?: ReleaseSecurityDetails;
}
export interface App extends Card {
  description: string;
  screenshots: { url: string; caption: string }[];
  homepage: string | null;
  license: string | null;
  developer_name: string | null;
  content_rating: string[];
  current_stable_release: Release | null;
  current_beta_release: Release | null;
  current_releases: Release[];
  install: {
    remote: string;
    remote_descriptor_url: string;
    flatpakref_url: string;
    command: string;
  };
}
export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
export interface Category {
  id: string;
  count: number;
}
export const apiBase = process.env.LIBREHUB_API_URL || "http://127.0.0.1:8080";
export const publicApiBase =
  process.env.LIBREHUB_API_PUBLIC_URL || "http://localhost:8080";
export const webBase =
  process.env.LIBREHUB_WEB_PUBLIC_URL || "http://localhost:3000";
for (const base of [apiBase, publicApiBase, webBase]) {
  const u = new URL(base);
  if (
    !["http:", "https:"].includes(u.protocol) ||
    u.username ||
    u.password ||
    u.search ||
    u.hash
  )
    throw new Error("Invalid operator URL configuration");
}
export class CatalogUnavailable extends Error {}
export const getCatalog = cache(async <T>(path: string): Promise<T | null> => {
  // Paths are constructed by our route code, never supplied as arbitrary URLs.
  if (!path.startsWith("/api/v1/catalog/"))
    throw new Error("Invalid catalog route");
  let response: Response;
  try {
    response = await fetch(`${apiBase.replace(/\/$/, "")}${path}`, {
      next: { revalidate: 5 },
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new CatalogUnavailable("The catalog is temporarily unavailable.");
  }
  if (response.status === 404) return null;
  if (!response.ok)
    throw new CatalogUnavailable("The catalog could not load this request.");
  return (await response.json()) as T;
});
export function listPath(
  params: Record<string, string | undefined>,
  search = false,
): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
  return `/api/v1/catalog/${search ? "search" : "apps"}?${q}`;
}
export function date(value: string): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}
export function commitLink(
  source: string | null,
  commit: string | null,
): string | null {
  if (!source || !commit || !/^[0-9a-f]{40}$/.test(commit)) return null;
  try {
    const u = new URL(source);
    if (
      u.protocol !== "https:" ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      u.hostname !== "github.com" ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?\/?$/.test(u.pathname)
    )
      return null;
    return `${u.origin}${u.pathname.replace(/\/$/, "").replace(/\.git$/, "")}/commit/${commit}`;
  } catch {
    return null;
  }
}
