import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import {
  AppCard,
  Grid,
  SearchForm,
  PermissionList,
  ReleaseHistory,
  Pagination,
  TrustBadge,
  PermissionDiffNotice,
  SecurityDetailsSection,
} from "../components/store";
import { ThemeToggle } from "../components/theme";
import Loading from "../app/loading";
import ErrorPage from "../app/error";
import {
  commitLink,
  type Card,
  type Release,
  type TrustSummary,
  type PermissionDiff,
} from "../lib/catalog";
vi.mock("next/image", () => ({
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) =>
    React.createElement("img", { src: props.src, alt: props.alt }),
}));
const app: Card = {
  app_id: "org.example.Test",
  slug: "org.example.Test",
  name: "Test App",
  summary: "An open tool",
  icon: null,
  publisher: { id: "publisher", display_name: "Developer" },
  project_id: "project",
  source_url: "https://github.com/example/test",
  categories: ["Utility"],
  architectures: ["x86_64"],
  channel: "stable",
  archived: false,
  updated_at: "2026-01-01T00:00:00Z",
  published_at: "2026-01-01T00:00:00Z",
};
const permissions = {
  network: true,
  filesystem: ["xdg-download:ro"],
  sockets: ["wayland"],
  devices: [],
  shared: ["network"],
  dbus: [],
  other: [],
};
const release: Release = {
  publication_id: "publication",
  build_id: "build",
  source_commit: "a".repeat(40),
  source_url: app.source_url,
  channel: "stable",
  architecture: "x86_64",
  flatpak_ref: "app/org.example.Test/x86_64/master",
  ostree_checksum: "b".repeat(64),
  published_at: app.published_at,
  version: "1.2",
  release_notes: "Notes",
  permissions,
};
describe("store components", () => {
  it("renders real card data with a canonical app link", () => {
    render(<AppCard app={app} />);
    expect(screen.getByRole("heading", { name: "Test App" })).toBeVisible();
    expect(screen.getByRole("link")).toHaveAttribute(
      "href",
      "/apps/org.example.Test",
    );
  });
  it("shows a meaningful empty catalog", () => {
    render(<Grid page={{ items: [], total: 0, limit: 24, offset: 0 }} />);
    expect(screen.getByText("No applications here yet")).toBeVisible();
  });
  it("preserves search and filters in a keyboard-submittable form", () => {
    render(<SearchForm q="editor" channel="beta" />);
    expect(screen.getByRole("textbox")).toHaveValue("editor");
    expect(
      screen.getByRole("button", { name: /Search/ }).closest("form"),
    ).toHaveAttribute("action", "/search");
    expect(screen.getByLabelText("Channel")).toHaveValue("beta");
  });
  it("renders neutral permissions", () => {
    render(<PermissionList permissions={permissions} />);
    expect(screen.getByText("Network access")).toBeVisible();
    expect(screen.getByText("xdg-download:ro")).toBeVisible();
    expect(screen.getByText("wayland")).toBeVisible();
  });
  it("renders actual release provenance", () => {
    render(
      <ReleaseHistory
        page={{ items: [release], total: 1, limit: 24, offset: 0 }}
      />,
    );
    expect(screen.getByText("1.2")).toBeVisible();
    expect(screen.getByRole("link")).toHaveAttribute(
      "href",
      `https://github.com/example/test/commit/${"a".repeat(40)}`,
    );
  });
  it("retains query on pagination", () => {
    render(
      <Pagination
        page={{ items: [], total: 60, limit: 24, offset: 24 }}
        pathname="/search"
        params={{ q: "editor" }}
      />,
    );
    expect(screen.getByRole("link", { name: /Next/ })).toHaveAttribute(
      "href",
      "/search?q=editor&offset=48",
    );
  });
  it("shows loading status", () => {
    render(<Loading />);
    expect(screen.getByRole("status")).toBeVisible();
  });
  it("allows recovery from server errors", () => {
    const reset = vi.fn();
    render(<ErrorPage reset={reset} />);
    fireEvent.click(screen.getByRole("button"));
    expect(reset).toHaveBeenCalledOnce();
  });
  it("uses accessible theme controls for mobile and desktop", () => {
    render(<ThemeToggle />);
    fireEvent.change(screen.getByRole("combobox"), {
      target: { value: "dark" },
    });
    expect(document.documentElement.dataset.theme).toBe("dark");
  });
  it("does not construct commit links to unknown hosts or unsafe schemes", () => {
    expect(commitLink("javascript:alert(1)", "a".repeat(40))).toBeNull();
    expect(
      commitLink("https://github.com.evil.net/user/repo", "a".repeat(40)),
    ).toBeNull();
    expect(commitLink(app.source_url, "../../")).toBeNull();
  });
  it("escapes metadata event attributes and scripts as React text", () => {
    render(
      <AppCard
        app={{
          ...app,
          name: "<script>alert(1)</script>",
          summary: "<img src=x onerror=alert(1)>",
        }}
      />,
    );
    expect(document.querySelector("script")).toBeNull();
    expect(document.querySelector("[onerror]")).toBeNull();
    expect(screen.getByText("<script>alert(1)</script>")).toBeVisible();
  });
  it("renders verified publisher trust badge with domain", () => {
    const trust: TrustSummary = {
      state: "verified_publisher",
      badge_label: "Verified Publisher",
      publisher_verified: true,
      verified_domain: "example.org",
      moderation_state: "normal",
      moderation_notice: null,
      latest_permission_change: "none",
      vulnerabilities_status: "clean",
      vulnerability_counts: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    };
    render(<TrustBadge trust={trust} />);
    expect(screen.getByText(/Verified Publisher/)).toBeVisible();
    expect(screen.getByText(/example.org/)).toBeVisible();
  });
  it("renders permission diff banner for significant permission changes", () => {
    const diff: PermissionDiff = {
      from_publication_id: "pub-1",
      to_publication_id: "pub-2",
      severity: "significant",
      network_changed: { from: false, to: true },
      added: {
        network: true,
        filesystem: ["home"],
        devices: ["all"],
        sockets: [],
        dbus: [],
        shared: [],
        other: [],
      },
      removed: {
        network: false,
        filesystem: [],
        devices: [],
        sockets: [],
        dbus: [],
        shared: [],
        other: [],
      },
      notes: ["Broad filesystem access added: home"],
      generated_at: "2026-01-01T00:00:00Z",
    };
    render(<PermissionDiffNotice diff={diff} />);
    expect(screen.getByText(/SIGNIFICANT IMPACT/)).toBeVisible();
    expect(screen.getByText("home")).toBeVisible();
    expect(screen.getByText(/Broad filesystem access added/)).toBeVisible();
  });
  it("renders security vulnerability assessment and SBOM artifact links", () => {
    const secRelease: Release = {
      ...release,
      security: {
        publication_id: "pub-1",
        app_id: "org.example.Test",
        channel: "stable",
        status: "ready",
        sbom_format: "SPDX-2.3",
        sbom_component_count: 42,
        sbom_sha256: "c".repeat(64),
        sbom_download_url: "/api/v1/catalog/apps/org.example.Test/releases/pub-1/sbom/download",
        vulnerabilities_status: "vulnerable",
        vulnerabilities_checked_at: "2026-01-01T00:00:00Z",
        vulnerability_counts: { critical: 1, high: 0, medium: 0, low: 0, total: 1 },
        findings: [
          {
            vulnerability_id: "GHSA-1234",
            component_name: "openssl",
            component_version: "1.1.1",
            severity: "critical",
            summary: "Buffer overflow vulnerability",
            reference_url: "https://osv.dev/vulnerability/GHSA-1234",
            source_provider: "osv",
            checked_at: "2026-01-01T00:00:00Z",
          },
        ],
        permissions_extracted_at: "2026-01-01T00:00:00Z",
        permission_severity: "none",
        permission_diff: null,
      },
    };
    render(<SecurityDetailsSection release={secRelease} />);
    expect(screen.getByText(/1 known vulnerability finding/)).toBeVisible();
    expect(screen.getByText(/CRITICAL/)).toBeVisible();
    expect(screen.getByText(/openssl @ 1.1.1/)).toBeVisible();
    expect(screen.getByText(/Buffer overflow vulnerability/)).toBeVisible();
    expect(screen.getByText(/42 package\(s\)/)).toBeVisible();
    expect(screen.getByRole("link", { name: /Download SBOM/ })).toHaveAttribute(
      "href",
      "http://localhost:8080/api/v1/catalog/apps/org.example.Test/releases/pub-1/sbom/download",
    );
  });
});
