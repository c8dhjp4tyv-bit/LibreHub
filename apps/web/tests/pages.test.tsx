import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { Card, App } from "../lib/catalog";
const { getCatalog } = vi.hoisted(() => ({ getCatalog: vi.fn() }));
vi.mock("../lib/catalog", async () => ({
  ...(await vi.importActual("../lib/catalog")),
  getCatalog,
}));
vi.mock("next/navigation", () => ({
  notFound: () => {
    throw new Error("NOT_FOUND");
  },
}));
const card: Card = {
  app_id: "org.example.Test",
  slug: "org.example.Test",
  name: "Live Catalog App",
  summary: "Read from the API",
  icon: null,
  publisher: { id: "dev", display_name: "Publisher" },
  project_id: "project",
  source_url: "https://github.com/example/test",
  categories: ["Utility"],
  architectures: ["x86_64"],
  channel: "stable",
  archived: false,
  updated_at: "2026-01-01T00:00:00Z",
  published_at: "2026-01-01T00:00:00Z",
};
const release = {
  publication_id: "publication",
  build_id: "build",
  source_commit: "a".repeat(40),
  source_url: card.source_url,
  channel: "stable" as const,
  architecture: "x86_64",
  flatpak_ref: "app/org.example.Test/x86_64/master",
  ostree_checksum: "b".repeat(64),
  published_at: card.published_at,
  version: "2.0",
  release_notes: "",
  permissions: {
    network: false,
    filesystem: [],
    devices: [],
    sockets: ["wayland"],
    dbus: [],
    shared: [],
    other: [],
  },
};
const page = { items: [card], total: 1, offset: 0, limit: 24 };
describe("server pages consume catalog DTOs", () => {
  it("home renders API catalog sections", async () => {
    getCatalog.mockImplementation((p: string) =>
      Promise.resolve(
        p.includes("categories") ? [{ id: "Utility", count: 1 }] : page,
      ),
    );
    const { default: Home } = await import("../app/page");
    render(await Home());
    expect(
      screen.getByRole("heading", { name: "Recently updated" }),
    ).toBeVisible();
    expect(screen.getAllByText("Live Catalog App")).toHaveLength(2);
    expect(getCatalog).toHaveBeenCalledWith(
      "/api/v1/catalog/apps?limit=6&sort=recently_updated",
    );
  });
  it("search calls the server search API with the URL query", async () => {
    getCatalog.mockResolvedValue(page);
    const { default: Search } = await import("../app/search/page");
    render(await Search({ searchParams: Promise.resolve({ q: "Live" }) }));
    expect(getCatalog).toHaveBeenCalledWith("/api/v1/catalog/search?q=Live");
    expect(screen.getByRole("textbox")).toHaveValue("Live");
  });
  it("app detail shows actual release, install action and source", async () => {
    const app: App = {
      ...card,
      description: "An actual description",
      screenshots: [],
      homepage: null,
      license: "MIT",
      developer_name: null,
      content_rating: [],
      current_stable_release: release,
      current_beta_release: null,
      current_releases: [release],
      install: {
        remote: "librehub",
        remote_descriptor_url: "https://repo.example.com/librehub.flatpakrepo",
        flatpakref_url: "https://api.example.com/app.flatpakref",
        command: "flatpak install --user librehub org.example.Test",
      },
    };
    getCatalog.mockImplementation((p: string) =>
      Promise.resolve(
        p.includes("/releases")
          ? { items: [release], total: 1, limit: 24, offset: 0 }
          : app,
      ),
    );
    const { default: Detail } = await import("../app/apps/[app_id]/page");
    render(
      await Detail({
        params: Promise.resolve({ app_id: card.app_id }),
        searchParams: Promise.resolve({}),
      }),
    );
    expect(
      screen.getByRole("heading", { name: "Live Catalog App", level: 1 }),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: /Install with Flatpak/ }),
    ).toHaveAttribute("href", app.install.flatpakref_url);
    expect(screen.getByText("MIT")).toBeVisible();
    expect(screen.getAllByText("2.0").length).toBeGreaterThan(0);
  });
  it("missing app follows a friendly 404 boundary", async () => {
    getCatalog.mockResolvedValue(null);
    const { default: Detail } = await import("../app/apps/[app_id]/page");
    await expect(
      Detail({
        params: Promise.resolve({ app_id: "org.example.Missing" }),
        searchParams: Promise.resolve({}),
      }),
    ).rejects.toThrow("NOT_FOUND");
  });
});
