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
} from "../components/store";
import { ThemeToggle } from "../components/theme";
import Loading from "../app/loading";
import ErrorPage from "../app/error";
import { commitLink, type Card, type Release } from "../lib/catalog";
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
});
