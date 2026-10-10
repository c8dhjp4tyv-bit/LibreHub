import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { BuildProvenance } from "../components/build-provenance";
import type { Release, SupplyChainEvidence } from "../lib/catalog";
const release = { publication_id: "release", flatpak_ref: "app/org.example.Test/x86_64/master", ostree_checksum: "a".repeat(64), source_commit: null } as Release;
describe("supply-chain claims", () => {
  it("labels missing evidence without claiming verification", () => {
    render(<BuildProvenance release={release} evidence={null} />);
    expect(screen.getByText("Attestation unavailable")).toBeVisible();
    expect(screen.getByText("Rebuild not checked")).toBeVisible();
    expect(screen.queryByText("Download attestation")).toBeNull();
  });
  it("does not display a verified label when signature evaluation failed", () => {
    const evidence = { status: "verified", verification: { verified: false }, reproducibility: "non_reproducible", build: null } as SupplyChainEvidence;
    render(<BuildProvenance release={release} evidence={evidence} />);
    expect(screen.getByText("Attestation unavailable")).toBeVisible();
    expect(screen.getByText("Rebuild differed")).toBeVisible();
    expect(screen.queryByText("Provenance verified")).toBeNull();
  });
});
