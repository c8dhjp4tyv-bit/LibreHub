import { publicApiBase, type Release, type SupplyChainEvidence } from "../lib/catalog";
export function BuildProvenance({ release, evidence }: { release: Release; evidence: SupplyChainEvidence | null }) {
  const build = evidence?.build?.predicate;
  const env = build?.buildDefinition?.internalParameters;
  const labels: Record<string, string> = {
    reproduced: "Rebuild matched", non_reproducible: "Rebuild differed",
    inconclusive: "Rebuild inconclusive", unsupported: "Rebuild unsupported", not_checked: "Rebuild not checked",
  };
  const verified = evidence?.status === "verified" && evidence.verification.verified;
  return <section aria-label="Build provenance">
    <h2>Build provenance</h2>
    <p>{verified ? "Provenance verified" : evidence?.status === "failed" ? "Attestation verification failed" : "Attestation unavailable"}</p>
    {evidence?.status === "legacy_unattested" && <p>This historical release has no build-time attestation.</p>}
    <dl>
      <dt>Source commit</dt><dd><code>{build?.buildDefinition?.externalParameters?.source?.revision?.commit || release.source_commit || "Unavailable"}</code></dd>
      <dt>Builder identity</dt><dd><code>{build?.runDetails?.builder?.id || "Unavailable"}</code></dd>
      <dt>Build completed</dt><dd>{build?.runDetails?.metadata?.finishedOn || "Unavailable"}</dd>
      <dt>Worker image configuration digest</dt><dd><code>{env?.imageConfigDigest || "Unavailable"}</code></dd>
      <dt>Build artifact SHA-256</dt><dd><code>{evidence?.build?.subject?.[0]?.digest?.sha256 || "Unavailable"}</code></dd>
      <dt>Final signed OSTree commit</dt><dd><code>{release.ostree_checksum}</code></dd>
      <dt>Reproducibility</dt><dd>{labels[evidence?.reproducibility || "not_checked"] || "Rebuild not checked"}</dd>
      <dt>Isolation profile</dt><dd>{env?.isolation || "Not recorded"}</dd>
    </dl>
    <p className="muted">Build environment not independently verified. Signatures confirm the attestor&apos;s recorded evidence; they do not establish malware absence or universal reproducibility.</p>
    {verified && <a href={`${publicApiBase.replace(/\/$/, "")}/api/v1/catalog/apps/${encodeURIComponent(release.flatpak_ref.split("/")[1])}/releases/${encodeURIComponent(release.publication_id)}/attestation/download`} download>Download attestation</a>}
    {release.security?.sbom_download_url && <p><a href={release.security.sbom_download_url}>Download SPDX SBOM</a></p>}
  </section>;
}
