//! Durable bounded security and trust supervisor.
//! Analyses successful publications, extracts permissions, computes diffs,
//! generates canonical SPDX 2.3 SBOMs, and performs vulnerability matching.
use crate::store::Store;
use chrono::Utc;
use librehub_common::{
    BuildRecord, FlatpakManifest, PublishRecord, PublishStatus, ReleaseSecurityDetails,
    ReleaseSecurityState, SbomPackage, SecurityTimestamps, VulnerabilitiesStatus,
    VulnerabilityCounts,
};
use librehub_publisher::repository::RepositoryConfig;
use librehub_security::{SbomInput, default_provider};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct SecurityWorker {
    pub store: Store,
    pub repository: Option<RepositoryConfig>,
    pub running: Arc<AtomicBool>,
    pub shutdown: CancellationToken,
}

impl SecurityWorker {
    pub fn new(
        store: Store,
        repository: Option<RepositoryConfig>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            store,
            repository,
            running: Arc::new(AtomicBool::new(false)),
            shutdown,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        self.store.security_recover().await?;
        self.running.store(true, Ordering::Release);
        let result = self.supervise().await;
        self.running.store(false, Ordering::Release);
        if result.is_err() {
            self.shutdown.cancel();
        }
        result
    }

    async fn supervise(&self) -> anyhow::Result<()> {
        while !self.shutdown.is_cancelled() {
            if let Some(repository) = &self.repository
                && let Some(publication) = self.store.security_claim().await?
            {
                let analysis = self.process_publication(publication.clone(), repository.clone());
                let result = tokio::select! {
                    _ = self.shutdown.cancelled() => return Ok(()),
                    res = tokio::time::timeout(Duration::from_secs(300), analysis) => res,
                };

                match result {
                    Ok(Ok(())) => {
                        tracing::info!(publication_id=%publication.id, "Security analysis completed successfully");
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(publication_id=%publication.id, %error, "Security analysis failed; recording failure");
                        let _ = self
                            .store
                            .security_failed(
                                &publication.id,
                                &publication.app_id,
                                &publication.channel.to_string(),
                                "analysis_error",
                                &error.to_string(),
                            )
                            .await;
                    }
                    Err(_) => {
                        tracing::warn!(publication_id=%publication.id, "Security analysis timed out; recording failure");
                        let _ = self
                            .store
                            .security_failed(
                                &publication.id,
                                &publication.app_id,
                                &publication.channel.to_string(),
                                "timeout",
                                "Security analysis timed out",
                            )
                            .await;
                    }
                }
                continue;
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
        Ok(())
    }

    async fn process_publication(
        &self,
        publication: PublishRecord,
        repository: RepositoryConfig,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            publication.status == PublishStatus::Succeeded,
            "Only successful publications can be analyzed"
        );

        // 1. Fetch Build and Manifest
        let mut attempts = 0;
        let (build, manifest) = loop {
            let lookup = async {
                let Some(b) = self.store.get(publication.build_id).await? else {
                    return Ok(None);
                };
                let m = self.store.manifest(publication.build_id).await?;
                Ok::<_, anyhow::Error>(Some((b, m)))
            }
            .await;

            attempts += 1;
            match lookup {
                Ok(Some(source)) => break source,
                Ok(None) => anyhow::bail!("Publication source build missing"),
                Err(err) if attempts < 3 => {
                    tracing::warn!(publication_id=%publication.id, %err, "Build lookup failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(err) => return Err(err),
            }
        };

        // 2. Extract /metadata text
        let metadata_text = extract_metadata_text(
            self.store.data_dir.clone(),
            &build,
            &manifest,
            &publication,
            &repository,
        )
        .await;

        // 3. Extract and snapshot permissions
        let snapshot = librehub_security::parse_permission_snapshot(&metadata_text)?;

        // 4. Compare with previous stable release
        let prev = self
            .store
            .get_previous_stable_permissions(
                &publication.app_id,
                &publication.channel.to_string(),
                &publication.id.to_string(),
            )
            .await?;

        let (prev_id, prev_snap) = match prev {
            Some((id, s)) => (Some(id), Some(s)),
            None => (None, None),
        };

        let diff = librehub_security::diff_permissions(
            prev_id,
            publication.id.to_string(),
            prev_snap.as_ref(),
            &snapshot,
            Utc::now(),
        );

        // 5. Build SbomPackage list for modules
        let mut additional_modules = Vec::new();
        for m in &manifest.modules {
            let ver = m
                .options
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let mut hashes = BTreeMap::new();
            let mut src_url = None;
            for s in &m.sources {
                if let Some(url) = s.options.get("url").and_then(|v| v.as_str()) {
                    src_url = Some(url.to_string());
                }
                if let Some(sha) = s.options.get("sha256").and_then(|v| v.as_str()) {
                    hashes.insert("SHA256".to_string(), sha.to_string());
                }
            }
            additional_modules.push(SbomPackage {
                name: m.name.clone(),
                version: ver,
                package_type: "library".to_string(),
                purl: Some(format!("pkg:generic/{}", m.name)),
                license: None,
                source: src_url,
                hashes,
                scope: "direct".to_string(),
            });
        }

        let checksum = publication
            .result
            .as_ref()
            .map(|r| r.published_ref.commit.clone())
            .unwrap_or_default();
        let source_commit = build
            .provenance
            .as_ref()
            .map(|p| p.revision.commit.as_str());

        let sbom_input = SbomInput {
            publication_id: &publication.id,
            app_id: &publication.app_id,
            version: &manifest.runtime_version,
            ostree_checksum: &checksum,
            source_commit,
            license: None,
            metadata_text: Some(&metadata_text),
            additional_modules,
        };

        let spdx_doc = librehub_security::generate_spdx_document(sbom_input);
        let (sbom_rel_path, sbom_sha256, sbom_comp_count) = librehub_security::write_sbom_artifact(
            &self.store.data_dir,
            &publication.id,
            &spdx_doc,
        )
        .await?;

        // 6. Vulnerability Matching
        let provider = default_provider();
        let (findings, vuln_status, vuln_checked_at) = match provider
            .check_packages(&spdx_doc.packages)
            .await
        {
            Ok(findings) => {
                let now = Utc::now();
                let status = if findings.is_empty() {
                    VulnerabilitiesStatus::Clean
                } else {
                    VulnerabilitiesStatus::Vulnerable
                };
                (findings, status, Some(now))
            }
            Err(err) => {
                tracing::warn!(publication_id=%publication.id, %err, "Vulnerability check unavailable");
                (Vec::new(), VulnerabilitiesStatus::Unavailable, None)
            }
        };

        let now = Utc::now();
        let counts = VulnerabilityCounts::from_findings(&findings);
        let perm_sev = diff.severity;

        let details = ReleaseSecurityDetails {
            publication_id: publication.id,
            app_id: publication.app_id.clone(),
            channel: publication.channel.to_string(),
            status: ReleaseSecurityState::Ready,
            sbom_format: "SPDX-2.3".to_string(),
            sbom_component_count: sbom_comp_count,
            sbom_sha256,
            sbom_download_url: format!(
                "/api/v1/catalog/apps/{}/releases/{}/sbom/download",
                publication.app_id, publication.id
            ),
            sbom_path: Some(sbom_rel_path),
            vulnerabilities_status: vuln_status,
            vulnerabilities_checked_at: vuln_checked_at,
            vulnerability_counts: counts,
            findings: findings.clone(),
            permissions_extracted_at: now,
            permission_severity: perm_sev,
            permission_diff: Some(diff.clone()),
            timestamps: SecurityTimestamps {
                sbom_generated_at: now,
                vulnerabilities_checked_at: vuln_checked_at,
                permissions_extracted_at: now,
            },
        };

        self.store
            .security_commit(details, snapshot, diff, findings)
            .await?;

        Ok(())
    }

    pub async fn ready(&self) -> bool {
        self.repository.is_some() && self.running.load(Ordering::Acquire)
    }
}

async fn extract_metadata_text(
    data_dir: PathBuf,
    build: &BuildRecord,
    manifest: &FlatpakManifest,
    publication: &PublishRecord,
    repository: &RepositoryConfig,
) -> String {
    if let Some(ref result) = publication.result
        && let Ok(prepared) = librehub_publisher::artifact::prepare(
            data_dir,
            build.clone(),
            manifest.clone(),
            publication.architecture,
            Duration::from_secs(60),
        )
        .await
    {
        let signed = format!(
            "--repo={}",
            prepared.workspace.path().join("signed").display()
        );
        let key = prepared.workspace.path().join("catalog-public.gpg");
        if tokio::fs::write(&key, &repository.public_key).await.is_ok() {
            let init = tokio::process::Command::new("ostree")
                .args([&signed, "init", "--mode=archive-z2"])
                .output()
                .await;
            if init.is_ok() {
                let remote = tokio::process::Command::new("ostree")
                    .args([
                        &signed,
                        "remote",
                        "add",
                        "--set=gpg-verify=true",
                        "--set=gpg-verify-summary=true",
                        &format!("--gpg-import={}", key.display()),
                        "librehub",
                        &repository.url(publication.channel),
                    ])
                    .output()
                    .await;
                if remote.is_ok() {
                    let pull = tokio::process::Command::new("ostree")
                        .args([
                            &signed,
                            "pull",
                            "--subpath=/metadata",
                            "librehub",
                            &result.published_ref.commit,
                        ])
                        .output()
                        .await;
                    if pull.is_ok() {
                        let cat_res = tokio::process::Command::new("ostree")
                            .args([&signed, "cat", &result.published_ref.commit, "/metadata"])
                            .output()
                            .await;
                        if let Ok(out) = cat_res
                            && out.status.success()
                            && let Ok(text) = String::from_utf8(out.stdout)
                        {
                            return text;
                        }
                    }
                }
            }
        }

        // Fallback: read directly from prepared repo if available
        let cat_prep = tokio::process::Command::new("ostree")
            .args([
                &format!("--repo={}", prepared.path.display()),
                "cat",
                &prepared.commit,
                "/metadata",
            ])
            .output()
            .await;
        if let Ok(out) = cat_prep
            && out.status.success()
            && let Ok(text) = String::from_utf8(out.stdout)
        {
            return text;
        }
    }

    // Fallback: reconstruct metadata ini from manifest finish_args
    let app_id = &publication.app_id;
    let mut lines = vec![
        "[Application]".to_string(),
        format!("name={app_id}"),
        format!("runtime={}", manifest.runtime),
        format!("sdk={}", manifest.sdk),
        format!("command={}", manifest.command),
        "".to_string(),
        "[Context]".to_string(),
    ];
    let mut filesystems = Vec::new();
    let mut sockets = Vec::new();
    let mut shared = Vec::new();
    let mut devices = Vec::new();
    for (k, v) in &manifest.options {
        if k == "finish-args"
            && let Some(arr) = v.as_array()
        {
            for item in arr {
                if let Some(arg) = item.as_str() {
                    if let Some(fs) = arg.strip_prefix("--filesystem=") {
                        filesystems.push(fs.to_string());
                    } else if let Some(sock) = arg.strip_prefix("--socket=") {
                        sockets.push(sock.to_string());
                    } else if let Some(sh) = arg.strip_prefix("--share=") {
                        shared.push(sh.to_string());
                    } else if let Some(dev) = arg.strip_prefix("--device=") {
                        devices.push(dev.to_string());
                    }
                }
            }
        }
    }
    if !filesystems.is_empty() {
        lines.push(format!("filesystems={}", filesystems.join(";")));
    }
    if !sockets.is_empty() {
        lines.push(format!("sockets={}", sockets.join(";")));
    }
    if !shared.is_empty() {
        lines.push(format!("shared={}", shared.join(";")));
    }
    if !devices.is_empty() {
        lines.push(format!("devices={}", devices.join(";")));
    }
    lines.join("\n")
}
