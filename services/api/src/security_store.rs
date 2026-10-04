//! Trust, Security, Moderation, and Verification persistence layer.
use crate::store::Store;
use anyhow::{Context, ensure};
use chrono::Utc;
use librehub_common::*;
use librehub_security::{
    CHALLENGE_PREFIX, CHALLENGE_TTL_SECS, DnsResolver, generate_challenge_token,
    validate_domain_syntax, verify_domain_txt,
};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

impl Store {
    // ------------------------------------------------------------------------
    // Publisher Domain Verification
    // ------------------------------------------------------------------------

    pub async fn request_domain_verification(
        &self,
        developer_id: &DeveloperId,
        domain: &str,
        method: VerificationMethod,
    ) -> anyhow::Result<DomainVerification> {
        let domain = validate_domain_syntax(domain)?;
        let dev_id = *developer_id;
        let dev_id_str = dev_id.to_string();
        let token = generate_challenge_token();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
        let id = VerificationId::new();

        self.run(move |db| {
            let tx = db.transaction()?;
            // Check if another developer already has active verified status on this domain
            let existing_verified: Option<String> = tx
                .query_row(
                    "SELECT developer_id FROM publisher_verifications WHERE domain=?1 AND status='verified'",
                    [&domain],
                    |r| r.get(0),
                )
                .optional()?;

            if let Some(other_dev) = existing_verified {
                ensure!(
                    other_dev == dev_id_str,
                    "Domain '{domain}' is already verified by another publisher"
                );
            }

            let id_str = id.to_string();
            tx.execute(
                "INSERT INTO publisher_verifications(id, developer_id, domain, method, challenge_token, challenge_expires_at, status, created_at, updated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
                params![
                    id_str,
                    dev_id_str,
                    domain,
                    method.to_string(),
                    token,
                    expires_at.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )?;

            tx.execute(
                "INSERT INTO audit_events(developer_id, action, project_id, target_id, timestamp, result)
                 VALUES(?1, 'domain_verification_requested', NULL, ?2, ?3, 'pending')",
                params![dev_id_str, id_str, now.to_rfc3339()],
            )?;

            tx.commit()?;

            Ok(DomainVerification {
                id,
                developer_id: dev_id,
                domain,
                method,
                challenge_token: Some(token),
                challenge_expires_at: expires_at,
                status: PublisherVerificationStatus::Pending,
                verified_at: None,
                revoked_at: None,
                created_at: now,
                updated_at: now,
            })
        })
        .await
    }

    pub async fn list_domain_verifications(
        &self,
        developer_id: &DeveloperId,
    ) -> anyhow::Result<Vec<DomainVerification>> {
        let dev_id_str = developer_id.to_string();
        self.run(move |db| {
            let mut stmt = db.prepare(
                "SELECT id, developer_id, domain, method, challenge_token, challenge_expires_at, status, verified_at, revoked_at, created_at, updated_at
                 FROM publisher_verifications WHERE developer_id=?1 ORDER BY created_at DESC",
            )?;
            let rows = stmt
                .query_map([&dev_id_str], |r| {
                    let id_str: String = r.get(0)?;
                    let dev_str: String = r.get(1)?;
                    let method_str: String = r.get(3)?;
                    let status_str: String = r.get(6)?;
                    let exp_str: String = r.get(5)?;
                    let ver_str: Option<String> = r.get(7)?;
                    let rev_str: Option<String> = r.get(8)?;
                    let created_str: String = r.get(9)?;
                    let updated_str: String = r.get(10)?;

                    Ok((
                        id_str,
                        dev_str,
                        r.get::<_, String>(2)?,
                        method_str,
                        r.get::<_, Option<String>>(4)?,
                        exp_str,
                        status_str,
                        ver_str,
                        rev_str,
                        created_str,
                        updated_str,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut out = Vec::new();
            for (id_str, dev_str, domain, method_str, challenge_token, exp_str, status_str, ver_str, rev_str, created_str, updated_str) in rows {
                out.push(DomainVerification {
                    id: VerificationId::from_str(&id_str)?,
                    developer_id: DeveloperId::from_str(&dev_str)?,
                    domain,
                    method: method_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    challenge_token,
                    challenge_expires_at: exp_str.parse()?,
                    status: status_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    verified_at: ver_str.map(|s| s.parse()).transpose()?,
                    revoked_at: rev_str.map(|s| s.parse()).transpose()?,
                    created_at: created_str.parse()?,
                    updated_at: updated_str.parse()?,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn check_domain_verification(
        &self,
        developer_id: &DeveloperId,
        verification_id: &VerificationId,
        resolver: &dyn DnsResolver,
    ) -> anyhow::Result<DomainVerification> {
        let dev_id_str = developer_id.to_string();
        let ver_id_str = verification_id.to_string();

        let (domain, _method, challenge_token, expires_at, status) = self
            .run({
                let dev_id_str = dev_id_str.clone();
                let ver_id_str = ver_id_str.clone();
                move |db| {
                    let mut stmt = db.prepare(
                        "SELECT domain, method, challenge_token, challenge_expires_at, status
                         FROM publisher_verifications WHERE id=?1 AND developer_id=?2",
                    )?;
                    let res: Option<(String, String, Option<String>, String, String)> = stmt
                        .query_row(params![ver_id_str, dev_id_str], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                        })
                        .optional()?;
                    res.context("Verification record not found")
                }
            })
            .await?;

        let status_parsed: PublisherVerificationStatus =
            status.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
        let expires_at_parsed: Timestamp = expires_at.parse()?;
        let now = Utc::now();

        if now > expires_at_parsed {
            self.run({
                let ver_id_str = ver_id_str.clone();
                move |db| {
                    db.execute(
                        "UPDATE publisher_verifications SET status='expired', updated_at=?2 WHERE id=?1",
                        params![ver_id_str, now.to_rfc3339()],
                    )?;
                    Ok(())
                }
            })
            .await?;
            anyhow::bail!("Verification challenge has expired. Please request a new verification.");
        }

        if status_parsed == PublisherVerificationStatus::Verified {
            // Already verified
            let list = self.list_domain_verifications(developer_id).await?;
            return list
                .into_iter()
                .find(|v| v.id == *verification_id)
                .context("Record not found");
        }

        let token = challenge_token.context("Challenge token not found")?;

        // Perform DNS check
        let is_verified = verify_domain_txt(resolver, &domain, &token)
            .await
            .context("DNS TXT query failed")?;

        if !is_verified {
            anyhow::bail!(
                "DNS verification TXT record '{CHALLENGE_PREFIX}{token}' was not found for domain '{domain}'"
            );
        }

        // Successfully verified: persist
        self.run({
            let ver_id_str = ver_id_str.clone();
            let dev_id_str = dev_id_str.clone();
            move |db| {
                let tx = db.transaction()?;
                tx.execute(
                    "UPDATE publisher_verifications
                     SET status='verified', verified_at=?2, challenge_token=NULL, updated_at=?2
                     WHERE id=?1",
                    params![ver_id_str, now.to_rfc3339()],
                )?;
                tx.execute(
                    "INSERT INTO audit_events(developer_id, action, project_id, target_id, timestamp, result)
                     VALUES(?1, 'domain_verified', NULL, ?2, ?3, 'succeeded')",
                    params![dev_id_str, ver_id_str, now.to_rfc3339()],
                )?;
                tx.commit()?;
                Ok(())
            }
        })
        .await?;

        let list = self.list_domain_verifications(developer_id).await?;
        list.into_iter()
            .find(|v| v.id == *verification_id)
            .context("Record not found")
    }

    pub async fn revoke_domain_verification(
        &self,
        developer_id: &DeveloperId,
        verification_id: &VerificationId,
    ) -> anyhow::Result<()> {
        let dev_id_str = developer_id.to_string();
        let ver_id_str = verification_id.to_string();
        let now = Utc::now();

        self.run(move |db| {
            let tx = db.transaction()?;
            let rows = tx.execute(
                "UPDATE publisher_verifications
                 SET status='revoked', revoked_at=?3, challenge_token=NULL, updated_at=?3
                 WHERE id=?1 AND developer_id=?2",
                params![ver_id_str, dev_id_str, now.to_rfc3339()],
            )?;
            ensure!(rows > 0, "Verification record not found");
            tx.execute(
                "INSERT INTO audit_events(developer_id, action, project_id, target_id, timestamp, result)
                 VALUES(?1, 'domain_revoked', NULL, ?2, ?3, 'succeeded')",
                params![dev_id_str, ver_id_str, now.to_rfc3339()],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn get_publisher_verification_info(
        &self,
        developer_id: &str,
    ) -> anyhow::Result<Option<DomainVerification>> {
        let dev_str = developer_id.to_string();
        self.run(move |db| {
            let mut stmt = db.prepare(
                "SELECT id, developer_id, domain, method, challenge_token, challenge_expires_at, status, verified_at, revoked_at, created_at, updated_at
                 FROM publisher_verifications
                 WHERE developer_id=?1 AND status='verified'
                 ORDER BY verified_at DESC LIMIT 1",
            )?;
            let row = stmt
                .query_row([&dev_str], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, Option<String>>(8)?,
                        r.get::<_, String>(9)?,
                        r.get::<_, String>(10)?,
                    ))
                })
                .optional()?;

            if let Some((id_str, dev_str, domain, method_str, challenge_token, exp_str, status_str, ver_str, rev_str, created_str, updated_str)) = row {
                Ok(Some(DomainVerification {
                    id: VerificationId::from_str(&id_str)?,
                    developer_id: DeveloperId::from_str(&dev_str)?,
                    domain,
                    method: method_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    challenge_token,
                    challenge_expires_at: exp_str.parse()?,
                    status: status_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    verified_at: ver_str.map(|s| s.parse()).transpose()?,
                    revoked_at: rev_str.map(|s| s.parse()).transpose()?,
                    created_at: created_str.parse()?,
                    updated_at: updated_str.parse()?,
                }))
            } else {
                Ok(None)
            }
        })
        .await
    }

    // ------------------------------------------------------------------------
    // Security Background Jobs
    // ------------------------------------------------------------------------

    pub async fn security_recover(&self) -> anyhow::Result<()> {
        self.run(|db| {
            db.execute(
                "UPDATE security_jobs SET state='pending' WHERE state='analyzing'",
                [],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn security_claim(&self) -> anyhow::Result<Option<PublishRecord>> {
        self.run(|db| {
            let tx = db.transaction()?;
            // Enqueue up to 64 completed publications not yet processed
            tx.execute(
                "INSERT INTO security_jobs(publication_id, state, updated_at)
                 SELECT p.id, 'pending', json_extract(p.record, '$.updated_at')
                 FROM publishes p
                 WHERE p.status='succeeded' AND NOT EXISTS(
                     SELECT 1 FROM security_jobs s WHERE s.publication_id=p.id
                 )
                 ORDER BY p.rowid
                 LIMIT max(0, 64 - (SELECT count(*) FROM security_jobs WHERE state IN ('pending', 'analyzing')))",
                [],
            )?;

            let raw: Option<String> = tx
                .query_row(
                    "SELECT p.record FROM security_jobs s
                     JOIN publishes p ON p.id = s.publication_id
                     WHERE s.state='pending' AND p.status='succeeded'
                     ORDER BY p.rowid LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;

            let publication: Option<PublishRecord> = raw.map(|r| serde_json::from_str(&r)).transpose()?;
            if let Some(p) = &publication {
                tx.execute(
                    "UPDATE security_jobs SET state='analyzing', attempts = attempts + 1, updated_at=?2
                     WHERE publication_id=?1 AND state='pending'",
                    params![p.id.to_string(), chrono::Utc::now().to_rfc3339()],
                )?;
            }
            tx.commit()?;
            Ok(publication)
        })
        .await
    }

    pub async fn security_failed(
        &self,
        publication_id: &PublishId,
        app_id: &str,
        channel: &str,
        error_code: &str,
        error_message: &str,
    ) -> anyhow::Result<()> {
        let pub_id_str = publication_id.to_string();
        let app_id_str = app_id.to_string();
        let channel_str = channel.to_string();
        let err_code_str = error_code.to_string();
        let err_msg_str = error_message.to_string();
        let now = Utc::now();

        self.run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE security_jobs SET state='failed', error_code=?2, error_message=?3, updated_at=?4
                 WHERE publication_id=?1",
                params![pub_id_str, err_code_str, err_msg_str, now.to_rfc3339()],
            )?;

            // Record security status as 'unavailable' so release remains visible without corrupting publication
            tx.execute(
                "INSERT INTO release_security(
                     publication_id, app_id, channel, status, sbom_format, sbom_path,
                     sbom_component_count, sbom_sha256, vulnerabilities_status, permissions_extracted_at,
                     permission_severity, created_at, updated_at
                 ) VALUES(?1, ?2, ?3, 'unavailable', 'spdx-2.3-json', '', 0, '', 'unavailable', ?4, 'none', ?4, ?4)
                 ON CONFLICT(publication_id) DO UPDATE SET
                     status='unavailable', vulnerabilities_status='unavailable', updated_at=excluded.updated_at",
                params![pub_id_str, app_id_str, channel_str, now.to_rfc3339()],
            )?;

            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn security_commit(
        &self,
        details: ReleaseSecurityDetails,
        snapshot: PermissionSnapshot,
        diff: PermissionDiff,
        findings: Vec<VulnerabilityFinding>,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let pub_id_str = details.publication_id.to_string();
        let app_id_str = details.app_id.clone();
        let channel_str = details.channel.clone();

        self.run(move |db| {
            let tx = db.transaction()?;

            // 1. Release Security summary
            tx.execute(
                "INSERT INTO release_security(
                     publication_id, app_id, channel, status, sbom_format, sbom_path,
                     sbom_component_count, sbom_sha256, vulnerabilities_status, vulnerabilities_checked_at,
                     permissions_extracted_at, permission_severity, created_at, updated_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)
                 ON CONFLICT(publication_id) DO UPDATE SET
                     status=excluded.status,
                     sbom_format=excluded.sbom_format,
                     sbom_path=excluded.sbom_path,
                     sbom_component_count=excluded.sbom_component_count,
                     sbom_sha256=excluded.sbom_sha256,
                     vulnerabilities_status=excluded.vulnerabilities_status,
                     vulnerabilities_checked_at=excluded.vulnerabilities_checked_at,
                     permissions_extracted_at=excluded.permissions_extracted_at,
                     permission_severity=excluded.permission_severity,
                     updated_at=excluded.updated_at",
                params![
                    pub_id_str,
                    app_id_str,
                    channel_str,
                    details.status.to_string(),
                    details.sbom_format,
                    details.sbom_path.unwrap_or_default(),
                    details.sbom_component_count,
                    details.sbom_sha256,
                    details.vulnerabilities_status.to_string(),
                    details.timestamps.vulnerabilities_checked_at.map(|t| t.to_rfc3339()),
                    details.timestamps.permissions_extracted_at.to_rfc3339(),
                    details.permission_severity.to_string(),
                    now.to_rfc3339(),
                ],
            )?;

            // 2. Release Permissions snapshot
            tx.execute(
                "INSERT INTO release_permissions(publication_id, app_id, channel, snapshot_json, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(publication_id) DO UPDATE SET snapshot_json=excluded.snapshot_json",
                params![
                    pub_id_str,
                    app_id_str,
                    channel_str,
                    serde_json::to_string(&snapshot)?,
                    now.to_rfc3339(),
                ],
            )?;

            // 3. Permission Diff
            tx.execute(
                "INSERT INTO permission_diffs(to_publication_id, from_publication_id, app_id, channel, severity, diff_json, generated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(to_publication_id) DO UPDATE SET
                     from_publication_id=excluded.from_publication_id,
                     severity=excluded.severity,
                     diff_json=excluded.diff_json,
                     generated_at=excluded.generated_at",
                params![
                    pub_id_str,
                    diff.from_publication_id,
                    app_id_str,
                    channel_str,
                    diff.severity.to_string(),
                    serde_json::to_string(&diff)?,
                    diff.generated_at.to_rfc3339(),
                ],
            )?;

            // 4. Vulnerability findings
            tx.execute(
                "DELETE FROM vulnerability_findings WHERE publication_id=?1",
                [&pub_id_str],
            )?;
            for f in &findings {
                let id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO vulnerability_findings(id, publication_id, vulnerability_id, component_name, component_version, severity, summary, reference_url, source_provider, checked_at)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        id,
                        pub_id_str,
                        f.vulnerability_id,
                        f.component_name,
                        f.component_version,
                        f.severity.to_string(),
                        f.summary,
                        f.reference_url,
                        f.source_provider,
                        f.checked_at.to_rfc3339(),
                    ],
                )?;
            }

            // 5. Mark security job ready
            tx.execute(
                "UPDATE security_jobs SET state='ready', error_code=NULL, updated_at=?2 WHERE publication_id=?1",
                params![pub_id_str, now.to_rfc3339()],
            )?;

            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn get_previous_stable_permissions(
        &self,
        app_id: &str,
        channel: &str,
        before_publication_id: &str,
    ) -> anyhow::Result<Option<(String, PermissionSnapshot)>> {
        let app = app_id.to_string();
        let chan = channel.to_string();
        let pub_id = before_publication_id.to_string();

        self.run(move |db| {
            let row = db
                .query_row(
                    "SELECT p.publication_id, p.snapshot_json
                     FROM release_permissions p
                     JOIN publishes pub ON pub.id = p.publication_id
                     WHERE p.app_id=?1 AND p.channel=?2 AND p.publication_id != ?3 AND pub.status='succeeded'
                     ORDER BY pub.rowid DESC LIMIT 1",
                    params![app, chan, pub_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;

            if let Some((prev_pub_id, snap_raw)) = row {
                let snap: PermissionSnapshot = serde_json::from_str(&snap_raw)?;
                Ok(Some((prev_pub_id, snap)))
            } else {
                Ok(None)
            }
        })
        .await
    }

    pub async fn get_release_security_details(
        &self,
        publication_id: &PublishId,
    ) -> anyhow::Result<Option<ReleaseSecurityDetails>> {
        let pub_id = *publication_id;
        let pub_id_str = pub_id.to_string();
        self.run(move |db| {
            let row = db
                .query_row(
                    "SELECT r.app_id, r.channel, r.status, r.sbom_format, r.sbom_path, r.sbom_component_count, r.sbom_sha256,
                            r.vulnerabilities_status, r.vulnerabilities_checked_at, r.permissions_extracted_at,
                            d.diff_json
                     FROM release_security r
                     LEFT JOIN permission_diffs d ON d.to_publication_id = r.publication_id
                     WHERE r.publication_id=?1",
                    [&pub_id_str],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, u32>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, String>(7)?,
                            r.get::<_, Option<String>>(8)?,
                            r.get::<_, String>(9)?,
                            r.get::<_, Option<String>>(10)?,
                        ))
                    },
                )
                .optional()?;

            let Some((app_id, channel, status_str, sbom_format, sbom_path, sbom_component_count, sbom_sha256, vuln_status_str, vuln_checked_at, perm_extracted_at, diff_json)) = row else {
                return Ok(None);
            };

            let mut vuln_stmt = db.prepare(
                "SELECT vulnerability_id, component_name, component_version, severity, summary, reference_url, source_provider, checked_at
                 FROM vulnerability_findings WHERE publication_id=?1",
            )?;
            let findings_rows = vuln_stmt
                .query_map([&pub_id_str], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut findings = Vec::new();
            for (v_id, c_name, c_ver, sev_str, summary, ref_url, src, chk) in findings_rows {
                findings.push(VulnerabilityFinding {
                    vulnerability_id: v_id,
                    component_name: c_name,
                    component_version: c_ver,
                    severity: sev_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    summary,
                    reference_url: ref_url,
                    source_provider: src,
                    checked_at: chk.parse()?,
                });
            }

            let diff: Option<PermissionDiff> = if let Some(raw) = diff_json {
                Some(serde_json::from_str(&raw)?)
            } else {
                None
            };

            let perm_sev = diff.as_ref().map(|d| d.severity).unwrap_or(PermissionSeverity::None);
            let counts = VulnerabilityCounts::from_findings(&findings);
            let perm_extracted: Timestamp = perm_extracted_at.parse()?;
            let vuln_checked: Option<Timestamp> = vuln_checked_at.map(|s| s.parse()).transpose()?;

            Ok(Some(ReleaseSecurityDetails {
                publication_id: pub_id,
                app_id: app_id.clone(),
                channel,
                status: status_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                sbom_format,
                sbom_component_count,
                sbom_sha256,
                sbom_download_url: format!("/api/v1/catalog/apps/{app_id}/releases/{pub_id}/sbom/download"),
                sbom_path: if sbom_path.is_empty() { None } else { Some(sbom_path) },
                vulnerabilities_status: vuln_status_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                vulnerabilities_checked_at: vuln_checked,
                vulnerability_counts: counts,
                findings,
                permissions_extracted_at: perm_extracted,
                permission_severity: perm_sev,
                permission_diff: diff,
                timestamps: SecurityTimestamps {
                    sbom_generated_at: perm_extracted,
                    vulnerabilities_checked_at: vuln_checked,
                    permissions_extracted_at: perm_extracted,
                },
            }))
        })
        .await
    }

    pub async fn get_current_permissions(
        &self,
        app_id: &str,
        channel: &str,
    ) -> anyhow::Result<Option<PermissionSnapshot>> {
        let app = app_id.to_string();
        let chan = channel.to_string();
        self.run(move |db| {
            let row = db
                .query_row(
                    "SELECT snapshot_json FROM release_permissions
                     WHERE app_id=?1 AND channel=?2
                     ORDER BY rowid DESC LIMIT 1",
                    [&app, &chan],
                    |r| r.get::<_, String>(0),
                )
                .optional()?;
            if let Some(raw) = row {
                Ok(Some(serde_json::from_str(&raw)?))
            } else {
                Ok(None)
            }
        })
        .await
    }

    pub async fn get_permission_history(
        &self,
        app_id: &str,
        channel: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<PermissionDiff>> {
        let app = app_id.to_string();
        let chan = channel.to_string();
        let limit = limit.min(50);

        self.run(move |db| {
            let mut stmt = db.prepare(
                "SELECT diff_json FROM permission_diffs
                 WHERE app_id=?1 AND channel=?2
                 ORDER BY generated_at DESC LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(params![app, chan, limit as i64], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;

            let mut out = Vec::new();
            for raw in rows {
                out.push(serde_json::from_str(&raw)?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn read_sbom_file(
        &self,
        data_dir: &Path,
        publication_id: &PublishId,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let pub_id_str = publication_id.to_string();
        let path: Option<String> = self
            .run(move |db| {
                let opt = db
                    .query_row(
                        "SELECT sbom_path FROM release_security WHERE publication_id=?1",
                        [&pub_id_str],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(opt)
            })
            .await?;

        let Some(rel_path) = path else {
            return Ok(None);
        };
        if rel_path.is_empty() {
            return Ok(None);
        }

        // Secure path validation: ensure it stays within data_dir
        let full_path = data_dir.join(&rel_path);
        let canonical_dir = tokio::fs::canonicalize(data_dir).await?;
        let canonical_file = tokio::fs::canonicalize(&full_path).await?;
        ensure!(
            canonical_file.starts_with(&canonical_dir),
            "Path traversal rejected"
        );

        let bytes = tokio::fs::read(&canonical_file).await?;
        Ok(Some(bytes))
    }

    // ------------------------------------------------------------------------
    // Moderation
    // ------------------------------------------------------------------------

    pub async fn apply_moderation(
        &self,
        app_id: &str,
        action: ModerationAction,
        reason: ModerationReason,
        public_note: Option<String>,
        internal_note: Option<String>,
        operator: &str,
    ) -> anyhow::Result<ModerationEvent> {
        let app = app_id.to_string();
        let target_state = action.target_state();
        let op = operator.to_string();
        let now = Utc::now();

        self.run(move |db| {
            let tx = db.transaction()?;

            let current_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM catalog_moderation WHERE app_id=?1",
                    [&app],
                    |r| r.get(0),
                )
                .optional()?;

            let from_state = current_state
                .map(|s| s.parse::<ModerationState>().map_err(|e| anyhow::anyhow!("{e}")))
                .transpose()?
                .unwrap_or(ModerationState::Normal);

            tx.execute(
                "INSERT INTO catalog_moderation(app_id, state, reason_code, public_note, internal_note, operator, updated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(app_id) DO UPDATE SET
                     state=excluded.state,
                     reason_code=excluded.reason_code,
                     public_note=excluded.public_note,
                     internal_note=excluded.internal_note,
                     operator=excluded.operator,
                     updated_at=excluded.updated_at",
                params![
                    app,
                    target_state.to_string(),
                    reason.to_string(),
                    public_note,
                    internal_note,
                    op,
                    now.to_rfc3339(),
                ],
            )?;

            tx.execute(
                "INSERT INTO moderation_events(app_id, action, from_state, to_state, reason_code, public_note, internal_note, operator, timestamp)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    app,
                    action.to_string(),
                    from_state.to_string(),
                    target_state.to_string(),
                    reason.to_string(),
                    public_note,
                    internal_note,
                    op,
                    now.to_rfc3339(),
                ],
            )?;

            let event_id = tx.last_insert_rowid();
            tx.commit()?;

            Ok(ModerationEvent {
                id: event_id,
                app_id: app,
                action,
                from_state,
                to_state: target_state,
                reason,
                public_note,
                internal_note,
                operator: op,
                timestamp: now,
            })
        })
        .await
    }

    pub async fn get_moderation_state(
        &self,
        app_id: &str,
    ) -> anyhow::Result<Option<(ModerationState, String, Option<String>)>> {
        let app = app_id.to_string();
        self.run(move |db| {
            let row = db
                .query_row(
                    "SELECT state, reason_code, public_note FROM catalog_moderation WHERE app_id=?1",
                    [&app],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)),
                )
                .optional()?;

            if let Some((state_str, reason_str, note)) = row {
                let st = state_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(Some((st, reason_str, note)))
            } else {
                Ok(None)
            }
        })
        .await
    }

    pub async fn get_moderation_history(
        &self,
        app_id: &str,
    ) -> anyhow::Result<Vec<ModerationEvent>> {
        let app = app_id.to_string();
        self.run(move |db| {
            let mut stmt = db.prepare(
                "SELECT id, app_id, action, from_state, to_state, reason_code, public_note, internal_note, operator, timestamp
                 FROM moderation_events WHERE app_id=?1 ORDER BY timestamp DESC",
            )?;
            let rows = stmt
                .query_map([&app], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, String>(9)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut out = Vec::new();
            for (id, app_id, action_str, from_str, to_str, reason_str, pub_note, int_note, op, ts_str) in rows {
                out.push(ModerationEvent {
                    id,
                    app_id,
                    action: action_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    from_state: from_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    to_state: to_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    reason: reason_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    public_note: pub_note,
                    internal_note: int_note,
                    operator: op,
                    timestamp: ts_str.parse()?,
                });
            }
            Ok(out)
        })
        .await
    }

    // ------------------------------------------------------------------------
    // User Reports
    // ------------------------------------------------------------------------

    pub async fn submit_report(
        &self,
        app_id: &str,
        reason: ReportReason,
        message: Option<String>,
        reporter_ip: Option<&str>,
    ) -> anyhow::Result<ReportRecord> {
        let app = app_id.to_string();
        let id = ReportId::new();
        let now = Utc::now();
        let reason_str = reason.to_string();

        let message = message.map(|m| {
            let bounded: String = m
                .chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .take(2000)
                .collect();
            bounded.trim().to_string()
        });

        let reporter_hash = reporter_ip.map(|ip| {
            let salt = now.format("%Y-%m-%d").to_string();
            let mut hasher = Sha256::new();
            hasher.update(ip.as_bytes());
            hasher.update(salt.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        self.run(move |db| {
            let tx = db.transaction()?;

            // Basic rate limit / spam check: reject duplicate report from same hashed reporter for same app today
            if let Some(ref hash) = reporter_hash {
                let count: i64 = tx.query_row(
                    "SELECT count(*) FROM app_reports WHERE app_id=?1 AND reporter_hash=?2 AND created_at >= ?3",
                    params![app, hash, (now - chrono::Duration::hours(24)).to_rfc3339()],
                    |r| r.get(0),
                )?;
                ensure!(count < 3, "Too many reports submitted. Please wait before submitting another report.");
            }

            let id_str = id.to_string();
            tx.execute(
                "INSERT INTO app_reports(id, app_id, reason, message, status, reporter_hash, created_at)
                 VALUES(?1, ?2, ?3, ?4, 'open', ?5, ?6)",
                params![
                    id_str,
                    app,
                    reason_str,
                    message,
                    reporter_hash,
                    now.to_rfc3339(),
                ],
            )?;

            tx.commit()?;

            Ok(ReportRecord {
                id,
                app_id: app,
                reason,
                message,
                status: ReportStatus::Open,
                resolution_note: None,
                resolved_by: None,
                resolved_at: None,
                created_at: now,
            })
        })
        .await
    }

    pub async fn list_reports(
        &self,
        status: Option<ReportStatus>,
        app_id: Option<String>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<ReportRecord>> {
        let limit = limit.min(100);
        let status_str = status.map(|s| s.to_string());

        self.run(move |db| {
            let mut query = "SELECT id, app_id, reason, message, status, resolution_note, resolved_by, resolved_at, created_at FROM app_reports WHERE 1=1".to_string();
            let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

            if let Some(ref st) = status_str {
                query.push_str(" AND status = ?");
                params_vec.push(st.clone().into());
            }
            if let Some(ref a) = app_id {
                query.push_str(" AND app_id = ?");
                params_vec.push(a.clone().into());
            }

            query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
            params_vec.push((limit as i64).into());
            params_vec.push((offset as i64).into());

            let mut stmt = db.prepare(&query)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params_vec), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, String>(8)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut out = Vec::new();
            for (id_str, a_id, r_str, msg, st_str, note, res_by, res_at, cr_at) in rows {
                out.push(ReportRecord {
                    id: ReportId::from_str(&id_str)?,
                    app_id: a_id,
                    reason: r_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    message: msg,
                    status: st_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                    resolution_note: note,
                    resolved_by: res_by,
                    resolved_at: res_at.map(|s| s.parse()).transpose()?,
                    created_at: cr_at.parse()?,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn resolve_report(
        &self,
        report_id: &ReportId,
        status: ReportStatus,
        resolution_note: Option<String>,
        operator: &str,
    ) -> anyhow::Result<ReportRecord> {
        let rep_id = *report_id;
        let rep_id_str = rep_id.to_string();
        let status_str = status.to_string();
        let op = operator.to_string();
        let now = Utc::now();

        self.run(move |db| {
            let tx = db.transaction()?;
            let rows = tx.execute(
                "UPDATE app_reports
                 SET status=?2, resolution_note=?3, resolved_by=?4, resolved_at=?5
                 WHERE id=?1",
                params![rep_id_str, status_str, resolution_note, op, now.to_rfc3339()],
            )?;
            ensure!(rows > 0, "Report record not found");

            #[allow(clippy::type_complexity)]
            let res: (String, String, Option<String>, String, Option<String>, Option<String>, Option<String>, String) = tx.query_row(
                "SELECT app_id, reason, message, status, resolution_note, resolved_by, resolved_at, created_at FROM app_reports WHERE id=?1",
                [&rep_id_str],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )?;

            tx.commit()?;

            Ok(ReportRecord {
                id: rep_id,
                app_id: res.0,
                reason: res.1.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                message: res.2,
                status: res.3.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
                resolution_note: res.4,
                resolved_by: res.5,
                resolved_at: res.6.map(|s| s.parse()).transpose()?,
                created_at: res.7.parse()?,
            })
        })
        .await
    }

    // ------------------------------------------------------------------------
    // Trust Summary Computation
    // ------------------------------------------------------------------------

    pub async fn compute_trust_summary(
        &self,
        app_id: &str,
        _channel: &str,
        publisher_id: Option<&str>,
        latest_publication_id: Option<&str>,
    ) -> anyhow::Result<TrustSummary> {
        // 1. Check Moderation State
        let mod_info = self.get_moderation_state(app_id).await?;
        let (moderation_state, moderation_notice) = match mod_info {
            Some((state, _reason, note)) => (state, note),
            None => (ModerationState::Normal, None),
        };

        // 2. Check Publisher Domain Verification
        let mut publisher_verified = false;
        let mut verified_domain = None;
        if let Some(pub_id) = publisher_id
            && let Ok(Some(verification)) = self.get_publisher_verification_info(pub_id).await
        {
            publisher_verified = true;
            verified_domain = Some(verification.domain);
        }

        // 3. Determine Trust State
        let trust_state = if moderation_state == ModerationState::Removed {
            TrustState::Removed
        } else if moderation_state == ModerationState::Restricted {
            TrustState::Restricted
        } else if publisher_verified {
            TrustState::VerifiedPublisher
        } else {
            TrustState::Unverified
        };

        // 4. Retrieve latest release security summary if available
        let mut counts = VulnerabilityCounts::default();
        let mut latest_perm_sev = PermissionSeverity::None;
        let mut sec_analysis = "pending".to_string();

        if let Some(pub_id_str) = latest_publication_id
            && let Ok(pub_id) = pub_id_str.parse::<PublishId>()
            && let Ok(Some(details)) = self.get_release_security_details(&pub_id).await
        {
            sec_analysis = details.status.to_string();
            latest_perm_sev = details.permission_severity;
            counts = details.vulnerability_counts;
        }

        let publisher_str = if publisher_verified {
            format!(
                "Verified domain: {}",
                verified_domain.as_deref().unwrap_or("")
            )
        } else {
            "Unverified publisher".to_string()
        };

        Ok(TrustSummary {
            trust_state,
            publisher_verification: publisher_str,
            verified_domain,
            source_available: true,
            signed_repository: true,
            security_analysis: sec_analysis,
            known_vulnerabilities: counts,
            latest_permission_change: latest_perm_sev,
            moderation_state,
            moderation_notice,
        })
    }
}
