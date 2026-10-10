//! Catalog SQL stays behind the CatalogStorage abstraction; no handler reads platform tables.
use crate::store::Store;
use anyhow::{Context, ensure};
use librehub_catalog::*;
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    card: PublicCatalogCard,
    metadata: CatalogMetadata,
}

impl Store {
    pub async fn catalog_recover(&self) -> anyhow::Result<()> {
        self.run(|db| {
            db.execute(
                "UPDATE catalog_jobs SET state='pending' WHERE state='indexing'",
                [],
            )?;
            Ok(())
        })
        .await
    }
    /// Publication state is the durable backlog. Only 64 jobs are materialized as active work.
    pub async fn catalog_claim(&self) -> anyhow::Result<Option<PublishRecord>> {
        let enforce = self.supply_policy == SupplyChainPolicy::Enforce;
        self.run(move |db| {
            let tx = db.transaction()?;
            tx.execute("INSERT INTO catalog_jobs(publication_id,state,updated_at) SELECT
                 p.id,'pending',json_extract(p.record,'$.updated_at') FROM publishes p WHERE p.status='succeeded' AND NOT
                 EXISTS(SELECT 1 FROM catalog_jobs j WHERE j.publication_id=p.id) ORDER BY p.rowid LIMIT max(0,64-(SELECT
                 count(*) FROM catalog_jobs WHERE state IN ('pending','indexing')))",[])?;
            let raw: Option<String> = tx.query_row("SELECT p.record FROM catalog_jobs j JOIN publishes p ON p.id=j.publication_id WHERE j.state='pending' AND
                 p.status='succeeded' AND (?1=0 OR EXISTS(SELECT 1 FROM builds b WHERE b.id=p.build_id AND json_extract(b.record,'$.result.environment') IS NULL) OR EXISTS(SELECT 1 FROM release_attestations r WHERE r.publication_id=p.id)) ORDER BY p.rowid LIMIT 1",[enforce],|r|r.get(0)).optional()?;
            let publication: Option<PublishRecord> = raw.map(|r|serde_json::from_str(&r)).transpose()?;
            if let Some(p) = &publication { tx.execute("UPDATE catalog_jobs SET state='indexing',error_code=NULL WHERE publication_id=?1 AND state='pending'",[p.id.to_string()])?; }
            tx.commit()?; Ok(publication)
        }).await
    }
    pub async fn catalog_failed(&self, id: PublishId) -> anyhow::Result<()> {
        self.run(move |db| { db.execute("UPDATE catalog_jobs SET state='failed',error_code='metadata_index_failed',updated_at=?2 WHERE publication_id=?1",params![id.to_string(),chrono::Utc::now().to_rfc3339()])?; Ok(()) }).await
    }
    pub async fn catalog_commit(
        &self,
        publication: PublishRecord,
        extracted: librehub_catalog::extract::Extracted,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let persisted: String = tx.query_row("SELECT record FROM publishes WHERE id=?1 AND status='succeeded'",[publication.id.to_string()],|r|r.get(0))?;
            let p: PublishRecord = serde_json::from_str(&persisted)?;
            let result = p.result.as_ref().context("Missing published result")?;
            ensure!(p.id == publication.id && result.published_ref.ref_name == publication.result.as_ref().context("Missing result")?.published_ref.ref_name, "Publication identity mismatch");
            ensure!(valid_checksum(&result.published_ref.commit), "Invalid published checksum");
            let build: String = tx.query_row("SELECT record FROM builds WHERE id=?1 AND status='succeeded'",[p.build_id.to_string()],|r|r.get(0))?;
            let build: BuildRecord = serde_json::from_str(&build)?;
            let owner: Option<String> = tx.query_row("SELECT developer_id FROM build_owners WHERE build_id=?1",[p.build_id.to_string()],|r|r.get(0)).optional()?;
            let display_name = if let Some(owner) = &owner {
                let raw: String = tx.query_row("SELECT record FROM developers WHERE id=?1",[owner],|r|r.get(0))?;
                let developer: Developer = serde_json::from_str(&raw)?;
                librehub_catalog::metadata::bounded_text(&developer.display_name,120)
            } else { extracted.metadata.developer_name.clone().unwrap_or_else(|| "Independent publisher".into()) };
            let source_url = build.provenance.as_ref().and_then(|b| librehub_catalog::metadata::public_url(&b.revision.repository));
            let source_commit = build.provenance.as_ref().map(|b|b.revision.commit.clone()).filter(|s|librehub_source::valid_commit(s));
            let project_id = build.provenance.as_ref().map(|b|b.project_id.to_string());
            let version = extracted.metadata.version.clone().unwrap_or_else(|| {
                build.provenance.as_ref().and_then(|b| b.revision.source_ref.strip_prefix("refs/tags/").map(|s|librehub_catalog::metadata::bounded_text(s,120)))
                .or_else(||source_commit.as_ref().map(|s| s[..12].into())).unwrap_or_else(||p.updated_at.format("%Y-%m-%d").to_string())
            });
            let release = PublicRelease { publication_id:p.id.to_string(), build_id:p.build_id.to_string(), source_commit, source_url:source_url.clone(), channel:p.channel, architecture:p.architecture, flatpak_ref:result.published_ref.ref_name.to_string(), ostree_checksum:result.published_ref.commit.clone(), published_at:p.updated_at, version, release_notes:extracted.metadata.release_notes.clone(), permissions:extracted.permissions, security: None };
            tx.execute("INSERT INTO
                 catalog_releases(publication_id,app_id,build_id,channel,architecture,published_at,checksum,record)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(publication_id) DO UPDATE SET record=excluded.record",params![release.publication_id,p.app_id,release.build_id,p.channel.to_string(),p.architecture.to_string(),p.updated_at.to_rfc3339(),release.ostree_checksum,serde_json::to_string(&release)?])?;
            let old: Option<(String,String)> = tx.query_row("SELECT updated_at,latest_publication FROM catalog_apps WHERE app_id=?1 AND channel=?2",params![p.app_id,p.channel.to_string()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let order = (p.updated_at.to_rfc3339(),p.id.to_string());
            if old.as_ref().is_none_or(|old|order >= *old) {
                let published_at: String = tx.query_row("SELECT min(published_at) FROM catalog_releases WHERE app_id=?1 AND channel=?2",params![p.app_id,p.channel.to_string()],|r|r.get(0))?;
                let entry = Entry { card:PublicCatalogCard { app_id:p.app_id.clone(), slug:p.app_id.clone(), name:extracted.metadata.name.clone(), summary:extracted.metadata.summary.clone(), icon:extracted.metadata.icon_url.clone(), publisher:PublicPublisher{id:owner.clone(),display_name},project_id:project_id.clone(),source_url,categories:extracted.metadata.categories.clone(),architectures:vec![],channel:p.channel,archived:false,trust:None,updated_at:p.updated_at,published_at:published_at.parse()? },metadata:extracted.metadata };
                tx.execute("INSERT INTO
                 catalog_apps(app_id,channel,name,publisher_id,project_id,published_at,updated_at,latest_publication,record,icon_png)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(app_id,channel) DO UPDATE SET
                 name=excluded.name,publisher_id=excluded.publisher_id,project_id=excluded.project_id,published_at=excluded.published_at,updated_at=excluded.updated_at,latest_publication=excluded.latest_publication,record=excluded.record,icon_png=excluded.icon_png",params![p.app_id,p.channel.to_string(),entry.card.name,owner,project_id,published_at,order.0,order.1,serde_json::to_string(&entry)?,extracted.icon_png])?;
                let row: i64 = tx.query_row("SELECT id FROM catalog_apps WHERE app_id=?1 AND channel=?2",params![p.app_id,p.channel.to_string()],|r|r.get(0))?;
                tx.execute("DELETE FROM catalog_categories WHERE app_row=?1",[row])?;
                for c in &entry.metadata.categories { tx.execute("INSERT INTO catalog_categories VALUES(?1,?2)",params![row,c])?; }
                index(&tx,row,&entry)?;
            }
            tx.execute("UPDATE catalog_jobs SET state='ready',error_code=NULL,updated_at=?2 WHERE publication_id=?1",params![p.id.to_string(),chrono::Utc::now().to_rfc3339()])?;
            tx.execute("INSERT OR IGNORE INTO security_jobs(publication_id, state, attempts, updated_at) VALUES(?1, 'pending', 0, ?2)", params![p.id.to_string(), chrono::Utc::now().to_rfc3339()])?;
            tx.commit()?; Ok(())
        }).await
    }
    /// Offline only: retain last-good entries/releases and requeue the publication-derived backlog.
    pub async fn catalog_rebuild(&self) -> anyhow::Result<()> {
        self.run(|db| {
            let tx = db.transaction()?;
            tx.execute("DELETE FROM catalog_jobs", [])?;
            tx.execute("DELETE FROM catalog_search", [])?;
            let rows = tx
                .prepare("SELECT id,record FROM catalog_apps")?
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            for (row, raw) in rows {
                match serde_json::from_str::<Entry>(&raw) {
                    Ok(entry) => index(&tx, row, &entry)?,
                    Err(_) => {
                        // Corrupt derived metadata cannot be last-known-good. Reconstruct it
                        // from the durable publication backlog without touching signing history.
                        tx.execute("DELETE FROM catalog_categories WHERE app_row=?1", [row])?;
                        tx.execute("DELETE FROM catalog_apps WHERE id=?1", [row])?;
                    }
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn catalog_ready(&self) -> bool {
        self.run(|db| {
            db.query_row(
                "SELECT count(*) FROM catalog_search WHERE catalog_search MATCH 'librehub'",
                [],
                |r| r.get::<_, i64>(0),
            )?;
            Ok(())
        })
        .await
        .is_ok()
    }
    pub async fn catalog_icon(
        &self,
        id: String,
        channel: RepositoryChannel,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.run(move |db| Ok(db.query_row("SELECT icon_png FROM catalog_apps WHERE app_id=?1 AND channel=?2 AND icon_png IS NOT NULL",params![id,channel.to_string()],|r|r.get(0)).optional()?)).await
    }
    pub async fn catalog_publisher(
        &self,
        id: String,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Option<PublicPublisherPage>> {
        let first = self
            .apps(CatalogQuery {
                publisher: Some(id.clone()),
                limit: 1,
                ..Default::default()
            })
            .await?;
        let Some(publisher) = first.items.first().map(|app| app.publisher.clone()) else {
            return Ok(None);
        };
        let apps = self
            .apps(CatalogQuery {
                publisher: Some(id),
                limit,
                offset,
                ..Default::default()
            })
            .await?;
        Ok(Some(PublicPublisherPage { publisher, apps }))
    }
}
fn index(db: &Connection, row: i64, entry: &Entry) -> anyhow::Result<()> {
    db.execute("DELETE FROM catalog_search WHERE rowid=?1", [row])?;
    db.execute("INSERT INTO catalog_search(rowid,app_id,name,summary,description,developer,keywords,categories,channel)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![row,entry.card.app_id,entry.metadata.name,entry.metadata.summary,entry.metadata.description,entry.card.publisher.display_name,entry.metadata.keywords.join(" "),entry.metadata.categories.join(" "),entry.card.channel.to_string()])?;
    Ok(())
}
fn get_app_trust_sync(
    db: &Connection,
    app_id: &str,
    publisher_id: Option<&str>,
    latest_pub_id: Option<&str>,
) -> anyhow::Result<TrustSummary> {
    let mod_row: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT state, public_note FROM catalog_moderation WHERE app_id=?1",
            [app_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    let (mod_state, mod_notice) = match mod_row {
        Some((s, note)) => (
            s.parse::<ModerationState>()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            note,
        ),
        None => (ModerationState::Normal, None),
    };

    let mut publisher_verified = false;
    let mut verified_domain = None;
    if let Some(pub_id) = publisher_id {
        let ver_row: Option<String> = db
            .query_row(
                "SELECT domain FROM publisher_verifications WHERE developer_id=?1 AND status='verified' ORDER BY verified_at DESC LIMIT 1",
                [pub_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(d) = ver_row {
            publisher_verified = true;
            verified_domain = Some(d);
        }
    }

    let trust_state = if mod_state == ModerationState::Removed {
        TrustState::Removed
    } else if mod_state == ModerationState::Restricted {
        TrustState::Restricted
    } else if publisher_verified {
        TrustState::VerifiedPublisher
    } else {
        TrustState::Unverified
    };

    let mut counts = VulnerabilityCounts::default();
    let mut latest_perm_sev = PermissionSeverity::None;
    let mut sec_analysis = "pending".to_string();

    if let Some(pub_id) = latest_pub_id {
        let sec_row: Option<(String, String)> = db
            .query_row(
                "SELECT status, permission_severity FROM release_security WHERE publication_id=?1",
                [pub_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((status_str, perm_sev_str)) = sec_row {
            sec_analysis = status_str;
            if let Ok(sev) = perm_sev_str.parse::<PermissionSeverity>() {
                latest_perm_sev = sev;
            }
            let mut vuln_stmt =
                db.prepare("SELECT severity FROM vulnerability_findings WHERE publication_id=?1")?;
            let vuln_rows = vuln_stmt.query_map([pub_id], |r| r.get::<_, String>(0))?;
            for v_sev in vuln_rows {
                let sev_str = v_sev?;
                if let Ok(sev) = sev_str.parse::<VulnerabilitySeverity>() {
                    match sev {
                        VulnerabilitySeverity::Critical => counts.critical += 1,
                        VulnerabilitySeverity::High => counts.high += 1,
                        VulnerabilitySeverity::Medium => counts.medium += 1,
                        VulnerabilitySeverity::Low => counts.low += 1,
                        VulnerabilitySeverity::Unknown => counts.unknown += 1,
                    }
                }
            }
        }
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
        moderation_state: mod_state,
        moderation_notice: mod_notice,
    })
}

fn get_release_security_sync(
    db: &Connection,
    pub_id: &str,
) -> anyhow::Result<Option<ReleaseSecurityDetails>> {
    let row = db
        .query_row(
            "SELECT r.app_id, r.channel, r.status, r.sbom_format, r.sbom_path, r.sbom_component_count, r.sbom_sha256,
                    r.vulnerabilities_status, r.vulnerabilities_checked_at, r.permissions_extracted_at,
                    d.diff_json
             FROM release_security r
             LEFT JOIN permission_diffs d ON d.to_publication_id = r.publication_id
             WHERE r.publication_id=?1",
            [pub_id],
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

    let Some((
        app_id,
        channel,
        status_str,
        sbom_format,
        sbom_path,
        sbom_component_count,
        sbom_sha256,
        vuln_status_str,
        vuln_checked_at,
        perm_extracted_at,
        diff_json,
    )) = row
    else {
        return Ok(None);
    };

    let mut vuln_stmt = db.prepare(
        "SELECT vulnerability_id, component_name, component_version, severity, summary, reference_url, source_provider, checked_at
         FROM vulnerability_findings WHERE publication_id=?1",
    )?;
    let findings_rows = vuln_stmt
        .query_map([pub_id], |r| {
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

    let perm_sev = diff
        .as_ref()
        .map(|d| d.severity)
        .unwrap_or(PermissionSeverity::None);
    let counts = VulnerabilityCounts::from_findings(&findings);
    let perm_extracted: Timestamp = perm_extracted_at.parse()?;
    let vuln_checked: Option<Timestamp> = vuln_checked_at.map(|s| s.parse()).transpose()?;

    Ok(Some(ReleaseSecurityDetails {
        publication_id: pub_id.parse()?,
        app_id: app_id.clone(),
        channel,
        status: status_str.parse().map_err(|e| anyhow::anyhow!("{e}"))?,
        sbom_format,
        sbom_component_count,
        sbom_sha256,
        sbom_download_url: format!("/api/v1/catalog/apps/{app_id}/releases/{pub_id}/sbom/download"),
        sbom_path: if sbom_path.is_empty() {
            None
        } else {
            Some(sbom_path)
        },
        vulnerabilities_status: vuln_status_str
            .parse()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
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
}

fn card(
    db: &Connection,
    raw: &str,
    icon: bool,
    archived: bool,
) -> anyhow::Result<PublicCatalogCard> {
    let mut entry: Entry = serde_json::from_str(raw)?;
    let arches = db.prepare("SELECT DISTINCT architecture FROM catalog_releases WHERE app_id=?1 AND channel=?2 ORDER BY architecture")?.query_map(params![entry.card.app_id,entry.card.channel.to_string()],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
    entry.card.architectures = arches
        .iter()
        .filter_map(|s| match s.as_str() {
            "x86_64" => Some(Architecture::X86_64),
            "aarch64" => Some(Architecture::Aarch64),
            _ => None,
        })
        .collect();
    entry.card.archived = archived;
    if icon {
        entry.card.icon = Some(format!(
            "/api/v1/catalog/apps/{}/icon?channel={}",
            entry.card.app_id, entry.card.channel
        ));
    }
    let latest_pub: Option<String> = db
        .query_row(
            "SELECT latest_publication FROM catalog_apps WHERE app_id=?1 AND channel=?2",
            params![entry.card.app_id, entry.card.channel.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    entry.card.trust = get_app_trust_sync(
        db,
        &entry.card.app_id,
        entry.card.publisher.id.as_deref(),
        latest_pub.as_deref(),
    )
    .ok();
    Ok(entry.card)
}
const FROM: &str = "catalog_apps a LEFT JOIN projects p ON p.id=a.project_id LEFT JOIN developers d ON d.id=a.publisher_id LEFT JOIN catalog_moderation m ON m.app_id=a.app_id";
const ARCHIVED: &str =
    "(coalesce(p.status,'active')!='active' OR coalesce(d.status,'active')!='active')";
#[async_trait::async_trait]
impl CatalogStorage for Store {
    async fn apps(&self, query: CatalogQuery) -> anyhow::Result<CatalogPage<PublicCatalogCard>> {
        let expression = search_expression(&query.q)?;
        ensure!(
            query.limit > 0 && query.limit <= 100 && query.offset <= 100_000,
            "Pagination bounds"
        );
        self.run(move |db| {
            let from = if expression.is_empty() { FROM.to_owned() } else { format!("{FROM} JOIN catalog_search ON catalog_search.rowid=a.id") };
            let filter = "a.channel=?1 AND coalesce(m.state,'normal') NOT IN ('restricted','removed') AND (?2 IS NULL OR EXISTS(SELECT 1 FROM catalog_categories c WHERE c.app_row=a.id AND c.category=?2)) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM catalog_releases r WHERE r.app_id=a.app_id AND r.channel=a.channel AND r.architecture=?3)) AND (?4 IS NULL OR a.publisher_id=?4)";
            let filter = if expression.is_empty(){filter.into()}else{format!("{filter} AND catalog_search MATCH ?5")};
            let order = if !expression.is_empty(){"CASE WHEN lower(a.app_id)=lower(?6) THEN 0 WHEN lower(a.name)=lower(?6) THEN 1 WHEN substr(lower(a.name),1,length(?6))=lower(?6) THEN 2 ELSE 3 END, bm25(catalog_search,12.0,10.0,6.0,1.0,3.0,4.0,4.0), a.app_id"}else{match query.sort{CatalogSort::Name=>"lower(a.name),a.app_id",CatalogSort::RecentlyPublished=>"a.published_at DESC,a.app_id",CatalogSort::RecentlyUpdated=>"a.updated_at DESC,a.app_id"}};
            let values: Vec<rusqlite::types::Value> = vec![query.channel.to_string().into(),query.category.map(Into::into).unwrap_or(rusqlite::types::Value::Null),query.architecture.map(|a|a.to_string().into()).unwrap_or(rusqlite::types::Value::Null),query.publisher.map(Into::into).unwrap_or(rusqlite::types::Value::Null)];
            let mut count_values = values.clone(); if !expression.is_empty(){count_values.push(expression.clone().into());}
            let total:u64 = db.query_row(&format!("SELECT count(*) FROM {from} WHERE {filter}"),rusqlite::params_from_iter(&count_values),|r|r.get::<_,i64>(0))? as u64;
            let mut values = count_values; if !expression.is_empty(){values.push(query.q.trim().to_owned().into());}
            // Number pagination parameters after the optional MATCH/rank inputs.
            let n=values.len(); values.push((query.limit as i64).into());values.push((query.offset as i64).into());
            let rows=db.prepare(&format!("SELECT a.record,a.icon_png IS NOT NULL,{ARCHIVED} FROM {from} WHERE {filter} ORDER BY {order} LIMIT ?{}
                 OFFSET ?{}",n+1,n+2))?.query_map(rusqlite::params_from_iter(&values),|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,bool>(2)?)))?.collect::<Result<Vec<_>,_>>()?;
            let items=rows.iter().map(|(r,i,a)|card(db,r,*i,*a)).collect::<anyhow::Result<Vec<_>>>()?;
            Ok(CatalogPage{items,total,limit:query.limit,offset:query.offset})
        }).await
    }
    async fn app(
        &self,
        id: String,
        channel: RepositoryChannel,
    ) -> anyhow::Result<Option<PublicCatalogApp>> {
        self.run(move |db| {
            let mod_state: Option<String> = db.query_row(
                "SELECT state FROM catalog_moderation WHERE app_id=?1",
                [&id],
                |r| r.get(0),
            ).optional()?;
            if mod_state.as_deref() == Some("removed") {
                return Ok(None);
            }
            let raw:Option<(String,bool,bool)>=db.query_row(&format!("SELECT a.record,a.icon_png IS NOT NULL,{ARCHIVED} FROM {FROM} WHERE a.app_id=?1 AND a.channel=?2"),params![id,channel.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let Some((raw,icon,archived))=raw else{return Ok(None);};
            let entry:Entry=serde_json::from_str(&raw)?;let card=card(db,&raw,icon,archived)?;
            let current_raw=db.prepare("SELECT record FROM (SELECT record,row_number() OVER (PARTITION BY channel,architecture ORDER BY
                 published_at DESC,publication_id DESC) AS position FROM catalog_releases WHERE app_id=?1) WHERE
                 position=1 ORDER BY json_extract(record,'$.published_at') DESC,json_extract(record,'$.publication_id')
                 DESC")?.query_map([&id],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
            let mut current = Vec::new();
            for r_str in current_raw {
                let mut rel = serde_json::from_str::<PublicRelease>(&r_str)?;
                rel.security = get_release_security_sync(db, &rel.publication_id).ok().flatten();
                current.push(rel);
            }
            let current_stable_release=current.iter().find(|r|r.channel==RepositoryChannel::Stable).cloned(); let current_beta_release=current.iter().find(|r|r.channel==RepositoryChannel::Beta).cloned();
            let current_releases=current.into_iter().filter(|r|r.channel==channel).collect::<Vec<_>>();
            let branch=current_releases.first().context("Catalog release missing")?.flatpak_ref.rsplit('/').next().unwrap_or("master").to_owned();
            let remote=if channel==RepositoryChannel::Stable{"librehub"}else{"librehub-beta"};
            Ok(Some(PublicCatalogApp{card,description:entry.metadata.description,screenshots:entry.metadata.screenshots,homepage:entry.metadata.homepage,license:entry.metadata.license,developer_name:entry.metadata.developer_name,content_rating:entry.metadata.content_rating,current_stable_release,current_beta_release,current_releases,install:CatalogInstall{remote:remote.into(),remote_descriptor_url:String::new(),flatpakref_url:format!("/api/v1/catalog/apps/{id}/flatpakref?channel={channel}"),command:format!("flatpak install --user {remote} {id}//{branch}")}}))
        }).await
    }
    async fn releases(
        &self,
        id: String,
        channel: RepositoryChannel,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<CatalogPage<PublicRelease>> {
        ensure!(
            limit > 0 && limit <= 100 && offset <= 100_000,
            "Pagination bounds"
        );
        self.run(move |db| {
            let total=db.query_row("SELECT count(*) FROM catalog_releases WHERE app_id=?1 AND channel=?2",params![id,channel.to_string()],|r|r.get::<_,i64>(0))? as u64;
            let rows=db.prepare("SELECT record FROM catalog_releases WHERE app_id=?1 AND channel=?2 ORDER BY published_at DESC,publication_id DESC LIMIT ?3 OFFSET ?4")?
                .query_map(params![id,channel.to_string(),limit as i64,offset as i64],|r|r.get::<_,String>(0))?
                .collect::<Result<Vec<_>,_>>()?;
            let mut items = Vec::new();
            for r in rows {
                let mut rel = serde_json::from_str::<PublicRelease>(&r)?;
                rel.security = get_release_security_sync(db, &rel.publication_id).ok().flatten();
                items.push(rel);
            }
            Ok(CatalogPage{items,total,limit,offset})
        }).await
    }
    async fn categories(&self) -> anyhow::Result<Vec<CatalogCategory>> {
        self.run(|db| Ok(db.prepare("SELECT category,count(*) FROM catalog_categories c JOIN catalog_apps a ON a.id=c.app_row LEFT JOIN catalog_moderation m ON m.app_id=a.app_id WHERE
                 a.channel='stable' AND coalesce(m.state,'normal') NOT IN ('restricted','removed') GROUP BY category ORDER BY category")?.query_map([],|r|Ok(CatalogCategory{id:r.get(0)?,count:r.get::<_,i64>(1)? as u64}))?.collect::<Result<Vec<_>,_>>()?)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    async fn publication(
        store: &Store,
        id: &str,
        channel: RepositoryChannel,
        name: &str,
    ) -> PublishRecord {
        let mut manifest = librehub_validator::validate(
            include_str!("../../../examples/org.librehub.Hello.json"),
            ManifestFormat::Json,
        )
        .unwrap();
        manifest.app_id = id.into();
        let build = store.insert(manifest, Architecture::X86_64).await.unwrap();
        store
            .transition(build.id, BuildStatus::Validating, None, None)
            .await
            .unwrap();
        store
            .transition(build.id, BuildStatus::Building, None, None)
            .await
            .unwrap();
        store
            .transition(
                build.id,
                BuildStatus::Succeeded,
                Some(BuildResult {
                    environment: None,
                    exit_code: Some(0),
                    artifacts: vec![Artifact {
                        path: format!("builds/{}/artifacts/application.flatpak", build.id),
                        size_bytes: 1,
                        sha256: "a".repeat(64),
                    }],
                }),
                None,
            )
            .await
            .unwrap();
        let mut p = store.enqueue_publish(build.id, channel).await.unwrap();
        p = store.claim_publication(p.id).await.unwrap().unwrap();
        for status in [
            PublishStatus::Uploading,
            PublishStatus::Committing,
            PublishStatus::Publishing,
        ] {
            p.status = status;
            store.save_publication(p.clone()).await.unwrap();
        }
        p.status = PublishStatus::Succeeded;
        p.result = Some(PublishResult {
            published_ref: PublishedRef {
                ref_name: RepositoryRef::new(id, Architecture::X86_64, "master").unwrap(),
                commit: "b".repeat(64),
                source_commit: "a".repeat(64),
                repository_url: "https://repo.example.com/repo/stable/".into(),
            },
            signing: SigningMetadata {
                fingerprint: "F".repeat(40),
                public_key_url: "https://repo.example.com/repository.gpg".into(),
            },
        });
        store.save_publication(p.clone()).await.unwrap();
        p = store.publish_record(p.id).await.unwrap().unwrap();
        let mut metadata = librehub_catalog::metadata::fallback(id);
        metadata.name = name.into();
        metadata.summary = "A code editor".into();
        metadata.description = "Edit documents".into();
        metadata.keywords = vec!["programming".into()];
        metadata.categories = vec!["Development".into()];
        metadata.version = Some("1.0".into());
        store
            .catalog_commit(
                p.clone(),
                librehub_catalog::extract::Extracted {
                    metadata,
                    permissions: CatalogPermissions {
                        network: true,
                        ..Default::default()
                    },
                    icon_png: None,
                },
            )
            .await
            .unwrap();
        p
    }
    #[tokio::test]
    async fn stable_is_public_and_beta_requires_explicit_channel() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        publication(
            &s,
            "org.example.Stable",
            RepositoryChannel::Stable,
            "Stable",
        )
        .await;
        publication(&s, "org.example.Beta", RepositoryChannel::Beta, "Preview").await;
        let stable = s.apps(CatalogQuery::default()).await.unwrap();
        assert_eq!(stable.total, 1);
        assert_eq!(stable.items[0].app_id, "org.example.Stable");
        assert!(
            s.app("org.example.Beta".into(), RepositoryChannel::Stable)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            s.apps(CatalogQuery {
                channel: RepositoryChannel::Beta,
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
            1
        );
    }
    #[tokio::test]
    async fn release_history_filters_channel_before_pagination() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let first = publication(&s, "org.example.Test", RepositoryChannel::Stable, "First").await;
        let second = publication(&s, "org.example.Test", RepositoryChannel::Stable, "Second").await;
        let beta = publication(&s, "org.example.Test", RepositoryChannel::Beta, "Beta").await;
        let router = crate::catalog_http::router(crate::catalog_http::CatalogHttp {
            store: s,
            api_public_url: "https://api.example.com".into(),
            repository: None,
            page_size: 24,
        });
        for (query, total, offset, expected) in [
            ("limit=1", 2, 0, Some(second.id)),
            ("channel=stable&limit=1&offset=1", 2, 1, Some(first.id)),
            ("channel=beta&limit=1", 1, 0, Some(beta.id)),
            ("channel=beta&limit=1&offset=1", 1, 1, None),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/api/v1/catalog/apps/org.example.Test/releases?{query}"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let page: CatalogPage<PublicRelease> = serde_json::from_slice(&body).unwrap();
            assert_eq!((page.total, page.limit, page.offset), (total, 1, offset));
            assert_eq!(page.items.len(), usize::from(expected.is_some()));
            if let Some(id) = expected {
                assert_eq!(page.items[0].publication_id, id.to_string());
            }
        }
    }

    #[tokio::test]
    async fn catalog_lookup_failures_do_not_shutdown_the_worker() {
        use crate::catalog_worker::CatalogWorker;
        use librehub_publisher::repository::RepositoryConfig;
        use std::time::{Duration, Instant};
        use tokio_util::sync::CancellationToken;

        for failure in ["record", "manifest", "missing"] {
            let root = tempfile::tempdir().unwrap();
            let s = Store::open(root.path()).unwrap();
            let p = publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
            s.catalog_rebuild().await.unwrap();
            let build_id = p.build_id;
            let publication_id = p.id;
            s.run(move |db| {
                match failure {
                    "record" => { db.execute("UPDATE builds SET record='invalid' WHERE id=?1", [build_id.to_string()])?; }
                    "manifest" => { db.execute("UPDATE builds SET manifest='invalid' WHERE id=?1", [build_id.to_string()])?; }
                    _ => { db.execute("UPDATE publishes SET record=json_set(record,'$.build_id',?2) WHERE id=?1", params![publication_id.to_string(), BuildId::new().to_string()])?; }
                }
                Ok(())
            }).await.unwrap();
            let shutdown = CancellationToken::new();
            let worker = CatalogWorker::new(
                s.clone(),
                Some(RepositoryConfig {
                    public_base_url: "https://repo.example.com".into(),
                    public_key: vec![],
                    fingerprint: "F".repeat(40),
                    runtime_repo_url: "https://repo.example.com/runtime.flatpakrepo".into(),
                }),
                shutdown.clone(),
            );
            let started = Instant::now();
            let task = tokio::spawn(worker.run());
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let state: Option<String> = s
                        .run(move |db| {
                            Ok(db
                                .query_row(
                                    "SELECT state FROM catalog_jobs WHERE publication_id=?1",
                                    [publication_id.to_string()],
                                    |row| row.get(0),
                                )
                                .optional()?)
                        })
                        .await
                        .unwrap();
                    if state.as_deref() == Some("failed") {
                        break;
                    }
                    assert!(
                        !task.is_finished(),
                        "lookup failure escaped the supervisor: {failure}"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if failure != "missing" {
                assert!(
                    started.elapsed() >= Duration::from_secs(2),
                    "lookup was not retried"
                );
            }
            assert!(!shutdown.is_cancelled());
            assert!(!task.is_finished());
            assert_eq!(
                s.publish_record(p.id).await.unwrap().unwrap().status,
                PublishStatus::Succeeded
            );
            assert_eq!(s.apps(CatalogQuery::default()).await.unwrap().total, 1);
            shutdown.cancel();
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn queued_failed_and_cancelled_never_index() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let manifest = librehub_validator::validate(
            include_str!("../../../examples/org.librehub.Hello.json"),
            ManifestFormat::Json,
        )
        .unwrap();
        let b = s.insert(manifest, Architecture::X86_64).await.unwrap();
        s.transition(
            b.id,
            BuildStatus::Failed,
            None,
            Some(BuildError {
                code: "test".into(),
                message: "Test".into(),
            }),
        )
        .await
        .unwrap();
        assert!(s.catalog_claim().await.unwrap().is_none());
        assert_eq!(s.apps(CatalogQuery::default()).await.unwrap().total, 0);
    }
    #[tokio::test]
    async fn duplicate_index_and_rebuild_preserve_release_identity() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let p = publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        let requeue = p.id;
        s.catalog_rebuild().await.unwrap();
        assert_eq!(s.apps(CatalogQuery::default()).await.unwrap().total, 1);
        let claim = s.catalog_claim().await.unwrap().unwrap();
        assert_eq!(claim.id, requeue);
        s.catalog_recover().await.unwrap();
        assert_eq!(s.catalog_claim().await.unwrap().unwrap().id, requeue);
        let mut metadata = librehub_catalog::metadata::fallback(&p.app_id);
        metadata.name = "Test".into();
        s.catalog_commit(
            p,
            librehub_catalog::extract::Extracted {
                metadata,
                permissions: Default::default(),
                icon_png: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            s.releases("org.example.Test".into(), RepositoryChannel::Stable, 24, 0)
                .await
                .unwrap()
                .total,
            1
        );
    }
    #[tokio::test]
    async fn rebuild_recovers_corrupt_derived_metadata_and_preserves_good_apps() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let p = publication(
            &s,
            "org.example.Corrupt",
            RepositoryChannel::Stable,
            "Corrupt",
        )
        .await;
        publication(&s, "org.example.Good", RepositoryChannel::Stable, "Good").await;
        s.run(|db| {
            db.execute(
                "UPDATE catalog_apps SET record='broken-json' WHERE app_id='org.example.Corrupt'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        s.catalog_rebuild().await.unwrap();
        let apps = s.apps(CatalogQuery::default()).await.unwrap();
        assert_eq!(apps.total, 1);
        assert_eq!(apps.items[0].app_id, "org.example.Good");
        assert_eq!(
            serde_json::to_value(s.publish_record(p.id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(&p).unwrap()
        );
        assert!(s.catalog_claim().await.unwrap().is_some());
        let mut metadata = librehub_catalog::metadata::fallback(&p.app_id);
        metadata.name = "Recovered".into();
        s.catalog_commit(
            p,
            librehub_catalog::extract::Extracted {
                metadata,
                permissions: Default::default(),
                icon_png: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            s.app("org.example.Corrupt".into(), RepositoryChannel::Stable)
                .await
                .unwrap()
                .unwrap()
                .card
                .name,
            "Recovered"
        );
        assert_eq!(
            s.releases(
                "org.example.Corrupt".into(),
                RepositoryChannel::Stable,
                24,
                0
            )
            .await
            .unwrap()
            .total,
            1
        );
    }
    #[tokio::test]
    async fn indexing_failure_preserves_last_good_app() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let p = publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        s.catalog_failed(p.id).await.unwrap();
        assert_eq!(s.apps(CatalogQuery::default()).await.unwrap().total, 1);
        assert_eq!(
            s.publish_record(p.id).await.unwrap().unwrap().status,
            PublishStatus::Succeeded
        );
    }
    #[tokio::test]
    async fn catalog_survives_database_reopen() {
        let root = tempfile::tempdir().unwrap();
        {
            let s = Store::open(root.path()).unwrap();
            publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        }
        let s = Store::open(root.path()).unwrap();
        assert_eq!(s.apps(CatalogQuery::default()).await.unwrap().total, 1);
        assert!(s.catalog_ready().await);
    }
    #[tokio::test]
    async fn deterministic_search_ranking_and_pagination() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        for (id, name) in [
            ("org.example.Code", "Other"),
            ("org.example.Exact", "Code"),
            ("org.example.Prefix", "Code Studio"),
            ("org.example.Summary", "Tool"),
        ] {
            publication(&s, id, RepositoryChannel::Stable, name).await;
        }
        let query = CatalogQuery {
            q: "code".into(),
            ..Default::default()
        };
        let page = s.apps(query.clone()).await.unwrap();
        assert_eq!(page.items[0].name, "Code");
        assert_eq!(page.items[1].name, "Code Studio");
        let exact = s
            .apps(CatalogQuery {
                q: "org.example.Code".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(exact.items[0].app_id, "org.example.Code");
        let first = s
            .apps(CatalogQuery {
                limit: 1,
                ..query.clone()
            })
            .await
            .unwrap();
        let second = s
            .apps(CatalogQuery {
                limit: 1,
                offset: 1,
                ..query
            })
            .await
            .unwrap();
        assert_ne!(first.items[0].app_id, second.items[0].app_id);
        assert_eq!(
            s.apps(CatalogQuery {
                q: "programming".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
            4
        );
        assert_eq!(
            s.apps(CatalogQuery {
                q: "nomatch".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
            0
        );
        assert!(
            s.apps(CatalogQuery {
                q: "a".repeat(201),
                ..Default::default()
            })
            .await
            .is_err()
        );
        assert!(
            s.apps(CatalogQuery {
                limit: 101,
                ..Default::default()
            })
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn categories_architectures_and_history_are_real() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        let first = publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        let second =
            publication(&s, "org.example.Test", RepositoryChannel::Stable, "Updated").await;
        let releases = s
            .releases(first.app_id.clone(), RepositoryChannel::Stable, 24, 0)
            .await
            .unwrap();
        assert_eq!(releases.total, 2);
        assert_eq!(releases.items[0].publication_id, second.id.to_string());
        assert_eq!(s.categories().await.unwrap()[0].count, 1);
        assert_eq!(
            s.apps(CatalogQuery {
                architecture: Some(Architecture::Aarch64),
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
            0
        );
        assert_eq!(
            s.apps(CatalogQuery {
                category: Some("Development".into()),
                ..Default::default()
            })
            .await
            .unwrap()
            .total,
            1
        );
        let app = s
            .app(first.app_id, RepositoryChannel::Stable)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(app.card.name, "Updated");
        assert!(app.current_releases[0].permissions.network);
    }
    #[tokio::test]
    async fn public_api_is_bounded_cacheable_and_private_by_dto() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        let router = crate::catalog_http::router(crate::catalog_http::CatalogHttp {
            store: s,
            api_public_url: "https://api.example.com".into(),
            repository: None,
            page_size: 24,
        });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/catalog/apps/org.example.Test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let etag = response.headers()["etag"].clone();
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["app_id"], "org.example.Test");
        for secret in [
            "webhook_secret",
            "token",
            "audit",
            "flat_manager_build_id",
            "email",
            "policy_version",
        ] {
            assert!(!String::from_utf8_lossy(&body).contains(secret));
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/catalog/apps/org.example.Test")
                    .header("if-none-match", etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        for uri in [
            "/api/v1/catalog/search?q=code&limit=101",
            "/api/v1/catalog/search?offset=100001",
            "/api/v1/catalog/apps?sort=popular",
        ] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            router
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/catalog/apps/org.example.Missing")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn disabled_publisher_keeps_existing_release_but_marks_archived() {
        let root = tempfile::tempdir().unwrap();
        let s = Store::open(root.path()).unwrap();
        publication(&s, "org.example.Test", RepositoryChannel::Stable, "Test").await;
        let d = s.create_developer("Dev".into()).await.unwrap();
        s.run(move |db| {
            db.execute(
                "UPDATE developers SET status='disabled' WHERE id=?1",
                [d.id.to_string()],
            )?;
            db.execute(
                "UPDATE catalog_apps SET publisher_id=?1",
                [d.id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let app = s
            .app("org.example.Test".into(), RepositoryChannel::Stable)
            .await
            .unwrap()
            .unwrap();
        assert!(app.card.archived);
        assert_eq!(app.current_releases.len(), 1);
    }
}
