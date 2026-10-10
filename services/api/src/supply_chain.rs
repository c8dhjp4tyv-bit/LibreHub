//! Trusted control-plane attestor. Workers never submit arbitrary statements to this module.
use crate::store::Store;
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use librehub_common::*;
use librehub_supply_chain::{self as crypto, Attestor};
use rusqlite::{OptionalExtension, params};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

impl Store {
    pub async fn configure_attestor(&mut self) -> Result<()> {
        self.supply_policy = match std::env::var("LIBREHUB_SUPPLY_CHAIN_POLICY")
            .unwrap_or_else(|_| "development".into())
            .as_str()
        {
            "development" => SupplyChainPolicy::Development,
            "audit_only" => SupplyChainPolicy::AuditOnly,
            "enforce" => SupplyChainPolicy::Enforce,
            _ => anyhow::bail!("Invalid supply-chain policy"),
        };
        self.allowed_images = std::env::var("LIBREHUB_ALLOWED_WORKER_IMAGE_IDS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if let Ok(seed) = std::env::var("LIBREHUB_ATTESTOR_KEY_FILE") {
            let bundle = std::env::var("LIBREHUB_ATTESTOR_KEYS_FILE")
                .context("Attestor public key bundle required")?;
            self.attestor = Some(Arc::new(Attestor::new(seed.into(), bundle.into())?));
            self.sync_attestor_keys().await?;
        }
        ensure!(
            self.supply_policy != SupplyChainPolicy::Enforce
                || (self.attestor.is_some() && !self.allowed_images.is_empty()),
            "Enforcement requires a provisioned attestor and allowed image IDs"
        );
        Ok(())
    }
    pub async fn sync_attestor_keys(&self) -> Result<KeyBundle> {
        let bundle = self
            .attestor
            .as_ref()
            .context("attestor_unavailable")?
            .bundle()?;
        let keys = bundle.keys.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            for key in keys {
                let old: Option<(String,String)> = tx.query_row("SELECT public_key,state FROM attestor_keys WHERE key_id=?1",[&key.key_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                let state = serde_json::to_value(key.state)?.as_str().context("key state")?.to_owned();
                if let Some((public,old_state)) = &old {
                    ensure!(public == &key.public_key,"key_replacement_rejected");
                    ensure!(old_state != "revoked" || state == "revoked","revocation_is_permanent");
                }
                if old.as_ref().is_none_or(|(_,st)|st != &state) {
                    tx.execute("INSERT INTO supply_chain_audit(action,target_id,result,timestamp) VALUES('attestor.key_rotated',?1,?2,?3)",params![key.key_id,state,Utc::now().to_rfc3339()])?;
                }
                tx.execute("INSERT INTO attestor_keys VALUES(?1,?2,?3,?4) ON CONFLICT(key_id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at",params![key.key_id,key.public_key,state,Utc::now().to_rfc3339()])?;
            }
            tx.commit()?; Ok(())
        }).await?;
        self.public_keys().await
    }
    pub async fn public_keys(&self) -> Result<KeyBundle> {
        self.run(|db| {
            let rows = db
                .prepare(
                    "SELECT key_id,public_key,state FROM attestor_keys ORDER BY key_id LIMIT 32",
                )?
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let keys = rows
                .into_iter()
                .map(|(key_id, public_key, state)| {
                    Ok(AttestorPublicKey {
                        key_id,
                        public_key,
                        state: serde_json::from_value(serde_json::json!(state))?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(KeyBundle { version: 1, keys })
        })
        .await
    }
    pub async fn envelope(&self, kind: &'static str, id: String) -> Result<Option<DsseEnvelope>> {
        self.run(move |db| {
            let sql = match kind {
                "build" => "SELECT envelope FROM build_attestations WHERE build_id=?1",
                "release" => "SELECT envelope FROM release_attestations WHERE publication_id=?1",
                _ => anyhow::bail!("invalid_attestation_kind"),
            };
            let raw: Option<String> = db.query_row(sql, [id], |r| r.get(0)).optional()?;
            raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
                .transpose()
        })
        .await
    }
    pub async fn supply_audit(
        &self,
        action: &'static str,
        id: String,
        result: &'static str,
    ) -> Result<()> {
        self.run(move |db| {db.execute("INSERT INTO supply_chain_audit(action,target_id,result,timestamp) VALUES(?1,?2,?3,?4)",params![action,id,result,Utc::now().to_rfc3339()])?;Ok(())}).await
    }
    pub async fn attest_build(&self, id: BuildId) -> Result<DsseEnvelope> {
        let signer = self.attestor.as_ref().context("attestor_unavailable")?;
        let keys = self.sync_attestor_keys().await?;
        let build = self.get(id).await?.context("build_missing")?;
        let manifest = self.manifest(id).await?;
        let source = build
            .provenance
            .clone()
            .context("immutable_source_unavailable")?;
        let environment = build
            .result
            .as_ref()
            .and_then(|r| r.environment.clone())
            .context("environment_unavailable")?;
        ensure!(
            build.status == BuildStatus::Succeeded,
            "build_not_successful"
        );
        fault_barrier(self, "build_evidence").await?;
        let root = self.data_dir.clone();
        let source_check = source.clone();
        let m = manifest.clone();
        let manifest_sha = tokio::task::spawn_blocking(move || {
            librehub_source::verify_manifest_snapshot(&root, id, &source_check, &m)
        })
        .await??;
        // M2 independently hashes an immutable copy, imports, fscks and validates app/arch/branch/runtime.
        let prepared = librehub_publisher::artifact::prepare(
            self.data_dir.clone(),
            build.clone(),
            manifest.clone(),
            build.architecture,
            Duration::from_secs(60),
        )
        .await?;
        fault_barrier(self, "build_verified").await?;
        let artifact_sha = build.result.as_ref().context("artifact_missing")?.artifacts[0]
            .sha256
            .clone();
        let dependencies = vec![
            SourceMaterial {
                uri: source.revision.repository.clone(),
                digest: crypto::digest("gitCommit", &source.revision.commit),
            },
            SourceMaterial {
                uri: "librehub:source-snapshot".into(),
                digest: crypto::digest("sha256", &source.snapshot.sha256),
            },
            SourceMaterial {
                uri: "librehub:manifest".into(),
                digest: crypto::digest("sha256", &manifest_sha),
            },
            SourceMaterial {
                uri: "librehub:worker-image-config".into(),
                digest: crypto::digest(
                    "sha256",
                    environment
                        .image_config_digest
                        .strip_prefix("sha256:")
                        .context("image_identity")?,
                ),
            },
            SourceMaterial {
                uri: environment.runtime_ref.clone(),
                digest: crypto::digest("sha256", &environment.runtime_commit),
            },
            SourceMaterial {
                uri: environment.sdk_ref.clone(),
                digest: crypto::digest("sha256", &environment.sdk_commit),
            },
        ];
        let implementation_version = environment.builder_version.clone();
        let statement = ProvenanceStatement {
            statement_type: STATEMENT_V1.into(),
            predicate_type: SLSA_V1.into(),
            subject: vec![AttestationSubject {
                name: prepared.ref_name.to_string(),
                digest: crypto::digest("sha256", &artifact_sha),
            }],
            predicate: ProvenancePredicate::Build(Box::new(SlsaProvenance {
                build_definition: BuildDefinition {
                    build_type: BUILD_TYPE_V1.into(),
                    external_parameters: BuildInvocation {
                        build_id: id,
                        app_id: manifest.app_id.clone(),
                        architecture: build.architecture,
                        branch: prepared
                            .ref_name
                            .as_str()
                            .rsplit('/')
                            .next()
                            .context("branch")?
                            .into(),
                        source,
                        declared_dependencies: crypto::declared_dependencies(&manifest),
                    },
                    internal_parameters: environment,
                    resolved_dependencies: dependencies,
                },
                run_details: RunDetails {
                    builder: BuilderIdentity {
                        id: BUILDER_ID.into(),
                        version: BTreeMap::from([("librehub".into(), implementation_version)]),
                    },
                    metadata: BuildMetadata {
                        invocation_id: id.to_string(),
                        started_on: build.started_at.context("build_start_missing")?,
                        finished_on: build.finished_at.context("build_finish_missing")?,
                    },
                },
            })),
        };
        if let Some(existing) = self.envelope("build", id.to_string()).await? {
            let (_, old_digest) = crypto::verify(&existing, &keys)?;
            ensure!(
                old_digest == crypto::sha256(&crypto::canonical(&statement)?),
                "build_evidence_changed"
            );
            return Ok(existing);
        }
        let envelope = signer.sign(&statement)?;
        fault_barrier(self, "build_signed").await?;
        let (_, digest) = crypto::verify(&envelope, &keys)?;
        let raw = serde_json::to_string(&envelope)?;
        let app = manifest.app_id;
        let key = envelope.signatures[0].keyid.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            tx.execute("INSERT OR IGNORE INTO build_attestations VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id.to_string(),app,artifact_sha,digest,key,raw,Utc::now().to_rfc3339()])?;
            let persisted:String = tx.query_row("SELECT statement_sha256 FROM build_attestations WHERE build_id=?1",[id.to_string()],|r|r.get(0))?;
            ensure!(persisted == digest,"conflicting_attestation");
            tx.execute("INSERT INTO supply_chain_audit(action,target_id,result,timestamp) VALUES('build.attestation_created',?1,'verified',?2)",params![id.to_string(),Utc::now().to_rfc3339()])?;
            tx.commit()?;Ok(())
        }).await?;
        fault_barrier(self, "build_persisted").await?;
        self.envelope("build", id.to_string())
            .await?
            .context("persisted_attestation_missing")
    }
    pub async fn check_supply_policy(&self, id: BuildId) -> Result<PolicyDecision> {
        let result = self.attest_build(id).await;
        let mut violations = Vec::new();
        match result {
            Ok(envelope) => {
                let keys = self.sync_attestor_keys().await?;
                let (s, _) = crypto::verify(&envelope, &keys)?;
                if let ProvenancePredicate::Build(p) = s.predicate {
                    if p.build_definition
                        .external_parameters
                        .declared_dependencies
                        .iter()
                        .any(|d| !d.immutable)
                    {
                        violations.push(PolicyViolation {
                            code: "mutable_dependency".into(),
                            message: "A declared source is not cryptographically pinned.".into(),
                        });
                    }
                    let env = p.build_definition.internal_parameters;
                    if env.isolation != IsolationPolicy::Hardened
                        || !self.allowed_images.contains(&env.image_config_digest)
                    {
                        violations.push(PolicyViolation {code:"environment_not_allowed".into(),message:"The build environment does not meet the configured production policy.".into()});
                    }
                }
            }
            Err(_) => violations.push(PolicyViolation {
                code: "provenance_invalid_or_missing".into(),
                message: "Trusted provenance verification failed or evidence is unavailable."
                    .into(),
            }),
        }
        let decision = PolicyDecision {
            allowed: self.supply_policy != SupplyChainPolicy::Enforce || violations.is_empty(),
            mode: self.supply_policy,
            violations,
        };
        let mode = serde_json::to_value(decision.mode)?
            .as_str()
            .context("mode")?
            .to_owned();
        let allowed = decision.allowed;
        let violations = serde_json::to_string(&decision.violations)?;
        self.run(move |db| { db.execute("INSERT INTO supply_chain_decisions(build_id,mode,allowed,violations,evaluated_at) VALUES(?1,?2,?3,?4,?5)",params![id.to_string(),mode,allowed,violations,Utc::now().to_rfc3339()])?; Ok(()) }).await?;
        if !decision.allowed {
            self.supply_audit("supply_chain.policy_denied", id.to_string(), "denied")
                .await?;
        }
        Ok(decision)
    }
    pub async fn attest_release(&self, id: PublishId) -> Result<DsseEnvelope> {
        let keys = self.sync_attestor_keys().await?;
        let publication = self
            .publish_record(id)
            .await?
            .context("publication_missing")?;
        ensure!(
            publication.status == PublishStatus::Succeeded,
            "publication_not_successful"
        );
        let published = publication
            .result
            .as_ref()
            .context("publication_result_missing")?;
        let repository = self
            .attestation_repository
            .as_ref()
            .context("repository_verifier_unavailable")?;
        librehub_publisher::repository::verify_public_ref(
            repository,
            publication.channel,
            &published.published_ref.ref_name,
            &published.published_ref.commit,
            Duration::from_secs(60),
            self.data_dir.join("publishes"),
        )
        .await?;
        let source_build = self
            .get(publication.build_id)
            .await?
            .context("build_missing")?;
        let manifest = self.manifest(publication.build_id).await?;
        let prepared = librehub_publisher::artifact::prepare(
            self.data_dir.clone(),
            source_build,
            manifest,
            publication.architecture,
            Duration::from_secs(60),
        )
        .await?;
        ensure!(
            prepared.commit == published.published_ref.source_commit
                && prepared.ref_name == published.published_ref.ref_name,
            "publication_source_mismatch"
        );
        let build_envelope = self.attest_build(publication.build_id).await?;
        let (build_statement, build_digest) = crypto::verify(&build_envelope, &keys)?;
        let details = self
            .get_release_security_details(&id)
            .await?
            .context("sbom_pending")?;
        let sbom = self
            .read_sbom_file(&self.data_dir, &id)
            .await?
            .context("sbom_missing")?;
        ensure!(
            details.app_id == publication.app_id && crypto::sha256(&sbom) == details.sbom_sha256,
            "sbom_integrity"
        );
        let spdx: SbomDocument = serde_json::from_slice(&sbom)?;
        ensure!(
            spdx.spdx_version == "SPDX-2.3"
                && spdx.document_namespace.ends_with(&format!("/{id}"))
                && spdx.packages.iter().any(|p| p.name == publication.app_id
                    && p.hashes.get("SHA256") == Some(&published.published_ref.commit)),
            "sbom_release_mismatch"
        );
        let statement = ProvenanceStatement {
            statement_type: STATEMENT_V1.into(),
            predicate_type: RELEASE_V1.into(),
            subject: vec![AttestationSubject {
                name: published.published_ref.ref_name.to_string(),
                digest: crypto::digest("sha256", &published.published_ref.commit),
            }],
            predicate: ProvenancePredicate::Release(Box::new(ReleaseProvenance {
                publication_id: id,
                build_id: publication.build_id,
                app_id: publication.app_id.clone(),
                architecture: publication.architecture,
                channel: publication.channel.to_string(),
                repository: published.published_ref.repository_url.clone(),
                flatpak_ref: published.published_ref.ref_name.to_string(),
                build_statement_sha256: build_digest,
                build_artifact_sha256: build_statement.subject[0].digest["sha256"].clone(),
                source_ostree_commit: published.published_ref.source_commit.clone(),
                sbom_sha256: details.sbom_sha256.clone(),
                published_on: publication.updated_at,
            })),
        };
        crypto::verify_link(
            &statement,
            &build_statement,
            &crypto::sha256(&crypto::canonical(&build_statement)?),
        )?;
        if let Some(existing) = self.envelope("release", id.to_string()).await? {
            let (_, old) = crypto::verify(&existing, &keys)?;
            ensure!(
                old == crypto::sha256(&crypto::canonical(&statement)?),
                "release_evidence_changed"
            );
            return Ok(existing);
        }
        fault_barrier(self, "release_verified").await?;
        let envelope = self
            .attestor
            .as_ref()
            .context("attestor_unavailable")?
            .sign(&statement)?;
        fault_barrier(self, "release_signed").await?;
        let (_, digest) = crypto::verify(&envelope, &keys)?;
        let raw = serde_json::to_string(&envelope)?;
        let key = envelope.signatures[0].keyid.clone();
        self.run(move |db| {let tx = db.transaction()?;
            tx.execute("INSERT OR IGNORE INTO release_attestations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id.to_string(),publication.build_id.to_string(),publication.app_id,published_commit(&statement),details.sbom_sha256,digest,key,raw,Utc::now().to_rfc3339()])?;
            let persisted:String = tx.query_row("SELECT statement_sha256 FROM release_attestations WHERE publication_id=?1",[id.to_string()],|r|r.get(0))?;ensure!(persisted == digest,"conflicting_attestation");
            tx.execute("INSERT INTO supply_chain_audit(action,target_id,result,timestamp) VALUES('release.attestation_created',?1,'verified',?2)",params![id.to_string(),Utc::now().to_rfc3339()])?;tx.commit()?;Ok(())}).await?;
        fault_barrier(self, "release_persisted").await?;
        self.envelope("release", id.to_string())
            .await?
            .context("persisted_attestation_missing")
    }
}
fn published_commit(s: &ProvenanceStatement) -> &str {
    &s.subject[0].digest["sha256"]
}

/// Durable derivation backlog. Signing retry never calls publish; failed jobs retry on restart or operator request.
async fn run_inner(store: Store, shutdown: tokio_util::sync::CancellationToken) -> Result<()> {
    if store.attestor.is_none() {
        return Ok(());
    }
    store
        .run(|db| {
            db.execute(
                "UPDATE attestation_jobs SET state='pending' WHERE state='failed'",
                [],
            )?;
            Ok(())
        })
        .await?;
    while !shutdown.is_cancelled() {
        let job = store.run(|db| {
            db.execute("INSERT OR IGNORE INTO attestation_jobs(kind,target_id,state,updated_at) SELECT 'build',id,'pending',json_extract(record,'$.updated_at') FROM builds WHERE status='succeeded' AND json_extract(record,'$.result.environment') IS NOT NULL AND json_extract(record,'$.provenance') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM attestation_jobs j WHERE j.kind='build' AND j.target_id=builds.id) LIMIT 64",[])?;
            db.execute("INSERT OR IGNORE INTO attestation_jobs(kind,target_id,state,updated_at) SELECT 'release',p.id,'pending',json_extract(p.record,'$.updated_at') FROM publishes p JOIN build_attestations b ON b.build_id=p.build_id JOIN release_security s ON s.publication_id=p.id WHERE p.status='succeeded' AND NOT EXISTS(SELECT 1 FROM attestation_jobs j WHERE j.kind='release' AND j.target_id=p.id) LIMIT 64",[])?;
            Ok(db.query_row("SELECT kind,target_id FROM attestation_jobs WHERE state='pending' ORDER BY rowid LIMIT 1",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?)
        }).await?;
        if let Some((kind, id)) = job {
            let work = async {
                if kind == "build" {
                    store.attest_build(id.parse()?).await
                } else {
                    store.attest_release(id.parse()?).await
                }
            };
            let result = tokio::select! {_=shutdown.cancelled()=>return Ok(()),r=work=>r};
            let state = if result.is_ok() { "verified" } else { "failed" };
            if result.is_err() {
                store
                    .supply_audit(
                        if kind == "build" {
                            "build.attestation_failed"
                        } else {
                            "release.attestation_failed"
                        },
                        id.clone(),
                        "evidence_or_signing_failed",
                    )
                    .await?;
            }
            store.run(move |db| {db.execute("UPDATE attestation_jobs SET state=?3,attempts=attempts+1,error_code=?4,updated_at=?5 WHERE kind=?1 AND target_id=?2",params![kind,id,state,if state == "failed" {Some("evidence_or_signing_failed")} else {None},Utc::now().to_rfc3339()])?;Ok(())}).await?;
        } else {
            tokio::select! {_=shutdown.cancelled()=>{},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
        }
    }
    Ok(())
}

impl Store {
    pub async fn latest_reproducibility(
        &self,
        id: BuildId,
    ) -> Result<Option<ReproducibilityResult>> {
        self.run(move |db| {
            let row = db.query_row("SELECT rebuild_id,state,reason,original_content,rebuild_content,checked_at FROM reproducibility_attempts WHERE original_build_id=?1 ORDER BY id DESC LIMIT 1",[id.to_string()],|r|Ok((r.get::<_,Option<String>>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?))).optional()?;
            row.map(|(rebuild,state,reason,original_content,rebuild_content,at)|Ok(ReproducibilityResult {original_build_id:id,rebuild_id:rebuild.map(|s|s.parse()).transpose()?,state:serde_json::from_value(serde_json::json!(state))?,reason,original_content,rebuild_content,checked_at:at.parse()?})).transpose()
        }).await
    }
    pub async fn save_reproducibility(&self, r: ReproducibilityResult) -> Result<()> {
        self.run(move |db| {let tx=db.transaction()?;tx.execute("INSERT INTO reproducibility_attempts(original_build_id,rebuild_id,state,reason,original_content,rebuild_content,checked_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![r.original_build_id.to_string(),r.rebuild_id.map(|i|i.to_string()),serde_json::to_value(r.state)?.as_str().context("state")?,r.reason,r.original_content,r.rebuild_content,r.checked_at.to_rfc3339()])?;
            tx.execute("INSERT INTO supply_chain_audit(action,target_id,result,timestamp) VALUES('reproducibility.check_completed',?1,?2,?3)",params![r.original_build_id.to_string(),serde_json::to_value(r.state)?.as_str().context("state")?,r.checked_at.to_rfc3339()])?;tx.commit()?;Ok(())}).await
    }
    pub async fn verify_reproducibility(
        &self,
        id: BuildId,
        mut config: librehub_builder::DockerConfig,
    ) -> Result<ReproducibilityResult> {
        let original = self.get(id).await?.context("build_missing")?;
        let manifest = self.manifest(id).await?;
        let mut result = ReproducibilityResult {
            original_build_id: id,
            rebuild_id: None,
            state: ReproducibilityState::Inconclusive,
            reason: "rebuild_interrupted_or_failed".into(),
            original_content: None,
            rebuild_content: None,
            checked_at: Utc::now(),
        };
        let environment = original.result.as_ref().and_then(|r| r.environment.clone());
        if original.provenance.is_none()
            || environment.is_none()
            || original.status != BuildStatus::Succeeded
            || crypto::declared_dependencies(&manifest)
                .iter()
                .any(|d| !d.immutable)
        {
            result.state = ReproducibilityState::Unsupported;
            result.reason = "immutable_source_environment_or_dependencies_unavailable".into();
            self.save_reproducibility(result.clone()).await?;
            return Ok(result);
        }
        let env = environment.context("environment_missing")?;
        config.image = env.image_config_digest.clone();
        config.network = env.network.clone();
        config.isolation = env.isolation;
        config.writable_bytes = env.writable_bytes.max(1);
        let rebuild = self.insert(manifest.clone(), original.architecture).await?;
        result.rebuild_id = Some(rebuild.id);
        // Persist an inconclusive attempt before execution so a crash remains observable.
        self.save_reproducibility(result.clone()).await?;
        self.supply_audit("reproducibility.check_started", id.to_string(), "started")
            .await?;
        let work = async {
            let root = self.data_dir.clone();
            let provenance = original.provenance.clone().context("source_missing")?;
            let m = manifest.clone();
            tokio::task::spawn_blocking(move || {
                librehub_source::verify_manifest_snapshot(&root, id, &provenance, &m)
            })
            .await??;
            let snapshot = librehub_publisher::artifact::controlled_file(
                &self.data_dir,
                &format!("sources/{id}.tar"),
            )?;
            use std::io::{Read, Write};
            let mut bytes = Vec::new();
            snapshot
                .take(librehub_source::MAX_SNAPSHOT_BYTES + 1)
                .read_to_end(&mut bytes)?;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(
                    self.data_dir
                        .join("sources")
                        .join(format!("{}.tar", rebuild.id)),
                )?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            let mut next = rebuild.clone();
            next.provenance = original.provenance.clone();
            self.run(move |db| {
                db.execute(
                    "UPDATE builds SET record=?2 WHERE id=?1 AND status='queued'",
                    params![next.id.to_string(), serde_json::to_string(&next)?],
                )?;
                Ok(())
            })
            .await?;
            let executor = Arc::new(librehub_builder::DockerExecutor::new(config)?);
            crate::worker::Supervisor::new(self.clone())
                .execute(rebuild.id, executor)
                .await?;
            let rebuilt = self.get(rebuild.id).await?.context("rebuild_missing")?;
            ensure!(
                rebuilt.status == BuildStatus::Succeeded
                    && rebuilt.result.as_ref().and_then(|r| r.environment.as_ref()) == Some(&env),
                "rebuild_environment_or_execution_mismatch"
            );
            let a = normalized_content(self, original, manifest.clone()).await?;
            let b = normalized_content(self, rebuilt, manifest).await?;
            Ok::<_, anyhow::Error>((a, b))
        }
        .await;
        match work {
            Ok((a, b)) => {
                result.state = if a == b {
                    ReproducibilityState::Reproduced
                } else {
                    ReproducibilityState::NonReproducible
                };
                result.reason = if a == b {
                    "ostree_content_listing_matched"
                } else {
                    "ostree_content_listing_differed"
                }
                .into();
                result.original_content = Some(a);
                result.rebuild_content = Some(b);
            }
            Err(_) => {
                result.reason = "rebuild_execution_environment_or_comparison_failed".into();
            }
        }
        result.checked_at = Utc::now();
        self.save_reproducibility(result.clone()).await?;
        Ok(result)
    }
}
async fn normalized_content(
    store: &Store,
    build: BuildRecord,
    manifest: FlatpakManifest,
) -> Result<String> {
    let repo = librehub_publisher::artifact::prepare(
        store.data_dir.clone(),
        build.clone(),
        manifest,
        build.architecture,
        Duration::from_secs(60),
    )
    .await?;
    // OSTree file checksums include content, mode, ownership and xattrs. Directory
    // trees include names/order; commit dates, parent, signatures are intentionally excluded.
    let listing = librehub_publisher::artifact::command(
        "ostree",
        &[
            format!("--repo={}", repo.path.display()),
            "ls".into(),
            "--checksum".into(),
            "--recursive".into(),
            repo.commit.clone(),
            "/".into(),
        ],
        Duration::from_secs(60),
    )
    .await?;
    Ok(crypto::sha256(listing.as_bytes()))
}
impl Store {
    pub async fn run_retry_attestations(&self) -> Result<()> {
        self.run(|db| {
            db.execute(
                "UPDATE attestation_jobs SET state='pending',error_code=NULL WHERE state='failed'",
                [],
            )?;
            Ok(())
        })
        .await
    }
}
impl Store {
    pub async fn last_supply_policy(&self, id: BuildId) -> Result<Option<PolicyDecision>> {
        self.run(move |db| {
            let row=db.query_row("SELECT mode,allowed,violations FROM supply_chain_decisions WHERE build_id=?1 ORDER BY id DESC LIMIT 1",[id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,String>(2)?))).optional()?;
            row.map(|(mode,allowed,violations)|Ok(PolicyDecision {mode:serde_json::from_value(serde_json::json!(mode))?,allowed,violations:serde_json::from_str(&violations)?})).transpose()
        }).await
    }
}

async fn fault_barrier(store: &Store, stage: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    {
        if std::env::var("LIBREHUB_TEST_ATTESTATION_FAULT_STAGE")
            .ok()
            .as_deref()
            == Some(stage)
        {
            let path = store.data_dir.join(format!("attestation-fault-{stage}"));
            tokio::fs::write(path, b"ready").await?;
            std::future::pending::<()>().await;
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (store, stage);
    }
    Ok(())
}

pub async fn run(store: Store, shutdown: tokio_util::sync::CancellationToken) -> Result<()> {
    let result = run_inner(store, shutdown.clone()).await;
    if result.is_err() {
        shutdown.cancel();
    }
    result
}
