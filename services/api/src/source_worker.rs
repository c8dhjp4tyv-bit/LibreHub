//! Persistent source supervisor. One source fetch at a time; handoff is idempotent.
use crate::{publishing::Publishing, worker::Supervisor};
use librehub_common::*;
use librehub_source::{GitSource, SourceProvider};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct SourceWorker {
    pub supervisor: Supervisor,
    pub provider: Arc<dyn SourceProvider>,
    pub publishing: Option<Publishing>,
    pub wake: Arc<Notify>,
    pub running: Arc<AtomicBool>,
}
impl SourceWorker {
    pub fn new(
        supervisor: Supervisor,
        provider: Arc<dyn SourceProvider>,
        publishing: Option<Publishing>,
    ) -> Self {
        Self {
            supervisor,
            provider,
            publishing,
            wake: Arc::new(Notify::new()),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
    pub async fn recover(&self) -> anyhow::Result<()> {
        // Staging is disposable; snapshots committed before handoff are content checked/reused.
        let staging = self.supervisor.store.data_dir.join("source-tmp");
        if staging.exists() {
            tokio::fs::remove_dir_all(&staging).await?;
        }
        tokio::fs::create_dir_all(staging).await?;
        tokio::fs::create_dir_all(self.supervisor.store.data_dir.join("sources")).await?;
        Ok(())
    }
    pub async fn ready(&self) -> bool {
        if !self.running.load(Ordering::Acquire) {
            return false;
        }
        let version = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::process::Command::new("git")
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .arg("--version")
                .output(),
        )
        .await;
        version.is_ok_and(|v| v.is_ok_and(|v| v.status.success()))
            && self.supervisor.store.database_ready().await
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::Release);
        let result = self.run_inner().await;
        self.running.store(false, Ordering::Release);
        if result.is_err() {
            self.supervisor.shutdown.cancel();
        }
        result
    }
    async fn run_inner(&self) -> anyhow::Result<()> {
        loop {
            if self.supervisor.shutdown.is_cancelled() {
                return Ok(());
            }
            self.auto_publish().await?;
            if let Some(event) = self.supervisor.store.pending_source().await? {
                self.fault_point("queued").await?;
                self.process(event).await?;
                continue;
            }
            tokio::select! {_=self.supervisor.shutdown.cancelled()=>return Ok(()),_=self.wake.notified()=>{},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
        }
    }
    pub async fn process(&self, mut event: SourceEvent) -> anyhow::Result<()> {
        let store = &self.supervisor.store;
        let current = store
            .project(event.project_id, event.policy.owner_developer_id)
            .await?;
        if current.is_none_or(|p| p.status != ProjectStatus::Active) {
            event.status = SourceEventStatus::Ignored;
            event.processed_at = Some(chrono::Utc::now());
            store.save_source(event).await?;
            return Ok(());
        }
        if event.attempts >= 3 {
            event.status = SourceEventStatus::Failed;
            event.processed_at = Some(chrono::Utc::now());
            event.error =
                Some(librehub_source::SourceError::new("source_retries_exhausted").failure());
            store.save_source(event).await?;
            return Ok(());
        }
        event.attempts += 1;
        event.status = SourceEventStatus::Resolving;
        store.save_source(event.clone()).await?;
        let operation = async {
            if event.revision.is_none() {
                let commit = self
                    .provider
                    .resolve_revision(&event.policy.repository, &event.source_ref)
                    .await?;
                event.revision = Some(SourceRevision {
                    repository: event.policy.repository.url.clone(),
                    commit,
                    source_ref: event.source_ref.clone(),
                    resolved_at: chrono::Utc::now(),
                });
                // Resolution is durable BEFORE fetching or any build side effect.
                store
                    .save_source(event.clone())
                    .await
                    .map_err(|_| librehub_source::SourceError::new("source_persistence_failed"))?;
            }
            event.status = SourceEventStatus::Fetching;
            store
                .save_source(event.clone())
                .await
                .map_err(|_| librehub_source::SourceError::new("source_persistence_failed"))?;
            self.fault_point("fetching")
                .await
                .map_err(|_| librehub_source::SourceError::new("source_storage_failed"))?;
            let revision = event
                .revision
                .clone()
                .ok_or_else(|| librehub_source::SourceError::new("source_revision_not_found"))?;
            tracing::info!(developer_id=%event.policy.owner_developer_id,project_id=%event.project_id,source_commit=%revision.commit,source_ref=%event.source_ref,build_id=%event.build_id,"Preparing immutable project source");
            let fetched = self
                .provider
                .fetch_source(
                    &event.policy.repository,
                    &revision.commit,
                    &store.data_dir.join("source-tmp"),
                )
                .await?;
            let provider = self.provider.clone();
            let manifest_path = event.policy.settings.manifest_path.clone();
            let prepared = tokio::task::spawn_blocking(move || {
                provider.discover_manifest(&fetched, manifest_path.as_deref())
            })
            .await
            .map_err(|_| librehub_source::SourceError::new("source_preparation_failed"))??;
            let path = store
                .data_dir
                .join("sources")
                .join(format!("{}.tar", event.build_id));
            let root = store.data_dir.join("sources");
            let bytes = prepared.archive;
            let expected = prepared.snapshot.sha256.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                use sha2::{Digest, Sha256};
                use std::io::Write;
                if path.exists() {
                    let meta = std::fs::symlink_metadata(&path)?;
                    anyhow::ensure!(
                        meta.is_file() && meta.len() <= librehub_source::MAX_SNAPSHOT_BYTES,
                        "Invalid retained source snapshot"
                    );
                    let old = std::fs::read(&path)?;
                    anyhow::ensure!(
                        format!("{:x}", Sha256::digest(&old)) == expected,
                        "Retained source snapshot changed"
                    );
                    return Ok(());
                }
                let mut temp = tempfile::NamedTempFile::new_in(&root)?;
                temp.write_all(&bytes)?;
                temp.as_file().sync_all()?;
                temp.persist_noclobber(&path)?;
                std::fs::File::open(root)?.sync_all()?;
                Ok(())
            })
            .await
            .map_err(|_| librehub_source::SourceError::new("source_storage_failed"))?
            .map_err(|_| librehub_source::SourceError::new("source_snapshot_integrity"))?;
            event.status = SourceEventStatus::Handoff;
            store
                .save_source(event.clone())
                .await
                .map_err(|_| librehub_source::SourceError::new("source_persistence_failed"))?;
            self.fault_point("handoff")
                .await
                .map_err(|_| librehub_source::SourceError::new("source_storage_failed"))?;
            let provenance = BuildProvenance {
                project_id: event.project_id,
                revision,
                manifest_path: prepared.manifest_path,
                snapshot: prepared.snapshot,
                trigger: event.trigger,
                trigger_event_id: event.id,
                policy_version: event.policy.policy_version,
            };
            store
                .handoff_source(
                    event.id,
                    prepared.manifest,
                    provenance,
                    Architecture::native(),
                )
                .await
                .map_err(|e| {
                    if e.is::<crate::store::QueueFull>() {
                        librehub_source::SourceError::transient("build_queue_full")
                    } else {
                        librehub_source::SourceError::new("source_handoff_failed")
                    }
                })?;
            self.supervisor.wake.notify_one();
            Ok::<_, librehub_source::SourceError>(())
        };
        let outcome = tokio::select! {
            biased;
            _=self.supervisor.shutdown.cancelled()=>return Ok(()),
            result=tokio::time::timeout(Duration::from_secs(180),operation)=>result.unwrap_or_else(|_|Err(librehub_source::SourceError::transient("source_fetch_timeout"))),
        };
        if let Err(error) = outcome {
            if error.code == "source_persistence_failed" {
                anyhow::bail!("Source journal operation failed")
            }
            event.error = Some(error.failure());
            tracing::warn!(project_id=%event.project_id,build_id=%event.build_id,error_code=error.code,"Source event failed");
            if error.retryable && event.attempts < 3 {
                event.status = SourceEventStatus::Queued;
                store.save_source(event).await?;
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(2))=>{},_=self.supervisor.shutdown.cancelled()=>{}};
            } else {
                event.status = SourceEventStatus::Failed;
                event.processed_at = Some(chrono::Utc::now());
                store.save_source(event).await?;
            }
        }
        Ok(())
    }
    async fn fault_point(&self, stage: &str) -> anyhow::Result<()> {
        // Deterministic SIGKILL barriers for the disposable TLS fixture only.
        // Release builds compile this out; no HTTP input can enable fault injection.
        #[cfg(debug_assertions)]
        if std::env::var("LIBREHUB_TEST_SOURCE_REPOSITORY").as_deref()
            == Ok("https://git.librehub.test/fixture.git")
            && std::env::var("LIBREHUB_TEST_SOURCE_FAULT_STAGE").as_deref() == Ok(stage)
        {
            let path = self
                .supervisor
                .store
                .data_dir
                .join(format!("source-fault-{stage}"));
            tokio::fs::write(path, b"ready").await?;
            self.supervisor.shutdown.cancelled().await;
        }
        let _ = stage;
        Ok(())
    }
    async fn auto_publish(&self) -> anyhow::Result<()> {
        let store = &self.supervisor.store;
        for event in store.auto_publish_candidates().await? {
            let Some(build) = store.get(event.build_id).await? else {
                continue;
            };
            if build.status != BuildStatus::Succeeded
                || !store.auto_policy_valid(event.clone()).await?
            {
                store.finish_auto_publish(event.id, "skipped").await?;
                continue;
            }
            let Some(publishing) = &self.publishing else {
                continue;
            };
            let Some(channel) = event.policy.settings.auto_publish_channel else {
                continue;
            };
            let Ok(_permit) = publishing.admission.clone().try_acquire_owned() else {
                continue;
            };
            let manifest = store.manifest(event.build_id).await?;
            if let Err(error) = publishing
                .publisher
                .eligible(build, manifest, store.data_dir.clone())
                .await
            {
                if !error.retryable() {
                    store.finish_auto_publish(event.id, "failed").await?;
                }
                continue;
            }
            // Admission rechecks current policy and journals automation in the SAME transaction.
            match store.enqueue_auto_publish(event.id, channel).await {
                Ok(Some(record)) => {
                    tracing::info!(project_id=%event.project_id,build_id=%event.build_id,publish_id=%record.id,"Project publication queued");
                    publishing.wake.notify_one();
                }
                Ok(None) => {}
                Err(error) if error.is::<crate::publication_store::AdmissionError>() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
/// Public HTTPS only; the TLS fixture exception is opt-in operator configuration.
pub fn git_from_env() -> anyhow::Result<GitSource> {
    let Some(repository) = std::env::var("LIBREHUB_TEST_SOURCE_REPOSITORY").ok() else {
        return Ok(GitSource::default());
    };
    anyhow::ensure!(
        repository == "https://git.librehub.test/fixture.git",
        "Invalid test repository identity"
    );
    let ca_file = std::env::var("LIBREHUB_TEST_SOURCE_CA_FILE")?;
    Ok(GitSource {
        test_origin: Some(librehub_source::TestOrigin {
            repository,
            address: std::net::Ipv4Addr::LOCALHOST,
            port: std::env::var("LIBREHUB_TEST_SOURCE_PORT")?.parse()?,
            ca_file: ca_file.into(),
        }),
    })
}
