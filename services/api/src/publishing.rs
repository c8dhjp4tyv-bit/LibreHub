use crate::store::Store;
use async_trait::async_trait;
use librehub_common::*;
use librehub_publisher::{
    PublishError, PublishJob, PublishJournal, Publisher, repository::RepositoryConfig,
};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Publishing {
    pub store: Store,
    pub publisher: Arc<dyn Publisher>,
    pub repository: RepositoryConfig,
    pub wake: Arc<Notify>,
    pub admission: Arc<Semaphore>,
    pub running: Arc<AtomicBool>,
    pub shutdown: CancellationToken,
    concurrency: usize,
}
#[async_trait]
impl PublishJournal for Store {
    async fn save(&self, record: PublishRecord) -> Result<(), PublishError> {
        self.save_publication(record)
            .await
            .map_err(|_| PublishError::Persistence)
    }
}
impl Publishing {
    pub fn new(
        store: Store,
        publisher: Arc<dyn Publisher>,
        repository: RepositoryConfig,
        concurrency: usize,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=8).contains(&concurrency),
            "Publisher concurrency must be 1–8"
        );
        Ok(Self {
            store,
            publisher,
            repository,
            wake: Arc::new(Notify::new()),
            admission: Arc::new(Semaphore::new(2)),
            running: Arc::new(AtomicBool::new(false)),
            shutdown,
            concurrency,
        })
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::Release);
        let result = self.supervise().await;
        self.running.store(false, Ordering::Release);
        if result.is_err() {
            self.shutdown.cancel();
        }
        result
    }
    async fn supervise(&self) -> anyhow::Result<()> {
        let mut tasks = JoinSet::new();
        let mut active = HashSet::new();
        // On startup, reconcile all interrupted states, including suspended ones.
        let recovery: HashSet<_> = self
            .store
            .active_publications()
            .await?
            .into_iter()
            .filter(|r| r.status != PublishStatus::Queued)
            .map(|r| r.id)
            .collect();
        let mut recovered = HashSet::new();
        let mut fatal = None;
        loop {
            if !self.shutdown.is_cancelled() && fatal.is_none() {
                let mut seen_refs = HashSet::new();
                for record in self.store.active_publications().await? {
                    if tasks.len() >= self.concurrency {
                        break;
                    }
                    // Serialize releases of the same application/repository. An
                    // uncertain earlier release blocks superseding work too.
                    if !seen_refs.insert(format!(
                        "{}/{}/{}",
                        record.app_id, record.channel, record.architecture
                    )) {
                        continue;
                    }
                    if active.contains(&record.id)
                        || (record.needs_attention
                            && (!recovery.contains(&record.id) || recovered.contains(&record.id)))
                    {
                        continue;
                    }
                    let record = if record.status == PublishStatus::Queued {
                        let Some(claimed) = self.store.claim_publication(record.id).await? else {
                            continue;
                        };
                        claimed
                    } else {
                        record
                    };
                    active.insert(record.id);
                    recovered.insert(record.id);
                    let this = self.clone();
                    tasks.spawn(async move {
                        let id = record.id;
                        (id, this.execute(record).await)
                    });
                }
            }
            if (self.shutdown.is_cancelled() || fatal.is_some()) && tasks.is_empty() {
                return fatal.map_or(Ok(()), Err);
            }
            tokio::select! {
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok((id, result))) => { active.remove(&id); if let Err(e) = result { fatal = Some(e); self.shutdown.cancel(); } },
                        Some(Err(_)) => { fatal = Some(anyhow::anyhow!("Publication task stopped unexpectedly; restart to reconcile")); self.shutdown.cancel(); },
                        None => {},
                    }
                },
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
    async fn execute(&self, mut record: PublishRecord) -> anyhow::Result<()> {
        let build = self
            .store
            .get(record.build_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Publication source disappeared"))?;
        let manifest = self.store.manifest(record.build_id).await?;
        // A bounded retry loop reconciles persisted state before each subsequent attempt.
        for attempt in 0..3 {
            record.attempts = record.attempts.saturating_add(1);
            record.needs_attention = false;
            record.error = None;
            self.store.save_publication(record.clone()).await?;
            let result = self
                .publisher
                .publish(
                    PublishJob {
                        record: record.clone(),
                        build: build.clone(),
                        manifest: manifest.clone(),
                        data_dir: self.store.data_dir.clone(),
                    },
                    &self.store,
                )
                .await;
            // Read the latest journal state; the publisher advanced it before side effects.
            record = self
                .store
                .publish_record(record.id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Publication disappeared"))?;
            match result {
                Ok(result) => {
                    record.status = PublishStatus::Succeeded;
                    record.result = Some(result);
                    record.error = None;
                    self.store.save_publication(record.clone()).await?;
                    tracing::info!(publish_id=%record.id, build_id=%record.build_id, "Publication verified in signed public repository");
                    return Ok(());
                }
                Err(PublishError::Persistence) => {
                    anyhow::bail!("Cannot persist publication progress")
                }
                Err(error) => {
                    tracing::warn!(publish_id=%record.id, build_id=%record.build_id, code=error.code(), "Publication operation failed");
                    let retry = error.retryable();
                    record.error = Some(error.failure());
                    // Any ambiguous state must remain reconcilable. Failure here must
                    // not advertise rollback or allow a new conflicting publication.
                    let suspend = retry
                        || matches!(error, PublishError::Uncertain | PublishError::Malformed)
                        || record.status == PublishStatus::Publishing;
                    if suspend {
                        record.needs_attention = true;
                    } else {
                        record.status = PublishStatus::Failed;
                    }
                    self.store.save_publication(record.clone()).await?;
                    if !retry || attempt == 2 || self.shutdown.is_cancelled() {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
                }
            }
        }
        Ok(())
    }
    pub async fn storage_ready(&self) -> bool {
        let root = self.store.data_dir.join("publishes");
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&root).ok()?;
            if std::fs::symlink_metadata(&root)
                .ok()?
                .file_type()
                .is_symlink()
            {
                return None;
            }
            let probe = tempfile::NamedTempFile::new_in(root).ok()?;
            probe.as_file().sync_all().ok()?;
            Some(())
        })
        .await
        .is_ok_and(|r| r.is_some())
    }
}
