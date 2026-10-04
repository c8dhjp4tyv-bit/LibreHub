//! Durable bounded catalog supervisor. Publication success never depends on indexing success.
use crate::store::Store;
use librehub_publisher::repository::RepositoryConfig;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct CatalogWorker {
    pub store: Store,
    pub repository: Option<RepositoryConfig>,
    pub running: Arc<AtomicBool>,
    pub shutdown: CancellationToken,
}
impl CatalogWorker {
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
        self.store.catalog_recover().await?;
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
                && let Some(publication) = self.store.catalog_claim().await?
            {
                let build = self
                    .store
                    .get(publication.build_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Catalog source missing"))?;
                let manifest = self.store.manifest(publication.build_id).await?;
                let extraction = librehub_catalog::extract::extract(
                    self.store.data_dir.clone(),
                    build,
                    manifest,
                    publication.clone(),
                    repository.clone(),
                );
                let result = tokio::select! { _=self.shutdown.cancelled()=>return Ok(()), result=tokio::time::timeout(std::time::Duration::from_secs(300),extraction)=>result };
                match result {
                    Ok(Ok(extracted)) => self.store.catalog_commit(publication, extracted).await?,
                    _ => {
                        tracing::warn!(publication_id=%publication.id,"Catalog metadata indexing failed; publication remains valid");
                        self.store.catalog_failed(publication.id).await?;
                    }
                }
                continue;
            }
            tokio::select! {_=self.shutdown.cancelled()=>{},_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
        }
        Ok(())
    }
    pub async fn ready(&self) -> bool {
        self.repository.is_some()
            && self.running.load(Ordering::Acquire)
            && self.store.catalog_ready().await
    }
}
