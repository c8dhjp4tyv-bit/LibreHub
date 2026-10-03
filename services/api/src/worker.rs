//! A durable SQLite queue with one asynchronous executor, independent of HTTP requests.
use crate::store::Store;
use async_trait::async_trait;
use chrono::Utc;
use librehub_builder::{BuildExecutor, BuildJob, ExecutorError, LogSink};
use librehub_common::*;
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Supervisor {
    pub store: Store,
    pub wake: Arc<Notify>,
    pub shutdown: CancellationToken,
}
struct PersistentLogs {
    store: Store,
    id: BuildId,
}
#[async_trait]
impl LogSink for PersistentLogs {
    async fn append(&self, entry: BuildLogEntry) -> anyhow::Result<()> {
        self.store.append(self.id, entry).await
    }
}
impl Supervisor {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            wake: Arc::new(Notify::new()),
            shutdown: CancellationToken::new(),
        }
    }
    pub async fn recover(&self, executor: &dyn BuildExecutor) -> anyhow::Result<()> {
        for id in self.store.interrupted().await? {
            // Fail startup if cleanup is uncertain. Do not launch duplicate builds.
            executor.cleanup(id).await?;
            if self
                .store
                .get(id)
                .await?
                .is_some_and(|record| record.status.is_terminal())
            {
                continue;
            }
            self.remove_artifacts(id).await?;
            self.store
                .transition(
                    id,
                    BuildStatus::Failed,
                    None,
                    Some(BuildError {
                        code: "worker_restarted".into(),
                        message: "Worker stopped before this build completed; submit it again"
                            .into(),
                    }),
                )
                .await?;
        }
        // Only service-owned UUID workspaces live here; the data directory is trusted.
        let scratch = self.store.data_dir.join("tmp");
        if scratch.exists() {
            tokio::fs::remove_dir_all(&scratch).await?;
        }
        Ok(())
    }
    pub async fn run(self, executor: Arc<dyn BuildExecutor>) -> anyhow::Result<()> {
        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }
            if let Some(id) = self.store.pending().await?.first().copied() {
                self.execute(id, executor.clone()).await?;
                continue;
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return Ok(()),
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
    async fn execute(&self, id: BuildId, executor: Arc<dyn BuildExecutor>) -> anyhow::Result<()> {
        let claimed = self
            .store
            .transition(id, BuildStatus::Validating, None, None)
            .await?;
        if claimed.status.is_terminal() {
            return Ok(());
        }
        let manifest = self.store.manifest(id).await?;
        // Revalidate stored input so recovery cannot bypass the validator.
        if let Err(validation) =
            librehub_validator::validate(&serde_json::to_string(&manifest)?, ManifestFormat::Json)
        {
            self.store
                .transition(
                    id,
                    BuildStatus::Failed,
                    None,
                    Some(BuildError {
                        code: "validation_failed".into(),
                        message: serde_json::to_string(&validation)?,
                    }),
                )
                .await?;
            return Ok(());
        }
        let record = self
            .store
            .transition(id, BuildStatus::Building, None, None)
            .await?;
        let logs: Arc<dyn LogSink> = Arc::new(PersistentLogs {
            store: self.store.clone(),
            id,
        });
        logs.append(BuildLogEntry {
            sequence: 0,
            timestamp: Utc::now(),
            stream: LogStream::System,
            message: "Starting isolated worker".into(),
        })
        .await?;
        let cancel = CancellationToken::new();
        if record.cancellation_requested || self.shutdown.is_cancelled() {
            cancel.cancel();
        }
        let job = BuildJob {
            id,
            manifest,
            architecture: record.architecture,
            data_dir: self.store.data_dir.clone(),
        };
        let exec_cancel = cancel.clone();
        let exec = executor.clone();
        // JoinError isolates a faulty executor panic from the API and supervisor.
        let mut task = tokio::spawn(async move { exec.execute(job, logs, exec_cancel).await });
        let mut poll = tokio::time::interval(Duration::from_millis(200));
        let outcome = loop {
            tokio::select! {
                result = &mut task => break result,
                _ = self.shutdown.cancelled(), if !cancel.is_cancelled() => cancel.cancel(),
                _ = poll.tick() => match self.store.get(id).await {
                    Ok(Some(record)) if record.cancellation_requested => cancel.cancel(),
                    Ok(_) => {},
                    Err(e) => {
                        cancel.cancel();
                        // Wait for actual teardown before propagating a storage failure.
                        match task.await {
                            Ok(Ok(_)) => {},
                            Ok(Err(error)) => tracing::warn!(%id, %error, "Executor stopped after storage failure"),
                            Err(error) => {
                                tracing::error!(%id, %error, "Executor task failed during teardown");
                                executor.cleanup(id).await?;
                            },
                        }
                        return Err(e);
                    }
                },
            }
        };
        let outcome = match outcome {
            Ok(result) => result,
            Err(e) => {
                executor.cleanup(id).await?;
                Err(ExecutorError::Infrastructure(anyhow::anyhow!(
                    "Executor task failed: {e}"
                )))
            }
        };
        let cleanup_failed = matches!(&outcome, Err(ExecutorError::Cleanup(_)));
        let latest = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Build disappeared"))?;
        let (status, result, error) = match outcome {
            Ok(_) if latest.cancellation_requested || self.shutdown.is_cancelled() => {
                (BuildStatus::Cancelled, None, None)
            }
            Ok(result) => (BuildStatus::Succeeded, Some(result), None),
            Err(ExecutorError::Cancelled) => (BuildStatus::Cancelled, None, None),
            Err(e) => {
                tracing::warn!(%id, error = %e, "Build failed");
                let result = if let ExecutorError::Exit(code) = &e {
                    Some(BuildResult {
                        exit_code: *code,
                        artifacts: vec![],
                    })
                } else {
                    None
                };
                (
                    BuildStatus::Failed,
                    result,
                    Some(BuildError {
                        code: e.code().into(),
                        message: e.to_string(),
                    }),
                )
            }
        };
        if status != BuildStatus::Succeeded {
            self.remove_artifacts(id).await?;
        }
        let final_record = self.store.transition(id, status, result, error).await?;
        // Cover a cancel transaction racing with the success commit.
        if final_record.status == BuildStatus::Cancelled {
            self.remove_artifacts(id).await?;
        }
        self.store
            .append(
                id,
                BuildLogEntry {
                    sequence: 0,
                    timestamp: Utc::now(),
                    stream: LogStream::System,
                    message: format!("Build finished: {:?}", final_record.status).to_lowercase(),
                },
            )
            .await?;
        if cleanup_failed {
            anyhow::bail!("Container cleanup failed for build {id}; stopping the supervisor");
        }
        Ok(())
    }
    async fn remove_artifacts(&self, id: BuildId) -> anyhow::Result<()> {
        let path = self
            .store
            .data_dir
            .join("builds")
            .join(id.to_string())
            .join("artifacts");
        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
