//! Executor boundary: the API supervises work; only disposable containers run builds.
mod docker;
pub use docker::{DockerConfig, DockerExecutor};

use async_trait::async_trait;
use librehub_common::{Architecture, BuildId, BuildLogEntry, BuildResult, FlatpakManifest};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("Build cancelled")]
    Cancelled,
    #[error("Build exceeded its time limit")]
    Timeout,
    #[error("Build process exited with code {0:?}")]
    Exit(Option<i32>),
    #[error("Cannot clean build container: {0:#}")]
    Cleanup(anyhow::Error),
    #[error("{0:#}")]
    Infrastructure(#[from] anyhow::Error),
}
impl ExecutorError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Timeout => "build_timeout",
            Self::Exit(_) => "build_failed",
            Self::Infrastructure(_) => "executor_error",
            Self::Cleanup(_) => "container_cleanup_failed",
        }
    }
}

#[async_trait]
pub trait LogSink: Send + Sync {
    async fn append(&self, entry: BuildLogEntry) -> anyhow::Result<()>;
}
#[derive(Clone)]
pub struct BuildJob {
    pub id: BuildId,
    pub manifest: FlatpakManifest,
    pub architecture: Architecture,
    pub data_dir: PathBuf,
    pub source_snapshot: Option<librehub_common::SourceSnapshot>,
}
#[async_trait]
pub trait BuildExecutor: Send + Sync {
    async fn execute(
        &self,
        job: BuildJob,
        logs: Arc<dyn LogSink>,
        cancel: CancellationToken,
    ) -> Result<BuildResult, ExecutorError>;
    /// Remove abandoned execution environments before recovering persistent state.
    async fn cleanup(&self, id: BuildId) -> anyhow::Result<()>;
}

pub const IMPLEMENTATION_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+git.",
    env!("LIBREHUB_BUILDER_REVISION")
);
