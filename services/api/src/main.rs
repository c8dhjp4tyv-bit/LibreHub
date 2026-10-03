use anyhow::Context;
use librehub_api::{ApiState, router, store::Store, worker::Supervisor};
use librehub_builder::{DockerConfig, DockerExecutor};
use librehub_common::Architecture;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let data_dir = PathBuf::from(env("LIBREHUB_DATA_DIR", "data"));
    let address: SocketAddr = env("LIBREHUB_BIND", "127.0.0.1:8080")
        .parse()
        .context("Invalid LIBREHUB_BIND")?;
    let config = DockerConfig {
        binary: PathBuf::from(env("LIBREHUB_DOCKER", "docker")),
        image: env("LIBREHUB_WORKER_IMAGE", "librehub-worker:m1"),
        network: env("LIBREHUB_WORKER_NETWORK", "none"),
        timeout: Duration::from_secs(
            env("LIBREHUB_BUILD_TIMEOUT_SECONDS", "1800")
                .parse()
                .context("Invalid build timeout")?,
        ),
        max_artifact_bytes: env("LIBREHUB_MAX_ARTIFACT_BYTES", "1073741824")
            .parse()
            .context("Invalid artifact size limit")?,
        ..DockerConfig::default()
    };
    let executor = Arc::new(DockerExecutor::new(config)?);
    let store = tokio::task::spawn_blocking(move || Store::open(&data_dir)).await??;
    let supervisor = Supervisor::new(store);
    supervisor
        .recover(executor.as_ref())
        .await
        .context("Cannot recover interrupted builds")?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "LibreHub M1 API listening");
    let app = router(ApiState {
        supervisor: supervisor.clone(),
        architecture: Architecture::native(),
    });
    let shutdown = supervisor.shutdown.clone();
    let server_shutdown = shutdown.clone();
    let mut worker = tokio::spawn(async move { supervisor.run(executor).await });
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
    });
    let mut worker_result = None;
    let mut server_result = None;
    let mut signal_result = Ok(());
    tokio::select! {
        result = &mut worker => worker_result = Some(result),
        result = &mut server => server_result = Some(result),
        result = shutdown_signal() => signal_result = result,
    }
    shutdown.cancel();
    tracing::info!("Stopping HTTP server and active build");
    let worker_result = match worker_result {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(45), &mut worker)
            .await
            .context("Worker shutdown timed out; restart will recover the active build")?,
    };
    let server_result = match server_result {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(10), &mut server)
            .await
            .context("HTTP shutdown timed out")?,
    };
    signal_result.context("Cannot listen for shutdown signals")?;
    worker_result.context("Worker task failed")??;
    server_result.context("HTTP server task failed")??;
    Ok(())
}
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
