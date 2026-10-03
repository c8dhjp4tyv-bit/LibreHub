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
    let worker_shutdown = shutdown.clone();
    let worker = tokio::spawn(async move {
        let result = supervisor.run(executor).await;
        if let Err(ref e) = result {
            tracing::error!(error = %e, "Build supervisor stopped");
        }
        worker_shutdown.cancel();
        result
    });
    let signal_shutdown = shutdown.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        signal_shutdown.cancel();
    });
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await;
    shutdown.cancel();
    // The executor stops containers before shutdown returns; pending jobs remain durable.
    let worker_result = worker.await.context("Worker task failed")?;
    signal.abort();
    result?;
    worker_result
}
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! { result = tokio::signal::ctrl_c() => {
                    if let Err(e) = result { tracing::error!(error = %e, "Cannot listen for Ctrl-C"); }
                }, _ = terminate.recv() => {} }
            }
            Err(e) => tracing::error!(error = %e, "Cannot listen for SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "Cannot listen for Ctrl-C");
    }
}
