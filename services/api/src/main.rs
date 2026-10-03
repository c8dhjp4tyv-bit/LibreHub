use anyhow::Context;
use librehub_api::{
    ApiState, config::AppConfig, publishing::Publishing, router_with_publisher, store::Store,
    worker::Supervisor,
};
use librehub_builder::DockerExecutor;
use librehub_common::Architecture;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = AppConfig::from_env()?;
    if let Some(publishing) = &config.publishing {
        publishing.repository.verify_key().await.context("Repository public key must match the configured fingerprint and contain no private keys")?;
    }
    let address = config.bind;
    let executor = Arc::new(DockerExecutor::new(config.builder)?);
    let data_dir = config.data_dir;
    let database_path = config.database_path;
    let store =
        tokio::task::spawn_blocking(move || Store::open_at(&data_dir, database_path.as_deref()))
            .await??;
    let supervisor = Supervisor::new(store);
    supervisor
        .recover(executor.as_ref())
        .await
        .context("Cannot recover interrupted builds")?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let publishing = config
        .publishing
        .map(|config| {
            Publishing::new(
                supervisor.store.clone(),
                Arc::new(config.publisher()?),
                config.repository,
                config.concurrency,
                supervisor.shutdown.clone(),
            )
        })
        .transpose()?;
    let publishing_task = publishing
        .clone()
        .map(|service| tokio::spawn(service.run()));
    tracing::info!(%address, "LibreHub API listening");
    let app = router_with_publisher(
        ApiState {
            supervisor: supervisor.clone(),
            architecture: Architecture::native(),
        },
        publishing,
    );
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
    worker_result?;
    if let Some(task) = publishing_task {
        task.await.context("Publisher task failed")??;
    }
    Ok(())
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
