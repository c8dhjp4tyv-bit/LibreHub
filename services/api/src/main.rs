use anyhow::Context;
use librehub_api::{
    ApiState, config::AppConfig, publishing::Publishing, store::Store, worker::Supervisor,
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
    let catalog_config = librehub_api::catalog_http::CatalogConfig::from_env()?;
    let executor = Arc::new(DockerExecutor::new(config.builder)?);
    let data_dir = config.data_dir;
    let database_path = config.database_path;
    let store_data_dir = data_dir.clone();
    let store = tokio::task::spawn_blocking(move || {
        Store::open_at(&store_data_dir, database_path.as_deref())
    })
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
    let catalog_worker = librehub_api::catalog_worker::CatalogWorker::new(
        supervisor.store.clone(),
        publishing.as_ref().map(|p| p.repository.clone()),
        supervisor.shutdown.clone(),
    );
    let catalog_task = tokio::spawn(catalog_worker.clone().run());
    let catalog_router =
        librehub_api::catalog_http::router(librehub_api::catalog_http::CatalogHttp {
            store: supervisor.store.clone(),
            api_public_url: catalog_config.api_public_url.clone(),
            repository: publishing.as_ref().map(|p| p.repository.clone()),
            page_size: catalog_config.page_size,
        });
    let publishing_task = publishing
        .clone()
        .map(|service| tokio::spawn(service.run()));
    tracing::info!(%address, "LibreHub API listening");
    let source_worker = librehub_api::source_worker::SourceWorker::new(
        supervisor.clone(),
        Arc::new(librehub_api::source_worker::git_from_env()?),
        publishing.clone(),
    );
    source_worker.recover().await?;
    let key = supervisor.store.platform_key().await?;
    let source_task = tokio::spawn(source_worker.clone().run());
    let app = librehub_api::platform::router(
        ApiState {
            supervisor: supervisor.clone(),
            architecture: Architecture::native(),
        },
        publishing.clone(),
        librehub_api::platform::Platform {
            worker: source_worker,
            key,
        },
    );
    let security_worker = librehub_api::security_worker::SecurityWorker::new(
        supervisor.store.clone(),
        publishing.as_ref().map(|p| p.repository.clone()),
        supervisor.shutdown.clone(),
    );
    let security_task = tokio::spawn(security_worker.clone().run());
    let mut security_http_state = librehub_api::security_http::SecurityHttp::new(
        supervisor.store.clone(),
        data_dir.clone(),
        catalog_config.api_public_url.clone(),
    );
    security_http_state.trusted_proxies = std::env::var("LIBREHUB_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter(|ip| !ip.trim().is_empty())
        .map(|ip| ip.trim().parse())
        .collect::<Result<Vec<_>, _>>()
        .context("LIBREHUB_TRUSTED_PROXIES must contain comma-separated IP addresses")?;
    let sec_public = librehub_api::security_http::public_router(security_http_state.clone());
    let sec_dev = librehub_api::security_http::developer_router(security_http_state.clone())
        .route_layer(axum::middleware::from_fn_with_state(
            supervisor.store.clone(),
            librehub_api::auth::middleware,
        ));
    let sec_admin = librehub_api::security_http::admin_router(security_http_state.clone())
        .route_layer(axum::middleware::from_fn_with_state(
            supervisor.store.clone(),
            librehub_api::auth::middleware,
        ));

    let app = app
        .merge(catalog_router)
        .merge(sec_public)
        .merge(sec_dev)
        .merge(sec_admin)
        .layer(axum::Extension(catalog_worker))
        .layer(axum::Extension(security_worker));
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
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.clone().cancelled_owned())
    .await;
    shutdown.cancel();
    // The executor stops containers before shutdown returns; pending jobs remain durable.
    let worker_result = worker.await.context("Worker task failed")?;
    signal.abort();
    result?;
    worker_result?;
    source_task.await.context("Source worker task failed")??;
    catalog_task.await.context("Catalog worker task failed")??;
    security_task
        .await
        .context("Security worker task failed")??;
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
