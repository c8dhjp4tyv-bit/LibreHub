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
    // Validate before anything binds, opens a database or starts a worker. Names only, no values.
    let vars: librehub_api::production::Vars = std::env::vars().collect();
    let mut problems = match librehub_api::production::validate(&vars) {
        Ok(_) => Vec::new(),
        Err(problems) => problems,
    };
    problems.extend(librehub_api::production::check_secret_files(&vars));
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("configuration error: {problem}");
        }
        eprintln!(
            "LibreHub configuration was rejected ({} problem(s)); nothing was started",
            problems.len()
        );
        std::process::exit(2);
    }
    let environment = librehub_api::production::environment(&vars)
        .unwrap_or(librehub_api::production::Environment::Development);
    if std::env::args().any(|argument| argument == "--check-config") {
        // Operator preflight: the same validation as a start, without binding or opening anything.
        println!("configuration ok ({environment:?})");
        return Ok(());
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if vars.get("LIBREHUB_LOG_FORMAT").map(String::as_str) == Some("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
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
    let database_file = database_path
        .clone()
        .unwrap_or_else(|| data_dir.join("builds.sqlite3"));
    let mut store = tokio::task::spawn_blocking(move || {
        Store::open_at(&store_data_dir, database_path.as_deref())
    })
    .await??;
    store.attestation_repository = config.publishing.as_ref().map(|p| p.repository.clone());
    store.automation_limits = librehub_api::automation_store::AutomationLimits::from_env()?;
    store.min_free_bytes = match std::env::var("LIBREHUB_MIN_FREE_BYTES") {
        Ok(value) => value
            .parse()
            .context("LIBREHUB_MIN_FREE_BYTES must be a number of bytes")?,
        Err(_) => 512 * 1024 * 1024,
    };
    store.configure_attestor().await?;
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
    let provider: Arc<dyn librehub_source::SourceProvider> =
        Arc::new(librehub_api::source_worker::git_from_env()?);
    let automation_provider = provider.clone();
    let source_worker = librehub_api::source_worker::SourceWorker::new(
        supervisor.clone(),
        provider,
        publishing.clone(),
    );
    let source_wake = source_worker.wake.clone();
    source_worker.recover().await?;
    if environment == librehub_api::production::Environment::Production {
        // A production start never creates encryption identities: restore or provision them first.
        anyhow::ensure!(
            data_dir.join("webhook.key").is_file(),
            "webhook.key must be provisioned in the data directory before a production start"
        );
    }
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
    // M7: automation engine, scheduler and outbound delivery. All state is durable in SQLite.
    let automation_worker = {
        let mut worker = librehub_api::automation_worker::AutomationWorker::new(
            supervisor.store.clone(),
            automation_provider,
            publishing.clone(),
            supervisor.wake.clone(),
            source_wake,
            supervisor.shutdown.clone(),
        );
        worker.scheduler_enabled =
            std::env::var("LIBREHUB_AUTOMATION_SCHEDULER").map_or(true, |v| v != "disabled");
        worker
    };
    let automation_task = tokio::spawn(automation_worker.clone().run());
    let outbound_policy = librehub_automation::webhook::DestinationPolicy {
        allow_loopback: librehub_common::test_hooks::test_env(
            "LIBREHUB_WEBHOOK_ALLOW_LOOPBACK_FOR_TESTS",
        )
        .is_ok_and(|v| v == "1"),
    };
    let webhook_ca = std::env::var("LIBREHUB_WEBHOOK_CA_FILE")
        .ok()
        .map(std::fs::read)
        .transpose()
        .context("Cannot read LIBREHUB_WEBHOOK_CA_FILE")?;
    let resolver: Arc<dyn librehub_api::outbound_worker::Resolver> =
        Arc::new(librehub_api::outbound_worker::SystemResolver);
    let outbound_worker = librehub_api::outbound_worker::OutboundWorker::new(
        supervisor.store.clone(),
        key,
        Arc::new(librehub_api::outbound_worker::ReqwestTransport::new(
            webhook_ca.as_deref(),
        )?),
        resolver.clone(),
        outbound_policy,
        supervisor.shutdown.clone(),
    );
    let mut outbound_worker = outbound_worker;
    if let Ok(seconds) = std::env::var("LIBREHUB_WEBHOOK_BACKOFF_BASE_SECONDS") {
        let seconds: u64 = seconds
            .parse()
            .context("Invalid LIBREHUB_WEBHOOK_BACKOFF_BASE_SECONDS")?;
        anyhow::ensure!(
            (1..=60).contains(&seconds),
            "LIBREHUB_WEBHOOK_BACKOFF_BASE_SECONDS must be 1–60"
        );
        outbound_worker.backoff_base = std::time::Duration::from_secs(seconds);
    }
    let outbound_task = tokio::spawn(outbound_worker.clone().run());
    let verifier = oidc_from_env()?;
    let automation_router =
        librehub_api::automation_http::router(librehub_api::automation_http::AutomationHttp {
            store: supervisor.store.clone(),
            wake: automation_worker.wake.clone(),
        })
        .route_layer(axum::middleware::from_fn_with_state(
            supervisor.store.clone(),
            librehub_api::auth::middleware,
        ));
    let integration_state = librehub_api::integration_http::IntegrationHttp {
        store: supervisor.store.clone(),
        key,
        verifier,
        policy: outbound_policy,
        resolver,
    };
    let integration_private = librehub_api::integration_http::private_router(
        integration_state.clone(),
    )
    .route_layer(axum::middleware::from_fn_with_state(
        supervisor.store.clone(),
        librehub_api::auth::middleware,
    ));
    let integration_public = librehub_api::integration_http::public_router(integration_state);
    let security_worker = librehub_api::security_worker::SecurityWorker::new(
        supervisor.store.clone(),
        publishing.as_ref().map(|p| p.repository.clone()),
        supervisor.shutdown.clone(),
    );
    let attestation_task = tokio::spawn(librehub_api::supply_chain::run(
        supervisor.store.clone(),
        supervisor.shutdown.clone(),
    ));
    let supply_router = librehub_api::supply_chain_http::router(supervisor.store.clone());
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

    // Operator metrics are served only on their own listener, which the public proxy never routes.
    let telemetry = Arc::new(librehub_api::ops::Telemetry::new());
    let metrics_address: std::net::SocketAddr = std::env::var("LIBREHUB_METRICS_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9464".into())
        .parse()
        .context("Invalid LIBREHUB_METRICS_BIND")?;
    let metrics_listener = tokio::net::TcpListener::bind(metrics_address)
        .await
        .context("Cannot bind LIBREHUB_METRICS_BIND")?;
    let metrics_app = librehub_api::ops::metrics_router(librehub_api::ops::OpsState {
        store: supervisor.store.clone(),
        telemetry: telemetry.clone(),
        database_path: database_file,
        outbound: Some(outbound_worker.clone()),
        automation: Some(automation_worker.clone()),
        catalog: Some(catalog_worker.clone()),
        security: Some(security_worker.clone()),
    });
    let app = app
        .merge(catalog_router)
        .merge(supply_router)
        .merge(sec_public)
        .merge(sec_dev)
        .merge(sec_admin)
        .merge(automation_router)
        .merge(integration_private)
        .merge(integration_public)
        .layer(axum::Extension(automation_worker))
        .layer(axum::Extension(outbound_worker))
        .layer(axum::Extension(catalog_worker))
        .layer(axum::Extension(security_worker))
        .layer(axum::middleware::from_fn_with_state(
            telemetry,
            librehub_api::ops::observe,
        ));
    let shutdown = supervisor.shutdown.clone();
    let metrics_shutdown = shutdown.clone();
    let metrics_task = tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(metrics_shutdown.cancelled_owned())
            .await
            .map_err(anyhow::Error::from)
    });
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
    attestation_task.await.context("Attestor task failed")??;
    source_task.await.context("Source worker task failed")??;
    catalog_task.await.context("Catalog worker task failed")??;
    automation_task
        .await
        .context("Automation worker task failed")??;
    outbound_task
        .await
        .context("Outbound delivery worker task failed")??;
    security_task
        .await
        .context("Security worker task failed")??;
    if let Some(task) = publishing_task {
        task.await.context("Publisher task failed")??;
    }
    metrics_task.await.context("Metrics listener failed")??;
    Ok(())
}
/// GitHub Actions OIDC federation is enabled by configuring the audience LibreHub expects.
fn oidc_from_env() -> anyhow::Result<Option<Arc<librehub_api::oidc_verifier::OidcVerifier>>> {
    let Ok(audience) = std::env::var("LIBREHUB_OIDC_AUDIENCE") else {
        return Ok(None);
    };
    anyhow::ensure!(
        !audience.trim().is_empty(),
        "LIBREHUB_OIDC_AUDIENCE must not be empty"
    );
    let issuer = std::env::var("LIBREHUB_OIDC_ISSUER")
        .unwrap_or_else(|_| librehub_automation::oidc::GITHUB_ISSUER.into());
    let jwks = std::env::var("LIBREHUB_OIDC_JWKS_URL")
        .unwrap_or_else(|_| format!("{}/.well-known/jwks", issuer.trim_end_matches('/')));
    // Plain HTTP is for the local test issuer only and has to be requested explicitly.
    let insecure = librehub_common::test_hooks::test_env("LIBREHUB_OIDC_INSECURE_FOR_TESTS")
        .is_ok_and(|v| v == "1");
    let config = librehub_automation::oidc::OidcConfig {
        issuer,
        audience,
        leeway_secs: 30,
        max_lifetime_secs: 3600,
    };
    let fetcher = librehub_api::oidc_verifier::HttpJwksFetcher::new(&jwks, insecure)?;
    Ok(Some(Arc::new(
        librehub_api::oidc_verifier::OidcVerifier::new(config, Arc::new(fetcher)),
    )))
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
