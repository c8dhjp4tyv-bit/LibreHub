use anyhow::{Context, bail};
use librehub_builder::DockerConfig;
use librehub_common::Architecture;
use librehub_publisher::{
    FlatManagerPublisher, flat_manager::FlatManagerClient, repository::RepositoryConfig,
};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

pub struct AppConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: Option<PathBuf>,
    pub builder: DockerConfig,
    pub publishing: Option<PublishingConfig>,
}
pub struct PublishingConfig {
    pub manager_url: String,
    token: String,
    pub repository: RepositoryConfig,
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub operation_timeout: Duration,
}
impl std::fmt::Debug for PublishingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishingConfig")
            .field("token", &"[REDACTED]")
            .field("concurrency", &self.concurrency)
            .finish_non_exhaustive()
    }
}
impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        if env("LIBREHUB_SUPPLY_CHAIN_POLICY", "development") == "enforce"
            && env("LIBREHUB_WORKER_ISOLATION", "compatibility") != "hardened"
        {
            bail!("Enforcement requires explicitly configured hardened workers");
        }
        let publishing = match std::env::var("LIBREHUB_FLAT_MANAGER_URL") {
            Ok(manager_url) => {
                let token = match std::env::var("LIBREHUB_FLAT_MANAGER_TOKEN_FILE") {
                    Ok(path) => std::fs::read_to_string(path)
                        .context("Cannot read flat-manager token file")?
                        .trim()
                        .to_owned(),
                    Err(_) => required("LIBREHUB_FLAT_MANAGER_TOKEN")?,
                };
                let key = std::fs::read(required("LIBREHUB_SIGNING_PUBLIC_KEY_FILE")?)
                    .context("Cannot read repository public key")?;
                let config = PublishingConfig {
                    manager_url,
                    token,
                    repository: RepositoryConfig {
                        public_base_url: required("LIBREHUB_PUBLIC_BASE_URL")?,
                        public_key: key,
                        fingerprint: required("LIBREHUB_SIGNING_FINGERPRINT")?,
                        runtime_repo_url: env(
                            "LIBREHUB_RUNTIME_REPO_URL",
                            "https://dl.flathub.org/repo/flathub.flatpakrepo",
                        ),
                    },
                    concurrency: number("LIBREHUB_PUBLISH_CONCURRENCY", 1, 8)? as usize,
                    connect_timeout: Duration::from_secs(number(
                        "LIBREHUB_CONNECT_TIMEOUT_SECONDS",
                        5,
                        60,
                    )?),
                    request_timeout: Duration::from_secs(number(
                        "LIBREHUB_REQUEST_TIMEOUT_SECONDS",
                        60,
                        600,
                    )?),
                    operation_timeout: Duration::from_secs(number(
                        "LIBREHUB_PUBLISH_TIMEOUT_SECONDS",
                        900,
                        7200,
                    )?),
                };
                config.publisher()?; // Validate URLs, trust configuration and credential format before listening.
                Some(config)
            }
            Err(_) => None,
        };
        Ok(Self {
            bind: env("LIBREHUB_BIND", "127.0.0.1:8080")
                .parse()
                .context("Invalid LIBREHUB_BIND")?,
            data_dir: env("LIBREHUB_DATA_DIR", "data").into(),
            database_path: std::env::var("LIBREHUB_DATABASE_PATH").ok().map(Into::into),
            builder: DockerConfig {
                binary: env("LIBREHUB_DOCKER", "docker").into(),
                image: env("LIBREHUB_WORKER_IMAGE", "librehub-worker:m1"),
                network: env("LIBREHUB_WORKER_NETWORK", "none"),
                isolation: match env("LIBREHUB_WORKER_ISOLATION", "compatibility").as_str() {
                    "compatibility" => librehub_common::IsolationPolicy::Compatibility,
                    "hardened" => librehub_common::IsolationPolicy::Hardened,
                    _ => bail!("Invalid worker isolation policy"),
                },
                timeout: Duration::from_secs(number(
                    "LIBREHUB_BUILD_TIMEOUT_SECONDS",
                    1800,
                    86400,
                )?),
                ..DockerConfig::default()
            },
            publishing,
        })
    }
}
impl PublishingConfig {
    pub fn publisher(&self) -> anyhow::Result<FlatManagerPublisher> {
        Ok(FlatManagerPublisher::new(
            FlatManagerClient::new(
                &self.manager_url,
                self.token.clone(),
                self.connect_timeout,
                self.request_timeout,
            )?,
            self.repository.clone(),
            Architecture::native(),
            self.operation_timeout,
        )?)
    }
}
fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}
fn required(key: &str) -> anyhow::Result<String> {
    let value = std::env::var(key)
        .with_context(|| format!("{key} is required when publishing is enabled"))?;
    if value.trim().is_empty() {
        bail!("{key} must not be empty");
    }
    Ok(value)
}
fn number(key: &str, default: u64, max: u64) -> anyhow::Result<u64> {
    let value = env(key, &default.to_string())
        .parse::<u64>()
        .with_context(|| format!("Invalid {key}"))?;
    if value == 0 || value > max {
        bail!("{key} is outside the supported range");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_debug_never_prints_credentials() {
        let config = PublishingConfig {
            manager_url: "http://localhost:8081".into(),
            token: "private-publisher-token".into(),
            repository: RepositoryConfig {
                public_base_url: "http://localhost:8090".into(),
                public_key: vec![],
                fingerprint: "A".repeat(40),
                runtime_repo_url: "https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
            },
            concurrency: 1,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(60),
            operation_timeout: Duration::from_secs(900),
        };
        let diagnostic = format!("{config:?}");
        assert!(diagnostic.contains("[REDACTED]"));
        assert!(!diagnostic.contains("private-publisher-token"));
    }
}
