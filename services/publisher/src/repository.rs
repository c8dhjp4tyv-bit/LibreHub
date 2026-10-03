use crate::{PublishError, artifact::command};
use base64::{Engine, engine::general_purpose::STANDARD};
use librehub_common::{RepositoryChannel, RepositoryRef, SigningMetadata};
use std::{path::PathBuf, time::Duration};

/// Public URL and trust verification are independent of the backing storage/HTTP server.
#[derive(Clone)]
pub struct RepositoryConfig {
    pub public_base_url: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub runtime_repo_url: String,
}
impl RepositoryConfig {
    pub fn validate(&self) -> Result<(), PublishError> {
        for value in [&self.public_base_url, &self.runtime_repo_url] {
            let url = reqwest::Url::parse(value).map_err(|_| PublishError::Malformed)?;
            if !["http", "https"].contains(&url.scheme())
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || value.contains(['\n', '\r'])
            {
                return Err(PublishError::Malformed);
            }
        }
        if self.public_key.is_empty()
            || self.public_key.len() > 65536
            || ![40, 64].contains(&self.fingerprint.len())
            || !self.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(PublishError::Malformed);
        }
        Ok(())
    }
    pub fn url(&self, channel: RepositoryChannel) -> String {
        format!(
            "{}/repo/{channel}/",
            self.public_base_url.trim_end_matches('/')
        )
    }
    pub fn flatpakrepo(&self, channel: RepositoryChannel) -> String {
        format!(
            "[Flatpak Repo]\nVersion=1\nTitle=LibreHub ({channel})\nUrl={}\nHomepage={}\nComment=Open application distribution for Linux\nDescription=LibreHub Flatpak repository\nDefaultBranch=master\nGPGKey={}\nRuntimeRepo={}\n",
            self.url(channel),
            self.public_base_url,
            STANDARD.encode(&self.public_key),
            self.runtime_repo_url
        )
    }
    pub fn signing(&self) -> SigningMetadata {
        SigningMetadata {
            fingerprint: self.fingerprint.clone(),
            public_key_url: format!(
                "{}/repository.gpg",
                self.public_base_url.trim_end_matches('/')
            ),
        }
    }
}
pub async fn verify_public_ref(
    config: &RepositoryConfig,
    channel: RepositoryChannel,
    name: &RepositoryRef,
    commit: &str,
    timeout: Duration,
    staging: PathBuf,
) -> Result<(), PublishError> {
    // Use libostree through the standard CLI to verify the served summary AND commit
    // with the exact distributed key. No --no-gpg-verify escape hatch.
    let dir = tempfile::Builder::new()
        .prefix("verify-")
        .tempdir_in(staging)
        .map_err(|_| PublishError::Storage)?;
    let key = dir.path().join("public.gpg");
    tokio::fs::write(&key, &config.public_key)
        .await
        .map_err(|_| PublishError::Storage)?;
    let repo = format!("--repo={}", dir.path().join("repo").display());
    command(
        "ostree",
        &[repo.clone(), "init".into(), "--mode=archive-z2".into()],
        timeout,
    )
    .await?;
    command(
        "ostree",
        &[
            repo.clone(),
            "remote".into(),
            "add".into(),
            "--set=gpg-verify=true".into(),
            "--set=gpg-verify-summary=true".into(),
            format!("--gpg-import={}", key.display()),
            "librehub".into(),
            config.url(channel),
        ],
        timeout,
    )
    .await?;
    command(
        "ostree",
        &[
            repo.clone(),
            "pull".into(),
            "--commit-metadata-only".into(),
            "librehub".into(),
            name.to_string(),
        ],
        timeout,
    )
    .await
    .map_err(|_| PublishError::Verification)?;
    let actual = command(
        "ostree",
        &[repo, "rev-parse".into(), format!("librehub:{name}")],
        timeout,
    )
    .await?;
    if actual.trim() != commit {
        return Err(PublishError::Verification);
    }
    Ok(())
}
