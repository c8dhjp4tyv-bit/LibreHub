use crate::{
    PublishError, artifact,
    flat_manager::{FlatManagerClient, RemoteBuild},
    repository::{RepositoryConfig, verify_public_ref},
};
use async_trait::async_trait;
use librehub_common::*;
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

#[derive(Clone)]
pub struct PublishJob {
    pub record: PublishRecord,
    pub build: BuildRecord,
    pub manifest: FlatpakManifest,
    pub data_dir: PathBuf,
}
#[async_trait]
pub trait PublishJournal: Send + Sync {
    async fn save(&self, record: PublishRecord) -> Result<(), PublishError>;
}
#[async_trait]
pub trait Publisher: Send + Sync {
    async fn eligible(
        &self,
        build: BuildRecord,
        manifest: FlatpakManifest,
        data_dir: PathBuf,
    ) -> Result<(), PublishError>;
    async fn publish(
        &self,
        request: PublishJob,
        journal: &dyn PublishJournal,
    ) -> Result<PublishResult, PublishError>;
    async fn ready(&self) -> bool;
    async fn repository_ready(&self) -> bool;
}
pub struct FlatManagerPublisher {
    client: FlatManagerClient,
    repository: RepositoryConfig,
    architecture: Architecture,
    timeout: Duration,
}
impl FlatManagerPublisher {
    pub fn new(
        client: FlatManagerClient,
        repository: RepositoryConfig,
        architecture: Architecture,
        timeout: Duration,
    ) -> Result<Self, PublishError> {
        repository.validate()?;
        if timeout.is_zero() {
            return Err(PublishError::Malformed);
        }
        Ok(Self {
            client,
            repository,
            architecture,
            timeout,
        })
    }
    fn check_remote(
        &self,
        remote: &RemoteBuild,
        record: &PublishRecord,
        marker: &str,
    ) -> Result<(), PublishError> {
        if remote.id <= 0
            || remote.repo != record.channel.to_string()
            || remote.app_id.as_deref() != Some(&record.app_id)
            || remote.build_log_url.as_deref() != Some(marker)
            || !(0..=6).contains(&remote.repo_state)
            || !(0..=3).contains(&remote.published_state)
        {
            return Err(PublishError::Malformed);
        }
        Ok(())
    }
    async fn run(
        &self,
        job: PublishJob,
        journal: &dyn PublishJournal,
    ) -> Result<PublishResult, PublishError> {
        let mut record = job.record;
        if record.build_id != job.build.id
            || record.app_id != job.build.manifest.app_id
            || record.architecture != job.build.architecture
        {
            return Err(PublishError::Metadata);
        }
        let name = artifact::source_ref(&job.build, &job.manifest, self.architecture)?;
        let marker = format!("librehub://publication/{}", record.id);
        let mut prepared = None;
        if matches!(
            record.status,
            PublishStatus::Preparing | PublishStatus::Uploading
        ) {
            let repo = artifact::prepare(
                job.data_dir.clone(),
                job.build,
                job.manifest,
                self.architecture,
                self.timeout,
            )
            .await?;
            if record
                .source_commit
                .as_ref()
                .is_some_and(|c| c != &repo.commit)
            {
                return Err(PublishError::Integrity);
            }
            record.source_commit = Some(repo.commit.clone());
            journal.save(record.clone()).await?;
            prepared = Some(repo);
        }
        let remote_id = if let Some(id) = record.flat_manager_build_id {
            id
        } else {
            let remote = if record.create_requested {
                let matches: Vec<_> = self
                    .client
                    .list(&record.app_id)
                    .await?
                    .into_iter()
                    .filter(|b| b.build_log_url.as_deref() == Some(&marker))
                    .collect();
                if matches.len() != 1 {
                    return Err(PublishError::Uncertain);
                }
                matches.into_iter().next().ok_or(PublishError::Uncertain)?
            } else {
                record.create_requested = true;
                journal.save(record.clone()).await?;
                self.client
                    .create(&record.channel.to_string(), &record.app_id, &marker)
                    .await?
            };
            self.check_remote(&remote, &record, &marker)?;
            record.flat_manager_build_id = Some(remote.id);
            journal.save(record.clone()).await?;
            remote.id
        };
        tracing::info!(publish_id=%record.id, build_id=%record.build_id, app_id=%record.app_id, channel=%record.channel, architecture=%record.architecture, flat_manager_build_id=remote_id, "Publishing validated build");
        let remote = self.client.get(remote_id).await?;
        self.check_remote(&remote, &record, &marker)?;
        if record.status == PublishStatus::Preparing {
            record.status = PublishStatus::Uploading;
            journal.save(record.clone()).await?;
        }
        if record.status == PublishStatus::Uploading {
            match remote.repo_state {
                0 => {
                    let repo = prepared.as_ref().ok_or(PublishError::Preparation)?;
                    self.client.upload(remote_id, &repo.path).await?;
                    self.client
                        .ref_create(remote_id, &repo.ref_name, &repo.commit)
                        .await?;
                }
                1 | 2 | 6 => {} // Prior commit request was accepted; do not upload again.
                _ => return Err(PublishError::Commit),
            }
            record.status = PublishStatus::Committing;
            journal.save(record.clone()).await?;
        }
        if record.status == PublishStatus::Committing {
            let remote = self.client.get(remote_id).await?;
            self.check_remote(&remote, &record, &marker)?;
            if remote.repo_state == 0 {
                self.client.commit(remote_id).await?;
            }
            loop {
                let remote = self.client.get(remote_id).await?;
                self.check_remote(&remote, &record, &marker)?;
                match remote.repo_state {
                    2 => break,
                    0 | 1 | 6 => tokio::time::sleep(Duration::from_millis(500)).await,
                    _ => return Err(PublishError::Commit),
                }
            }
            record.status = PublishStatus::Publishing;
            journal.save(record.clone()).await?;
        }
        if record.status != PublishStatus::Publishing {
            return Err(PublishError::Ineligible);
        }
        let remote = self.client.get(remote_id).await?;
        self.check_remote(&remote, &record, &marker)?;
        if remote.published_state == 0 {
            self.client.publish(remote_id).await?;
        }
        loop {
            let remote = self.client.get(remote_id).await?;
            self.check_remote(&remote, &record, &marker)?;
            match remote.published_state {
                2 => break,
                0 | 1 => tokio::time::sleep(Duration::from_millis(500)).await,
                _ => return Err(PublishError::Publish),
            }
        }
        let publish_job = self.client.job(remote_id, "publish").await?;
        if publish_job.status != 2 {
            return Err(PublishError::Publish);
        }
        let result: Value = serde_json::from_str(
            publish_job
                .results
                .as_deref()
                .ok_or(PublishError::Malformed)?,
        )
        .map_err(|_| PublishError::Malformed)?;
        let commit = result
            .get("refs")
            .and_then(|r| r.get(name.as_str()))
            .and_then(Value::as_str)
            .filter(|c| valid_checksum(c))
            .ok_or(PublishError::Malformed)?
            .to_owned();
        // flat-manager's publish job queues summary generation. Poll its result via
        // normal signed repository pulls; publication alone is insufficient proof.
        loop {
            match verify_public_ref(
                &self.repository,
                record.channel,
                &name,
                &commit,
                self.timeout.min(Duration::from_secs(30)),
                job.data_dir.join("publishes"),
            )
            .await
            {
                Ok(()) => break,
                Err(PublishError::Verification) => {
                    tokio::time::sleep(Duration::from_millis(500)).await
                }
                Err(e) => return Err(e),
            }
        }
        Ok(PublishResult {
            published_ref: PublishedRef {
                ref_name: name,
                commit,
                source_commit: record.source_commit.ok_or(PublishError::Metadata)?,
                repository_url: self.repository.url(record.channel),
            },
            signing: self.repository.signing(),
        })
    }
}
#[async_trait]
impl Publisher for FlatManagerPublisher {
    async fn eligible(
        &self,
        build: BuildRecord,
        manifest: FlatpakManifest,
        data_dir: PathBuf,
    ) -> Result<(), PublishError> {
        artifact::source_ref(&build, &manifest, self.architecture)?;
        // Admission checks actual Flatpak metadata as well as hash; bounded HTTP
        // admission concurrency is enforced by the API, outside executor threads.
        let _repo = artifact::prepare(
            data_dir,
            build,
            manifest,
            self.architecture,
            self.timeout.min(Duration::from_secs(60)),
        )
        .await?;
        Ok(())
    }
    async fn publish(
        &self,
        request: PublishJob,
        journal: &dyn PublishJournal,
    ) -> Result<PublishResult, PublishError> {
        tokio::time::timeout(self.timeout, self.run(request, journal))
            .await
            .map_err(|_| PublishError::Timeout)?
    }
    async fn ready(&self) -> bool {
        self.client.ready().await
    }
    async fn repository_ready(&self) -> bool {
        let Ok(client) = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        else {
            return false;
        };
        for channel in [RepositoryChannel::Stable, RepositoryChannel::Beta] {
            for filename in ["summary", "summary.sig"] {
                if !client
                    .head(format!("{}{filename}", self.repository.url(channel)))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    return false;
                }
            }
        }
        true
    }
}
