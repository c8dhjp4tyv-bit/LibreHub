use crate::PublishError;
use librehub_common::{RepositoryRef, valid_checksum};
use reqwest::{Client, Method, multipart};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};

#[derive(Clone)]
pub struct FlatManagerClient {
    client: Client,
    base_url: String,
    token: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteBuild {
    pub id: i32,
    pub repo: String,
    pub app_id: Option<String>,
    pub repo_state: i16,
    pub published_state: i16,
    pub build_log_url: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct RemoteJob {
    pub status: i16,
    pub results: Option<String>,
}
impl FlatManagerClient {
    pub fn new(
        base_url: &str,
        token: String,
        connect: Duration,
        request: Duration,
    ) -> Result<Self, PublishError> {
        let url = reqwest::Url::parse(base_url).map_err(|_| PublishError::Malformed)?;
        if !["http", "https"].contains(&url.scheme())
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || token.trim().is_empty()
            || !token.bytes().all(|b| b.is_ascii_graphic())
            || base_url.contains(['\n', '\r'])
            || connect.is_zero()
            || request.is_zero()
        {
            return Err(PublishError::Malformed);
        }
        let client = Client::builder()
            .connect_timeout(connect)
            .timeout(request)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PublishError::Malformed)?;
        Ok(Self {
            client,
            base_url: url.as_str().trim_end_matches('/').into(),
            token,
        })
    }
    async fn decode<T: DeserializeOwned>(
        mut response: reqwest::Response,
    ) -> Result<T, PublishError> {
        let status = response.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => PublishError::Unauthorized,
                429 | 500..=599 => PublishError::Unavailable,
                s => PublishError::Rejected(s),
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(PublishError::Malformed);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| PublishError::Malformed)
    }
    async fn json<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
        safe_retry: bool,
    ) -> Result<T, PublishError> {
        let tries = if safe_retry { 3 } else { 1 };
        for attempt in 0..tries {
            let result = match self
                .client
                .request(method.clone(), format!("{}/api/v1/{path}", self.base_url))
                .bearer_auth(&self.token)
                .json(body)
                .send()
                .await
            {
                Ok(r) => Self::decode(r).await,
                Err(e) => Err(transport(e)),
            };
            match result {
                Err(ref e) if e.retryable() && attempt + 1 < tries => {
                    tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await
                }
                _ => return result,
            }
        }
        Err(PublishError::Unavailable)
    }
    pub async fn ready(&self) -> bool {
        // Authentication and DB lookup occur before the 404; this avoids
        // assuming the publisher token permits a particular application prefix.
        matches!(
            self.get(i32::MAX).await,
            Ok(_) | Err(PublishError::Rejected(404))
        )
    }
    pub async fn list(&self, app_id: &str) -> Result<Vec<RemoteBuild>, PublishError> {
        // App IDs have been validated before use; do not interpolate arbitrary request data.
        self.json(
            Method::GET,
            &format!("build?app-id={app_id}"),
            &json!({}),
            true,
        )
        .await
    }
    pub async fn create(
        &self,
        repo: &str,
        app_id: &str,
        marker: &str,
    ) -> Result<RemoteBuild, PublishError> {
        self.json(
            Method::POST,
            "build",
            &json!({"repo":repo,"app-id":app_id,"public-download":false,"build-log-url":marker}),
            false,
        )
        .await
    }
    pub async fn get(&self, id: i32) -> Result<RemoteBuild, PublishError> {
        self.json(Method::GET, &format!("build/{id}"), &json!({}), true)
            .await
    }
    pub async fn ref_create(
        &self,
        id: i32,
        name: &RepositoryRef,
        commit: &str,
    ) -> Result<(), PublishError> {
        let _: Value = self
            .json(
                Method::POST,
                &format!("build/{id}/build_ref"),
                &json!({"ref":name.as_str(),"commit":commit}),
                true,
            )
            .await?;
        Ok(())
    }
    pub async fn commit(&self, id: i32) -> Result<(), PublishError> {
        let _: Value = self
            .json(
                Method::POST,
                &format!("build/{id}/commit"),
                &json!({}),
                false,
            )
            .await?;
        Ok(())
    }
    pub async fn publish(&self, id: i32) -> Result<(), PublishError> {
        let _: Value = self
            .json(
                Method::POST,
                &format!("build/{id}/publish"),
                &json!({}),
                false,
            )
            .await?;
        Ok(())
    }
    pub async fn job(&self, id: i32, kind: &str) -> Result<RemoteJob, PublishError> {
        self.json(
            Method::GET,
            &format!("build/{id}/{kind}"),
            &json!({"log-offset":0}),
            true,
        )
        .await
    }
    async fn missing(&self, id: i32, wanted: &[String]) -> Result<Vec<String>, PublishError> {
        #[derive(Deserialize)]
        struct Missing {
            missing: Vec<String>,
        }
        let result: Missing = self
            .json(
                Method::GET,
                &format!("build/{id}/missing_objects"),
                &json!({"wanted":wanted}),
                true,
            )
            .await?;
        if result.missing.iter().any(|m| !wanted.contains(m)) {
            return Err(PublishError::Malformed);
        }
        Ok(result.missing)
    }
    pub async fn upload(&self, id: i32, repo: &Path) -> Result<(), PublishError> {
        let objects = object_names(repo).await?;
        for batch in objects.chunks(1000) {
            // Content-addressed uploads and missing queries are safe to retry.
            let mut missing = self.missing(id, batch).await?;
            for attempt in 0..3 {
                if missing.is_empty() {
                    break;
                }
                for name in &missing {
                    let path = repo.join("objects").join(&name[..2]).join(&name[2..]);
                    let size = tokio::fs::metadata(&path)
                        .await
                        .map_err(|_| PublishError::Storage)?
                        .len();
                    let part = multipart::Part::stream_with_length(
                        tokio::fs::File::open(&path)
                            .await
                            .map_err(|_| PublishError::Storage)?,
                        size,
                    )
                    .file_name(name.clone());
                    let response = self
                        .client
                        .post(format!("{}/api/v1/build/{id}/upload", self.base_url))
                        .bearer_auth(&self.token)
                        .multipart(multipart::Form::new().part("file0", part))
                        .send()
                        .await
                        .map_err(transport)?;
                    let sizes: Vec<u64> = Self::decode(response).await?;
                    if sizes.as_slice() != [size] {
                        return Err(PublishError::PartialUpload);
                    }
                }
                missing = self.missing(id, batch).await?;
                if !missing.is_empty() && attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
                }
            }
            if !missing.is_empty() {
                return Err(PublishError::PartialUpload);
            }
        }
        Ok(())
    }
}
fn transport(e: reqwest::Error) -> PublishError {
    if e.is_timeout() {
        PublishError::Timeout
    } else {
        PublishError::Unavailable
    }
}
async fn object_names(repo: &Path) -> Result<Vec<String>, PublishError> {
    let repo = repo.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut names = BTreeSet::new();
        let mut total = 0_u64;
        for dir in std::fs::read_dir(repo.join("objects")).map_err(|_| PublishError::Storage)? {
            let dir = dir.map_err(|_| PublishError::Storage)?;
            let prefix = dir
                .file_name()
                .into_string()
                .map_err(|_| PublishError::Storage)?;
            if prefix.len() != 2
                || !prefix.bytes().all(|b| b.is_ascii_hexdigit())
                || !dir.file_type().map_err(|_| PublishError::Storage)?.is_dir()
            {
                return Err(PublishError::Storage);
            }
            for file in std::fs::read_dir(dir.path()).map_err(|_| PublishError::Storage)? {
                let file = file.map_err(|_| PublishError::Storage)?;
                let name = format!(
                    "{prefix}{}",
                    file.file_name().to_str().ok_or(PublishError::Storage)?
                );
                let (checksum, suffix) = name.split_once('.').ok_or(PublishError::Storage)?;
                if !valid_checksum(checksum)
                    || !["filez", "dirtree", "dirmeta", "commit", "commitmeta"].contains(&suffix)
                    || !file
                        .file_type()
                        .map_err(|_| PublishError::Storage)?
                        .is_file()
                {
                    return Err(PublishError::Storage);
                }
                total += file.metadata().map_err(|_| PublishError::Storage)?.len();
                if total > 2 * crate::artifact::MAX_ARTIFACT_BYTES || names.len() >= 32768 {
                    return Err(PublishError::Storage);
                }
                names.insert(name);
            }
        }
        if names.is_empty() {
            return Err(PublishError::Preparation);
        }
        Ok(names.into_iter().collect())
    })
    .await
    .map_err(|_| PublishError::Storage)?
}
