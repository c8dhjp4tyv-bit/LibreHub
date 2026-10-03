//! Narrow smart-HTTP relay. Git never receives upstream redirects or dumb-HTTP
//! alternates, which could otherwise point its HTTP helper at private addresses.
use super::{MAX_GIT_BYTES, SourceError};
use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
#[derive(Clone)]
pub(super) struct RelayState {
    pub client: reqwest::Client,
    pub origin: String,
    pub path: String,
    pub failure: std::sync::Arc<std::sync::Mutex<Option<SourceError>>>,
    pub admission: std::sync::Arc<tokio::sync::Semaphore>,
}
pub(super) struct Relay {
    pub url: String,
    pub task: tokio::task::JoinHandle<()>,
    pub failure: std::sync::Arc<std::sync::Mutex<Option<SourceError>>>,
}
impl Relay {
    pub fn failure(&self) -> Option<SourceError> {
        self.failure.lock().ok().and_then(|f| f.clone())
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) fn uuid_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub(super) async fn relay_request(
    State(state): State<RelayState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(body) = body else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let (suffix, response_type) = if method == Method::GET
        && uri.path() == format!("{}/info/refs", state.path)
        && uri.query() == Some("service=git-upload-pack")
    {
        (
            "/info/refs?service=git-upload-pack",
            "application/x-git-upload-pack-advertisement",
        )
    } else if method == Method::POST
        && uri.path() == format!("{}/git-upload-pack", state.path)
        && uri.query().is_none()
    {
        ("/git-upload-pack", "application/x-git-upload-pack-result")
    } else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let mut request = state
        .client
        .request(method.clone(), format!("{}{suffix}", state.origin));
    if method == Method::POST {
        request = request
            .header(
                header::CONTENT_TYPE,
                "application/x-git-upload-pack-request",
            )
            .body(body);
    }
    let response = async {
        let mut remote = request
            .send()
            .await
            .map_err(|_| SourceError::transient("source_fetch_failed"))?;
        if !remote.status().is_success() {
            return Err(match remote.status().as_u16() {
                404 => SourceError::new("source_repository_not_found"),
                401 | 403 => SourceError::new("source_authentication_rejected"),
                500..=599 => SourceError::transient("source_fetch_failed"),
                _ => SourceError::new("repository_not_allowed"),
            });
        }
        if remote
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next() != Some(response_type))
        {
            return Err(SourceError::new("source_smart_http_required"));
        }
        if remote.content_length().is_some_and(|n| n > MAX_GIT_BYTES) {
            return Err(SourceError::new("source_limit_exceeded"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = remote
            .chunk()
            .await
            .map_err(|_| SourceError::transient("source_fetch_failed"))?
        {
            if bytes.len() as u64 + chunk.len() as u64 > MAX_GIT_BYTES {
                return Err(SourceError::new("source_limit_exceeded"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((StatusCode::OK, Bytes::from(bytes)))
    }
    .await;
    match response {
        Ok((status, body)) => {
            (status, [(header::CONTENT_TYPE, response_type)], body).into_response()
        }
        Err(error) => {
            if let Ok(mut saved) = state.failure.lock() {
                *saved = Some(error);
            }
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}
