use crate::{publication_store::AdmissionError, publishing::Publishing, store, worker::Supervisor};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use librehub_common::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{str::FromStr, sync::Arc};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct ApiState {
    pub supervisor: Supervisor,
    pub architecture: Architecture,
}
#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}
struct ApiError(StatusCode, ErrorBody);
impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self(
            status,
            ErrorBody {
                code,
                message: message.into(),
            },
        )
    }
    fn internal(error: anyhow::Error) -> Self {
        tracing::error!(error = %error, "API storage operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Persistent storage operation failed",
        )
    }
    fn missing() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "build_not_found",
            "Build does not exist",
        )
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

pub fn router(state: ApiState) -> Router {
    router_with_publisher(state, None)
}
pub fn router_with_publisher(state: ApiState, publishing: Option<Publishing>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/librehub.flatpakrepo", get(stable_repo))
        .route("/librehub-beta.flatpakrepo", get(beta_repo))
        .route("/repository.gpg", get(public_key))
        .route("/api/v1/builds/{id}/publish", post(publish_build))
        .route("/api/v1/builds/{id}/publishes", get(build_publications))
        .route("/api/v1/publishes/{id}", get(publication))
        .route("/api/v1/publishes/{id}/cancel", post(cancel_publication))
        .route("/api/v1/builds", post(create))
        .route("/api/v1/builds/{id}", get(lookup))
        .route("/api/v1/builds/{id}/logs", get(logs))
        .route("/api/v1/builds/{id}/cancel", post(cancel))
        .fallback(|| async {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "Endpoint does not exist",
            )
        })
        .method_not_allowed_fallback(|| async {
            ApiError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "HTTP method is unsupported for this endpoint",
            )
        })
        .layer(DefaultBodyLimit::max(
            2 * librehub_validator::MAX_MANIFEST_BYTES,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(publishing))
        .with_state(Arc::new(state))
}

fn publishing_service(publishing: Option<Publishing>) -> Result<Publishing, ApiError> {
    publishing.ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "publishing_disabled",
            "Repository publishing is not configured",
        )
    })
}
fn publish_id(raw: &str) -> Result<PublishId, ApiError> {
    raw.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_publish_id",
            "Publish ID must be a UUID",
        )
    })
}
fn publication_error(error: anyhow::Error) -> ApiError {
    if let Some(error) = error.downcast_ref::<AdmissionError>() {
        let (status, code) = match error {
            AdmissionError::Missing => (StatusCode::NOT_FOUND, "build_not_found"),
            AdmissionError::Ineligible => (StatusCode::CONFLICT, "build_not_publishable"),
            AdmissionError::Full => (StatusCode::SERVICE_UNAVAILABLE, "publish_queue_full"),
            AdmissionError::TooLate => (StatusCode::CONFLICT, "publication_not_cancellable"),
        };
        return ApiError::new(status, code, error.to_string());
    }
    ApiError::internal(error)
}
async fn publish_build(
    State(state): State<Arc<ApiState>>,
    Extension(publishing): Extension<Option<Publishing>>,
    Path(raw): Path<String>,
    body: Result<Json<PublishRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let publishing = publishing_service(publishing)?;
    if state.supervisor.shutdown.is_cancelled() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_stopping",
            "Service is shutting down",
        ));
    }
    let Json(request) = body.map_err(|_| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_publish_request",
            "Provide only channel: stable or beta",
        )
    })?;
    let id = parse_id(&raw)?;
    let build = state
        .supervisor
        .store
        .get(id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::missing)?;
    let existing = state
        .supervisor
        .store
        .publications(id)
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|p| p.channel == request.channel);
    let record = if let Some(existing) = existing {
        existing
    } else {
        if build.status != BuildStatus::Succeeded {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "build_not_publishable",
                "Only successful builds can be published",
            ));
        }
        let _permit = publishing
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "publish_admission_busy",
                    "Publication admission is busy; retry later",
                )
            })?;
        let manifest = state
            .supervisor
            .store
            .manifest(id)
            .await
            .map_err(ApiError::internal)?;
        publishing
            .publisher
            .eligible(build, manifest, state.supervisor.store.data_dir.clone())
            .await
            .map_err(|e| ApiError::new(StatusCode::CONFLICT, e.code(), e.to_string()))?;
        state
            .supervisor
            .store
            .enqueue_publish(id, request.channel)
            .await
            .map_err(publication_error)?
    };
    publishing.wake.notify_one();
    let status = if record.status.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((
        status,
        [(header::LOCATION, format!("/api/v1/publishes/{}", record.id))],
        Json(record),
    )
        .into_response())
}
async fn publication(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
) -> Result<Json<PublishRecord>, ApiError> {
    Ok(Json(
        state
            .supervisor
            .store
            .publish_record(publish_id(&raw)?)
            .await
            .map_err(ApiError::internal)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "publish_not_found",
                    "Publication does not exist",
                )
            })?,
    ))
}
async fn build_publications(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
) -> Result<Json<Vec<PublishRecord>>, ApiError> {
    let id = parse_id(&raw)?;
    if state
        .supervisor
        .store
        .get(id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::missing());
    }
    Ok(Json(
        state
            .supervisor
            .store
            .publications(id)
            .await
            .map_err(ApiError::internal)?,
    ))
}
async fn cancel_publication(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
) -> Result<Json<PublishRecord>, ApiError> {
    Ok(Json(
        state
            .supervisor
            .store
            .cancel_publication(publish_id(&raw)?)
            .await
            .map_err(publication_error)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "publish_not_found",
                    "Publication does not exist",
                )
            })?,
    ))
}
async fn ready(
    State(state): State<Arc<ApiState>>,
    Extension(publishing): Extension<Option<Publishing>>,
) -> impl IntoResponse {
    let database = state.supervisor.store.database_ready().await;
    let (manager, repository, publisher) = if let Some(publishing) = publishing {
        let (manager, storage, repository) = tokio::join!(
            publishing.publisher.ready(),
            publishing.storage_ready(),
            publishing.publisher.repository_ready()
        );
        (
            manager,
            storage && repository,
            publishing
                .running
                .load(std::sync::atomic::Ordering::Acquire),
        )
    } else {
        (false, false, false)
    };
    let ready =
        database && manager && repository && publisher && !state.supervisor.shutdown.is_cancelled();
    let component = |ok| if ok { "ok" } else { "unavailable" };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(
            serde_json::json!({"ready":ready,"components":{"database":component(database),"flat_manager":component(manager),"repository":component(repository),"publisher":component(publisher)}}),
        ),
    )
}
async fn stable_repo(
    Extension(publishing): Extension<Option<Publishing>>,
) -> Result<Response, ApiError> {
    repo_file(publishing, RepositoryChannel::Stable)
}
async fn beta_repo(
    Extension(publishing): Extension<Option<Publishing>>,
) -> Result<Response, ApiError> {
    repo_file(publishing, RepositoryChannel::Beta)
}
fn repo_file(
    publishing: Option<Publishing>,
    channel: RepositoryChannel,
) -> Result<Response, ApiError> {
    let service = publishing_service(publishing)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.flatpak.repo"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        service.repository.flatpakrepo(channel),
    )
        .into_response())
}
async fn public_key(
    Extension(publishing): Extension<Option<Publishing>>,
) -> Result<Response, ApiError> {
    Ok((
        [(header::CONTENT_TYPE, "application/pgp-keys")],
        publishing_service(publishing)?.repository.public_key,
    )
        .into_response())
}
async fn health(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    if state.supervisor.shutdown.is_cancelled() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status":"stopping"})),
        )
    } else {
        (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
    }
}
#[derive(Serialize)]
struct Created {
    id: BuildId,
    status: BuildStatus,
}
async fn create(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    if state.supervisor.shutdown.is_cancelled() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_stopping",
            "Service is shutting down",
        ));
    }
    let body = body.map_err(|e| ApiError::new(e.status(), "invalid_body", e.body_text()))?;
    let input = std::str::from_utf8(&body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_encoding",
            "Manifest must be UTF-8",
        )
    })?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let (manifest, format, architecture) = match content_type {
        "application/json" => {
            let parsed: Value = serde_json::from_str(input).map_err(|e| {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid_syntax", e.to_string())
            })?;
            if parsed.get("manifest").is_some() {
                let request: BuildRequest = serde_json::from_value(parsed).map_err(|e| {
                    ApiError::new(StatusCode::BAD_REQUEST, "invalid_request", e.to_string())
                })?;
                (request.manifest, request.format, request.architecture)
            } else {
                (input.to_owned(), ManifestFormat::Json, state.architecture)
            }
        }
        "application/yaml" | "application/x-yaml" | "text/yaml" => {
            (input.to_owned(), ManifestFormat::Yaml, state.architecture)
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Use application/json or application/yaml",
            ));
        }
    };
    if architecture != state.architecture {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_architecture",
            "No native worker is configured for this architecture",
        ));
    }
    // Parsing and validation are CPU work, outside the HTTP scheduler threads.
    let validated =
        tokio::task::spawn_blocking(move || librehub_validator::validate(&manifest, format))
            .await
            .map_err(|e| ApiError::internal(e.into()))?;
    let manifest = match validated {
        Ok(manifest) => manifest,
        Err(result) => return Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(result)).into_response()),
    };
    let record = state
        .supervisor
        .store
        .insert(manifest, architecture)
        .await
        .map_err(|e| {
            if e.is::<store::QueueFull>() {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "queue_full", e.to_string())
            } else {
                ApiError::internal(e)
            }
        })?;
    state.supervisor.wake.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("/api/v1/builds/{}", record.id))],
        Json(Created {
            id: record.id,
            status: record.status,
        }),
    )
        .into_response())
}
fn parse_id(raw: &str) -> Result<BuildId, ApiError> {
    BuildId::from_str(raw).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_build_id",
            "Build ID must be a UUID",
        )
    })
}
async fn lookup(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
) -> Result<Json<BuildRecord>, ApiError> {
    let record = state
        .supervisor
        .store
        .get(parse_id(&raw)?)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::missing)?;
    Ok(Json(record))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "page_size")]
    limit: usize,
}
fn page_size() -> usize {
    200
}
async fn logs(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
    query: Result<Query<LogQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<BuildLogEntry>>, ApiError> {
    let Query(query) = query
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_query", e.body_text()))?;
    if query.limit == 0 || query.limit > 500 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_limit",
            "limit must be between 1 and 500",
        ));
    }
    let id = parse_id(&raw)?;
    if state
        .supervisor
        .store
        .get(id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::missing());
    }
    Ok(Json(
        state
            .supervisor
            .store
            .logs(id, query.after, query.limit)
            .await
            .map_err(ApiError::internal)?,
    ))
}
async fn cancel(
    State(state): State<Arc<ApiState>>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let record = state
        .supervisor
        .store
        .cancel(parse_id(&raw)?)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::missing)?;
    state.supervisor.wake.notify_one();
    let code = if record.status.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((code, Json(record)).into_response())
}
