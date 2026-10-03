pub mod store;
pub mod worker;

use axum::{
    Json, Router,
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
use worker::Supervisor;

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
    Router::new()
        .route("/health", get(health))
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
        .with_state(Arc::new(state))
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
