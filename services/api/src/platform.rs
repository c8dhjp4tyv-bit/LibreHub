//! Owner-scoped HTTP boundary. Git and publishing work run outside request handlers.
use crate::{
    auth::{self, AuthenticatedDeveloper, Secret},
    http::{ApiError, ApiState},
    platform_store::{Admission, PlatformError, SourceAdmission, WebhookAdmission},
    publishing::Publishing,
    source_worker::SourceWorker,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use librehub_common::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::Arc;

#[derive(Clone)]
pub struct Platform {
    pub worker: SourceWorker,
    pub key: [u8; 32],
}
impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform { secrets: [REDACTED] }")
    }
}
pub fn router(state: ApiState, publishing: Option<Publishing>, platform: Platform) -> Router {
    let store = state.supervisor.store.clone();
    // Keep M1/M2 request/response compatibility, adding auth at their shared boundary.
    let legacy = crate::http::router_with_publisher(state, publishing)
        .route_layer(axum::middleware::from_fn_with_state(store.clone(), guard));
    let platform = Arc::new(platform);
    let private = Router::new()
        .route("/api/v1/projects", post(create_project).get(list_projects))
        .route(
            "/api/v1/projects/{id}",
            get(get_project)
                .patch(update_project)
                .delete(archive_project),
        )
        .route(
            "/api/v1/projects/{id}/webhook-secret/rotate",
            post(rotate_secret),
        )
        .route("/api/v1/projects/{id}/builds", post(trigger).get(history))
        .route(
            "/api/v1/projects/{id}/source-events/{event}",
            get(source_event),
        )
        .route("/api/v1/projects/{id}/audit", get(project_audit))
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/{id}", axum::routing::delete(revoke_token))
        .route("/api/v1/audit", get(list_audit))
        .route_layer(axum::middleware::from_fn_with_state(
            store,
            auth::middleware,
        ));
    let app = private
        .merge(Router::new().route("/api/v1/webhooks/github/{id}", post(webhook)))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(platform.clone());
    legacy.merge(app).layer(Extension(platform))
}
async fn guard(
    State(store): State<crate::store::Store>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, ApiError> {
    if request.uri().path().starts_with("/api/") {
        auth::middleware(State(store), request, next).await
    } else {
        Ok(next.run(request).await)
    }
}
fn failure(error: anyhow::Error) -> ApiError {
    if let Some(error) = error.downcast_ref::<PlatformError>() {
        let code = error.0;
        let status = match code {
            "project_not_found" => StatusCode::NOT_FOUND,
            "project_disabled" | "project_slug_taken" | "project_update_conflict" => {
                StatusCode::CONFLICT
            }
            "webhook_signature_invalid" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        return ApiError::new(
            status,
            code,
            "The developer-platform operation was rejected",
        );
    }
    ApiError::internal(error)
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Request fields are invalid",
    )
}
fn id(raw: &str) -> Result<ProjectId, ApiError> {
    raw.parse().map_err(|_| invalid())
}
async fn owned(
    platform: &Platform,
    auth: &AuthenticatedDeveloper,
    id: ProjectId,
) -> Result<Project, ApiError> {
    platform
        .worker
        .supervisor
        .store
        .project(id, auth.developer_id)
        .await
        .map_err(failure)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "project_not_found",
                "Project does not exist",
            )
        })
}
fn parse<T: serde::de::DeserializeOwned>(
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<T, ApiError> {
    let body =
        body.map_err(|e| ApiError::new(e.status(), "invalid_body", "Request body exceeds limits"))?;
    serde_json::from_slice(&body).map_err(|_| invalid())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewProject {
    slug: String,
    display_name: String,
    #[serde(default)]
    description: String,
    repository: ProjectSource,
    #[serde(default = "default_branch")]
    default_branch: String,
    #[serde(default)]
    manifest_path: Option<String>,
    #[serde(default)]
    auto_build: bool,
    #[serde(default)]
    build_branches: Vec<String>,
    #[serde(default)]
    build_tags: bool,
    #[serde(default, deserialize_with = "channel")]
    auto_publish_channel: Option<RepositoryChannel>,
    #[serde(default)]
    auto_publish_tags_only: bool,
}
fn default_branch() -> String {
    "main".into()
}
fn channel<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<RepositoryChannel>, D::Error> {
    let value = Option::<String>::deserialize(d)?;
    match value.as_deref() {
        None | Some("none") => Ok(None),
        Some("beta") => Ok(Some(RepositoryChannel::Beta)),
        Some("stable") => Ok(Some(RepositoryChannel::Stable)),
        _ => Err(serde::de::Error::custom("Invalid channel")),
    }
}
fn validate_project(record: &mut Project) -> Result<(), ApiError> {
    if record.slug.is_empty()
        || record.slug.len() > 64
        || !record.slug.as_bytes()[0].is_ascii_lowercase()
        || record.slug.ends_with('-')
        || !record
            .slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || record.display_name.trim().is_empty()
        || record.display_name.len() > 120
        || record.description.len() > 4096
        || !librehub_source::safe_ref(&record.settings.default_branch)
        || record.settings.default_branch.starts_with("refs/")
        || record.settings.build_branches.len() > 16
        || record
            .settings
            .build_branches
            .iter()
            .any(|b| !librehub_source::safe_ref(b) || b.starts_with("refs/"))
        || record
            .settings
            .manifest_path
            .as_ref()
            .is_some_and(|p| !librehub_source::safe_path(p))
    {
        return Err(invalid());
    }
    record.repository =
        librehub_source::normalize_repository(&record.repository).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "repository_not_allowed",
                "The repository URL is not permitted",
            )
        })?;
    Ok(())
}
async fn create_project(
    State(platform): State<Arc<Platform>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let request: NewProject = parse(body)?;
    let now = chrono::Utc::now();
    if request.auto_build {
        auth.require(Scope::BuildsWrite)?;
    }
    if request.auto_publish_channel.is_some() {
        auth.require(Scope::PublishesWrite)?;
    }
    let branches = if request.build_branches.is_empty() {
        vec![request.default_branch.clone()]
    } else {
        request.build_branches
    };
    let mut project = Project {
        id: ProjectId::new(),
        owner_developer_id: auth.developer_id,
        slug: request.slug,
        display_name: request.display_name,
        description: request.description,
        repository: request.repository,
        settings: ProjectSettings {
            default_branch: request.default_branch,
            manifest_path: request.manifest_path,
            auto_build: request.auto_build,
            build_branches: branches,
            build_tags: request.build_tags,
            auto_publish_channel: request.auto_publish_channel,
            auto_publish_tags_only: request.auto_publish_tags_only,
        },
        status: ProjectStatus::Active,
        policy_version: 1,
        created_at: now,
        updated_at: now,
    };
    validate_project(&mut project)?;
    let secret = auth::random_secret().map_err(failure)?;
    let project = platform
        .worker
        .supervisor
        .store
        .create_project(project, platform.key, secret.clone())
        .await
        .map_err(failure)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"project":project,"webhook_secret":secret})),
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    #[serde(default = "page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}
fn page_limit() -> usize {
    50
}
impl Page {
    pub fn checked(self) -> Result<Self, ApiError> {
        if self.limit == 0 || self.limit > 100 || self.offset > 1_000_000 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_pagination",
                "limit must be 1–100 and offset at most 1000000",
            ));
        }
        Ok(self)
    }
}
async fn list_projects(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<Project>>, ApiError> {
    let page = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        p.worker
            .supervisor
            .store
            .projects(a.developer_id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
async fn get_project(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
) -> Result<Json<Project>, ApiError> {
    Ok(Json(owned(&p, &a, id(&raw)?).await?))
}
async fn update_project(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<Project>, ApiError> {
    let patch: serde_json::Map<String, Value> = parse(body)?;
    let mut project = owned(&p, &a, id(&raw)?).await?;
    let version = project.policy_version;
    // Deserialize the merged document to reuse all typed fields. Identity fields are immutable.
    let mut value = serde_json::to_value(&project).map_err(|_| invalid())?;
    for (key, val) in patch {
        if ![
            "display_name",
            "description",
            "repository",
            "default_branch",
            "manifest_path",
            "auto_build",
            "build_branches",
            "build_tags",
            "auto_publish_channel",
            "auto_publish_tags_only",
            "status",
        ]
        .contains(&key.as_str())
        {
            return Err(invalid());
        }
        if key == "auto_build" && val == true {
            a.require(Scope::BuildsWrite)?;
        }
        if key == "auto_publish_channel" || key == "auto_publish_tags_only" {
            a.require(Scope::PublishesWrite)?;
        }
        value[&key] = if key == "auto_publish_channel" && val == "none" {
            Value::Null
        } else {
            val
        };
    }
    project = serde_json::from_value(value).map_err(|_| invalid())?;
    if project.settings.auto_publish_channel.is_some() {
        a.require(Scope::PublishesWrite)?;
    }
    validate_project(&mut project)?;
    project.policy_version += 1;
    project.updated_at = chrono::Utc::now();
    Ok(Json(
        p.worker
            .supervisor
            .store
            .update_project(project, version, "project.updated")
            .await
            .map_err(failure)?,
    ))
}
async fn archive_project(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
) -> Result<Json<Project>, ApiError> {
    let mut project = owned(&p, &a, id(&raw)?).await?;
    if project.status == ProjectStatus::Archived {
        return Ok(Json(project));
    }
    let version = project.policy_version;
    project.status = ProjectStatus::Archived;
    project.policy_version += 1;
    project.updated_at = chrono::Utc::now();
    Ok(Json(
        p.worker
            .supervisor
            .store
            .update_project(project, version, "project.deleted")
            .await
            .map_err(failure)?,
    ))
}
async fn rotate_secret(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let project = owned(&p, &a, id(&raw)?).await?;
    let secret = auth::random_secret().map_err(failure)?;
    p.worker
        .supervisor
        .store
        .rotate_webhook(project.id, a.developer_id, p.key, secret.clone())
        .await
        .map_err(failure)?;
    Ok(Json(json!({"webhook_secret":secret})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trigger {
    #[serde(rename = "ref")]
    source_ref: Option<String>,
}
async fn trigger(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let request: Trigger = parse(body)?;
    let project = owned(&p, &a, id(&raw)?).await?;
    let source_ref = request
        .source_ref
        .unwrap_or(project.settings.default_branch);
    if !librehub_source::safe_ref(&source_ref) {
        return Err(invalid());
    }
    let result = p
        .worker
        .supervisor
        .store
        .admit_source(
            SourceAdmission {
                project_id: project.id,
                owner: Some(a.developer_id),
                trigger: TriggerType::Manual,
                source_ref,
                commit: None,
                webhook: None,
            },
            false,
        )
        .await
        .map_err(failure)?;
    let Admission::Created(event) = result else {
        return Err(invalid());
    };
    p.worker.wake.notify_one();
    let location = format!(
        "/api/v1/projects/{}/source-events/{}",
        event.project_id, event.id
    );
    Ok((
        StatusCode::ACCEPTED,
        [(header::LOCATION, location)],
        Json(json!({"build_id":event.build_id,"source_event_id":event.id,"status":event.status})),
    )
        .into_response())
}
async fn source_event(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path((raw, event)): Path<(String, String)>,
) -> Result<Json<SourceEvent>, ApiError> {
    let project = owned(&p, &a, id(&raw)?).await?;
    let event = event.parse().map_err(|_| invalid())?;
    Ok(Json(
        p.worker
            .supervisor
            .store
            .source_event(event, project.id)
            .await
            .map_err(failure)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "source_event_not_found",
                    "Source event does not exist",
                )
            })?,
    ))
}
#[derive(Serialize)]
struct History {
    build_id: BuildId,
    source_event_id: SourceEventId,
    status: Value,
    source_status: SourceEventStatus,
    source_commit: Option<String>,
    source_ref: String,
    trigger: TriggerType,
    created_at: Timestamp,
    finished_at: Option<Timestamp>,
    provenance: Option<BuildProvenance>,
    error: Option<SourceFailure>,
    publishes: Vec<PublishRecord>,
}
async fn history(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<History>>, ApiError> {
    let project = owned(&p, &a, id(&raw)?).await?;
    let page = query.map_err(|_| invalid())?.0.checked()?;
    let store = &p.worker.supervisor.store;
    let events = store
        .project_events(project.id, page.limit, page.offset)
        .await
        .map_err(failure)?;
    let mut rows = Vec::new();
    for event in events {
        let build = store.get(event.build_id).await.map_err(failure)?;
        rows.push(History {
            build_id: event.build_id,
            source_event_id: event.id,
            status: build
                .as_ref()
                .map(|b| serde_json::to_value(b.status).unwrap_or(Value::Null))
                .unwrap_or(serde_json::to_value(event.status).unwrap_or(Value::Null)),
            source_status: event.status,
            source_commit: event.revision.map(|r| r.commit),
            source_ref: event.source_ref,
            trigger: event.trigger,
            created_at: event.received_at,
            finished_at: build
                .as_ref()
                .and_then(|b| b.finished_at)
                .or(event.processed_at),
            provenance: build.and_then(|b| b.provenance),
            error: event.error,
            publishes: store.publications(event.build_id).await.map_err(failure)?,
        });
    }
    Ok(Json(rows))
}
async fn list_audit(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    let page = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        p.worker
            .supervisor
            .store
            .audit_events(a.developer_id, None, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
async fn project_audit(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    let project = owned(&p, &a, id(&raw)?).await?;
    let page = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        p.worker
            .supervisor
            .store
            .audit_events(a.developer_id, Some(project.id), page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewToken {
    name: String,
    scopes: Vec<Scope>,
}
async fn create_token(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let request: NewToken = parse(body)?;
    if request.scopes.contains(&Scope::Operator)
        || request.scopes.iter().any(|s| !a.scopes.contains(s))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "Cannot delegate scopes absent from this token",
        ));
    }
    if request.name.is_empty()
        || request.name.len() > 120
        || request.scopes.is_empty()
        || request.scopes.len() > 10
    {
        return Err(invalid());
    }
    Ok((
        StatusCode::CREATED,
        Json(
            p.worker
                .supervisor
                .store
                .issue_token(a.developer_id, request.name, request.scopes)
                .await
                .map_err(failure)?,
        ),
    )
        .into_response())
}
async fn list_tokens(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<ApiToken>>, ApiError> {
    let page = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        p.worker
            .supervisor
            .store
            .tokens(a.developer_id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
async fn revoke_token(
    State(p): State<Arc<Platform>>,
    Extension(a): Extension<AuthenticatedDeveloper>,
    Path(raw): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !p
        .worker
        .supervisor
        .store
        .revoke_token(a.developer_id, raw.parse().map_err(|_| invalid())?)
        .await
        .map_err(failure)?
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "token_not_found",
            "Token does not exist",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}
pub fn verify_signature(secret: &Secret, body: &[u8], signature: Option<&str>) -> bool {
    let Some(signature) = signature.and_then(|s| s.strip_prefix("sha256=")) else {
        return false;
    };
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mut digest = [0_u8; 32];
    for (i, out) in digest.iter_mut().enumerate() {
        let Ok(byte) = u8::from_str_radix(&signature[i * 2..i * 2 + 2], 16) else {
            return false;
        };
        *out = byte;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.0.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&digest).is_ok()
}
async fn webhook(
    State(p): State<Arc<Platform>>,
    Path(raw): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let body = body
        .map_err(|e| ApiError::new(e.status(), "invalid_body", "Webhook payload exceeds limits"))?;
    let project_id = id(&raw)?;
    let (project, cipher) = p
        .worker
        .supervisor
        .store
        .webhook_connection(project_id)
        .await
        .map_err(failure)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "project_not_found",
                "Project does not exist",
            )
        })?;
    let secret = auth::decrypt_secret(&p.key, project_id, &cipher).map_err(failure)?;
    let header_text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if !verify_signature(&secret, &body, header_text("x-hub-signature-256")) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "webhook_signature_invalid",
            "Webhook signature is invalid",
        ));
    }
    let delivery = header_text("x-github-delivery").ok_or_else(invalid)?;
    let delivery = delivery
        .parse::<uuid::Uuid>()
        .map_err(|_| invalid())?
        .to_string();
    let kind = header_text("x-github-event").ok_or_else(invalid)?;
    if kind.len() > 64 || !kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        return Err(invalid());
    }
    // JSON is processed only after HMAC verification. Never store/log raw payloads.
    let payload: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
    let supported = ["push", "create"].contains(&kind);
    let mut ignored = !supported || !project.settings.auto_build;
    if supported {
        let url = payload["repository"]["clone_url"]
            .as_str()
            .ok_or_else(invalid)?;
        let source = ProjectSource {
            provider: project.repository.provider,
            url: url.into(),
        };
        let normalized = librehub_source::normalize_repository(&source).map_err(|_| invalid())?;
        if normalized.url != project.repository.url {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "webhook_repository_mismatch",
                "Webhook repository does not match this project",
            ));
        }
    }
    let mut source_ref = project.settings.default_branch.clone();
    let mut commit = None;
    let mut trigger = TriggerType::WebhookPush;
    match kind {
        "push" => {
            source_ref = payload["ref"].as_str().ok_or_else(invalid)?.into();
            if let Some(branch) = source_ref.strip_prefix("refs/heads/") {
                ignored |= !project.settings.build_branches.iter().any(|b| b == branch);
            } else if source_ref.starts_with("refs/tags/") {
                trigger = TriggerType::WebhookTag;
                ignored |= !project.settings.build_tags;
            } else {
                return Err(invalid());
            }
            ignored |= payload["deleted"].as_bool().unwrap_or(false);
            if !ignored {
                let sha = payload["after"].as_str().ok_or_else(invalid)?;
                if !librehub_source::valid_commit(sha) {
                    return Err(invalid());
                }
                commit = Some(sha.to_owned());
            }
        }
        "create" => {
            if payload["ref_type"] == "tag" {
                let tag = payload["ref"].as_str().ok_or_else(invalid)?;
                source_ref = format!("refs/tags/{tag}");
                trigger = TriggerType::WebhookTag;
                ignored |= !project.settings.build_tags;
            } else {
                ignored = true;
            }
        }
        _ => {}
    }
    if !librehub_source::safe_ref(&source_ref) {
        return Err(invalid());
    }
    let admission = SourceAdmission {
        project_id,
        owner: None,
        trigger,
        source_ref,
        commit,
        webhook: Some(WebhookAdmission {
            delivery_id: delivery.clone(),
            event_type: kind.into(),
            expected_cipher: cipher,
            expected_policy: project.policy_version,
        }),
    };
    let result = p
        .worker
        .supervisor
        .store
        .admit_source(admission, ignored)
        .await
        .map_err(failure)?;
    tracing::info!(%project_id,webhook_delivery_id=%delivery,"Verified webhook delivery admitted");
    Ok(match result {
        Admission::Created(event) => {
            p.worker.wake.notify_one();
            (
                StatusCode::ACCEPTED,
                Json(
                    json!({"status":"queued","source_event_id":event.id,"build_id":event.build_id}),
                ),
            )
                .into_response()
        }
        Admission::Duplicate(event) => (
            StatusCode::OK,
            Json(json!({"code":"webhook_duplicate","status":"duplicate","source_event_id":event})),
        )
            .into_response(),
        Admission::Ignored => (StatusCode::OK, Json(json!({"status":"ignored"}))).into_response(),
    })
}
