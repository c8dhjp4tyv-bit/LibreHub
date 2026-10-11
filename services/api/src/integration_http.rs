//! Integration endpoints: GitHub Actions OIDC token exchange, trusted CI identities and
//! outbound webhook subscriptions.
use crate::{
    auth::{AuthenticatedDeveloper, Secret, encrypt_secret_aad, random_secret},
    automation_http::{failure, invalid, owned, parse},
    http::ApiError,
    integration_store::fingerprint,
    oidc_verifier::{OidcVerifier, VerifyError},
    outbound_worker::{Resolver, check_destination},
    platform::Page,
    platform_store::PlatformError,
    store::Store,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use librehub_automation::{oidc::GithubIdentityPolicy, webhook::DestinationPolicy};
use librehub_common::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone)]
pub struct IntegrationHttp {
    pub store: Store,
    pub key: [u8; 32],
    pub verifier: Option<Arc<OidcVerifier>>,
    pub policy: DestinationPolicy,
    pub resolver: Arc<dyn Resolver>,
}

/// Unauthenticated by bearer token: the GitHub identity token itself is the credential.
pub fn public_router(state: IntegrationHttp) -> Router {
    Router::new()
        .route("/api/v1/integrations/github/oidc/exchange", post(exchange))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .with_state(state)
}
pub fn private_router(state: IntegrationHttp) -> Router {
    Router::new()
        .route(
            "/api/v1/projects/{id}/integrations/oidc",
            post(create_connection).get(list_connections),
        )
        .route(
            "/api/v1/projects/{id}/integrations/oidc/{connection}",
            get(show_connection)
                .patch(update_connection)
                .delete(revoke_connection),
        )
        .route(
            "/api/v1/projects/{id}/integrations/webhooks",
            post(create_webhook).get(list_webhooks),
        )
        .route(
            "/api/v1/projects/{id}/integrations/webhooks/{webhook}",
            get(show_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route(
            "/api/v1/projects/{id}/integrations/webhooks/{webhook}/rotate",
            post(rotate_webhook),
        )
        .route(
            "/api/v1/projects/{id}/integrations/webhooks/{webhook}/deliveries",
            get(webhook_deliveries),
        )
        .route(
            "/api/v1/projects/{id}/integrations/deliveries",
            get(project_deliveries),
        )
        .route(
            "/api/v1/projects/{id}/integrations/deliveries/{delivery}",
            get(show_delivery),
        )
        .route(
            "/api/v1/projects/{id}/integrations/deliveries/{delivery}/replay",
            post(replay_delivery),
        )
        .route("/api/v1/projects/{id}/integrations/audit", get(audit))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeRequest {
    project_id: ProjectId,
}
async fn exchange(
    State(s): State<IntegrationHttp>,
    headers: HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let verifier = s.verifier.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_not_configured",
            "OIDC federation is not configured on this server",
        )
    })?;
    let request: ExchangeRequest = parse(body)?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "oidc_token_missing",
                "A GitHub Actions identity token is required",
            )
        })?;
    let claims = verifier.verify(token).await.map_err(|e| match e {
        VerifyError::Token(e) => ApiError::new(
            StatusCode::UNAUTHORIZED,
            e.code(),
            "The identity token was rejected",
        ),
        VerifyError::KeysUnavailable => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "oidc_keys_unavailable",
            "The identity provider's signing keys are unavailable",
        ),
    })?;
    tracing::info!(project_id=%request.project_id, repository_id=%claims.repository_id, run_id=%claims.run_id, "Verified GitHub identity presented for exchange");
    let granted = s
        .store
        .oidc_exchange(verifier.config.issuer.clone(), request.project_id, claims)
        .await
        .map_err(failure)?;
    match granted {
        Ok(grant) => {
            let ttl = (grant.expires_at - chrono::Utc::now()).num_seconds().max(0);
            Ok((
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
                Json(json!({
                    "token": grant.token, "token_type": "Bearer", "expires_at": grant.expires_at, "expires_in": ttl,
                    "scopes": grant.scopes, "project_id": grant.project_id, "integration_id": grant.connection_id,
                })),
            )
                .into_response())
        }
        Err(_) => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "oidc_exchange_denied",
            "This identity is not authorized for the project",
        )),
    }
}

fn page(
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Page, ApiError> {
    query.map_err(|_| invalid())?.0.checked()
}

// ------------------------------------------------------------------ OIDC connections
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewConnection {
    name: String,
    policy: GithubIdentityPolicy,
}
async fn create_connection(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let body: NewConnection = parse(body)?;
    let created = s
        .store
        .create_connection(project.id, auth.developer_id, body.name, body.policy)
        .await
        .map_err(failure)?;
    Ok((StatusCode::CREATED, Json(created)).into_response())
}
async fn list_connections(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<IntegrationConnection>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .connections(project.id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
fn not_found(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, code, "Resource does not exist")
}
async fn show_connection(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, connection)): Path<(String, String)>,
) -> Result<Json<IntegrationConnection>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let id: IntegrationId = connection.parse().map_err(|_| invalid())?;
    Ok(Json(
        s.store
            .connection(project.id, id)
            .await
            .map_err(failure)?
            .ok_or_else(|| not_found("integration_not_found"))?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionPatch {
    #[serde(default)]
    policy: Option<GithubIdentityPolicy>,
    #[serde(default)]
    enabled: Option<bool>,
}
async fn update_connection(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, connection)): Path<(String, String)>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<IntegrationConnection>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let patch: ConnectionPatch = parse(body)?;
    if patch.policy.is_none() && patch.enabled.is_none() {
        return Err(invalid());
    }
    let id: IntegrationId = connection.parse().map_err(|_| invalid())?;
    Ok(Json(
        s.store
            .update_connection(
                project.id,
                id,
                auth.developer_id,
                patch.policy,
                patch.enabled,
            )
            .await
            .map_err(failure)?,
    ))
}
async fn revoke_connection(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, connection)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let id: IntegrationId = connection.parse().map_err(|_| invalid())?;
    s.store
        .revoke_connection(project.id, id, auth.developer_id)
        .await
        .map_err(failure)?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ webhooks
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewWebhook {
    url: String,
    #[serde(default)]
    description: String,
    event_types: Vec<String>,
    #[serde(default)]
    exclude_origins: Vec<String>,
}
const ORIGINS: &[&str] = &["automation", "manual", "webhook", "system"];
fn validate_filters(events: &[String], origins: &[String]) -> Result<(), ApiError> {
    if events.is_empty()
        || events.len() > OUTBOUND_EVENT_TYPES.len()
        || events
            .iter()
            .any(|e| !OUTBOUND_EVENT_TYPES.contains(&e.as_str()))
        || origins.len() > ORIGINS.len()
        || origins.iter().any(|o| !ORIGINS.contains(&o.as_str()))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_filter",
            "event_types and exclude_origins contain unsupported values",
        ));
    }
    Ok(())
}
async fn validate_url(s: &IntegrationHttp, url: &str) -> Result<(), ApiError> {
    check_destination(url, s.policy, s.resolver.as_ref())
        .await
        .map(|_| ())
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                e.code(),
                "The webhook destination is not allowed",
            )
        })
}
fn new_secret(key: &[u8; 32], id: WebhookId) -> Result<(Secret, Vec<u8>, String), ApiError> {
    let secret = Secret(format!(
        "whsec_{}",
        random_secret().map_err(ApiError::internal)?.0
    ));
    let cipher = encrypt_secret_aad(key, &id.to_string(), &secret).map_err(ApiError::internal)?;
    let fp = fingerprint(&secret.0);
    Ok((secret, cipher, fp))
}
async fn create_webhook(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let body: NewWebhook = parse(body)?;
    if body.description.len() > 200 || body.description.chars().any(char::is_control) {
        return Err(invalid());
    }
    validate_filters(&body.event_types, &body.exclude_origins)?;
    validate_url(&s, &body.url).await?;
    let id = WebhookId::new();
    let (secret, cipher, fp) = new_secret(&s.key, id)?;
    let view = s
        .store
        .create_webhook(
            project.id,
            auth.developer_id,
            id,
            body.url,
            body.description,
            body.event_types,
            body.exclude_origins,
            cipher,
            fp,
        )
        .await
        .map_err(failure)?;
    // The only time the secret is ever visible.
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"webhook":view,"secret":secret})),
    )
        .into_response())
}
async fn list_webhooks(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<WebhookView>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .webhooks(project.id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
fn webhook_id(raw: &str) -> Result<WebhookId, ApiError> {
    raw.parse().map_err(|_| invalid())
}
async fn show_webhook(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, webhook)): Path<(String, String)>,
) -> Result<Json<WebhookView>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    Ok(Json(
        s.store
            .webhook(project.id, webhook_id(&webhook)?)
            .await
            .map_err(failure)?
            .ok_or_else(|| not_found("webhook_not_found"))?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookPatch {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    event_types: Option<Vec<String>>,
    #[serde(default)]
    exclude_origins: Option<Vec<String>>,
    #[serde(default)]
    enabled: Option<bool>,
}
async fn update_webhook(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, webhook)): Path<(String, String)>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<WebhookView>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let patch: WebhookPatch = parse(body)?;
    if let Some(url) = &patch.url {
        validate_url(&s, url).await?;
    }
    if patch.event_types.is_some() || patch.exclude_origins.is_some() {
        let current = s
            .store
            .webhook(project.id, webhook_id(&webhook)?)
            .await
            .map_err(failure)?
            .ok_or_else(|| not_found("webhook_not_found"))?;
        validate_filters(
            patch.event_types.as_deref().unwrap_or(&current.event_types),
            patch
                .exclude_origins
                .as_deref()
                .unwrap_or(&current.exclude_origins),
        )?;
    }
    if patch
        .description
        .as_deref()
        .is_some_and(|d| d.len() > 200 || d.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    Ok(Json(
        s.store
            .update_webhook(
                project.id,
                webhook_id(&webhook)?,
                auth.developer_id,
                patch.url,
                patch.description,
                patch.event_types,
                patch.exclude_origins,
                patch.enabled,
            )
            .await
            .map_err(failure)?,
    ))
}
async fn delete_webhook(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, webhook)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    s.store
        .delete_webhook(project.id, webhook_id(&webhook)?, auth.developer_id)
        .await
        .map_err(failure)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn rotate_webhook(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, webhook)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let id = webhook_id(&webhook)?;
    s.store
        .webhook(project.id, id)
        .await
        .map_err(failure)?
        .ok_or_else(|| not_found("webhook_not_found"))?;
    let (secret, cipher, fp) = new_secret(&s.key, id)?;
    let view = s
        .store
        .rotate_webhook_secret(project.id, id, auth.developer_id, cipher, fp)
        .await
        .map_err(failure)?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"webhook":view,"secret":secret})),
    )
        .into_response())
}
async fn webhook_deliveries(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, webhook)): Path<(String, String)>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<DeliveryView>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .deliveries(
                project.id,
                Some(webhook_id(&webhook)?),
                page.limit,
                page.offset,
            )
            .await
            .map_err(failure)?,
    ))
}
async fn project_deliveries(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<DeliveryView>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .deliveries(project.id, None, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
fn delivery_id(raw: &str) -> Result<DeliveryId, ApiError> {
    raw.parse().map_err(|_| invalid())
}
async fn show_delivery(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, delivery)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let (view, attempts) = s
        .store
        .delivery(project.id, delivery_id(&delivery)?)
        .await
        .map_err(failure)?
        .ok_or_else(|| not_found("delivery_not_found"))?;
    Ok(Json(json!({"delivery":view,"attempts":attempts})))
}
async fn replay_delivery(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, delivery)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let view = s
        .store
        .replay_delivery(project.id, delivery_id(&delivery)?, auth.developer_id)
        .await
        .map_err(failure)?;
    Ok((StatusCode::ACCEPTED, Json(view)).into_response())
}
async fn audit(
    State(s): State<IntegrationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .integration_audit_events(project.id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}

#[allow(dead_code)]
fn _error_is_platform(e: PlatformError) -> PlatformError {
    e
}
