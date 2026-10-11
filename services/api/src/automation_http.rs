//! Project-scoped automation, run and approval endpoints. All routes sit behind the M3 bearer
//! middleware, which maps them to `automations:*` / `releases:approve` scopes and confines
//! federated CI credentials to their one project.
use crate::{
    auth::AuthenticatedDeveloper,
    automation_store::{AdmitRun, AutomationPatch, DecideApproval, NewAutomation, RunAdmission},
    http::ApiError,
    platform::Page,
    platform_store::PlatformError,
    store::Store,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use librehub_automation::workflow::{self, WorkflowSpec};
use librehub_common::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Clone)]
pub struct AutomationHttp {
    pub store: Store,
    pub wake: Arc<Notify>,
}

pub fn router(state: AutomationHttp) -> Router {
    Router::new()
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/projects/{id}/automations", post(create).get(list))
        .route(
            "/api/v1/projects/{id}/automations/{automation}",
            get(show).patch(update),
        )
        .route(
            "/api/v1/projects/{id}/automations/{automation}/run",
            post(trigger),
        )
        .route(
            "/api/v1/projects/{id}/automations/{automation}/runs",
            get(runs_of),
        )
        .route("/api/v1/projects/{id}/runs", get(project_runs))
        .route(
            "/api/v1/projects/{id}/automations/runs/{run}",
            get(run_detail),
        )
        .route(
            "/api/v1/projects/{id}/automations/runs/{run}/events",
            get(run_events),
        )
        .route(
            "/api/v1/projects/{id}/automations/runs/{run}/cancel",
            post(cancel),
        )
        .route("/api/v1/projects/{id}/approvals", get(project_approvals))
        .route("/api/v1/approvals", get(approvals))
        .route("/api/v1/approvals/{approval}", get(approval))
        .route("/api/v1/approvals/{approval}/approve", post(approve))
        .route("/api/v1/approvals/{approval}/reject", post(reject))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(state)
}

/// Never reveals secrets: identifiers, granted scopes and the project binding only.
async fn whoami(Extension(auth): Extension<AuthenticatedDeveloper>) -> Json<Value> {
    Json(json!({
        "developer_id": auth.developer_id, "token_id": auth.token_id, "scopes": auth.scopes,
        "project_id": auth.project_id, "federated": auth.is_federated(),
    }))
}

pub(crate) fn failure(error: anyhow::Error) -> ApiError {
    if let Some(e) = error.downcast_ref::<PlatformError>() {
        let status = match e.0 {
            "project_not_found"
            | "automation_not_found"
            | "automation_run_not_found"
            | "approval_not_found"
            | "webhook_not_found"
            | "integration_not_found"
            | "delivery_not_found" => StatusCode::NOT_FOUND,
            "invalid_request" | "workflow_invalid" => StatusCode::BAD_REQUEST,
            "project_not_active"
            | "automation_disabled"
            | "automation_name_taken"
            | "integration_exists"
            | "webhook_exists"
            | "approval_not_pending"
            | "approval_expired"
            | "approval_stale"
            | "approval_invalid"
            | "delivery_in_progress"
            | "automation_trigger_not_allowed"
            | "automation_cancelled" => StatusCode::CONFLICT,
            "automation_limit_exceeded"
            | "automation_queue_full"
            | "automation_history_limit"
            | "automation_rate_limited"
            | "approval_limit_exceeded"
            | "webhook_limit_exceeded"
            | "integration_limit_exceeded" => StatusCode::TOO_MANY_REQUESTS,
            "automation_loop_detected" => StatusCode::UNPROCESSABLE_ENTITY,
            "developer_disabled" => StatusCode::FORBIDDEN,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        return ApiError::new(status, e.0, e.0.replace('_', " "));
    }
    ApiError::internal(error)
}
pub(crate) fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Request fields are invalid",
    )
}
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<T, ApiError> {
    let body =
        body.map_err(|e| ApiError::new(e.status(), "invalid_body", "Request body exceeds limits"))?;
    serde_json::from_slice(&body).map_err(|_| invalid())
}
fn workflow_error(error: workflow::WorkflowError) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, error.code, error.message)
}
pub(crate) async fn owned(
    store: &Store,
    auth: &AuthenticatedDeveloper,
    raw: &str,
) -> Result<Project, ApiError> {
    let id: ProjectId = raw.parse().map_err(|_| invalid())?;
    if !auth.can_access_project(id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "project_not_found",
            "Project does not exist",
        ));
    }
    store
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
fn page(
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Page, ApiError> {
    query.map_err(|_| invalid())?.0.checked()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecBody {
    #[serde(default)]
    spec: Option<Value>,
    #[serde(default)]
    yaml: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    schedules_enabled: Option<bool>,
}
impl SpecBody {
    fn workflow(&self) -> Result<Option<WorkflowSpec>, ApiError> {
        match (&self.spec, &self.yaml) {
            (Some(_), Some(_)) => Err(invalid()),
            (Some(value), None) => workflow::parse_workflow_value(value.clone())
                .map(Some)
                .map_err(workflow_error),
            (None, Some(text)) => workflow::parse_workflow(text)
                .map(Some)
                .map_err(workflow_error),
            (None, None) => Ok(None),
        }
    }
}

async fn create(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let body: SpecBody = parse(body)?;
    let spec = body.workflow()?.ok_or_else(invalid)?;
    let definition = s
        .store
        .create_automation(NewAutomation {
            project_id: project.id,
            owner: auth.developer_id,
            spec,
        })
        .await
        .map_err(failure)?;
    Ok((
        StatusCode::CREATED,
        Json(definition_view(&s.store, definition).await?),
    )
        .into_response())
}
async fn definition_view(
    store: &Store,
    definition: AutomationDefinition,
) -> Result<Value, ApiError> {
    let schedules = store
        .next_schedule_times(definition.id)
        .await
        .map_err(failure)?;
    let mut value = serde_json::to_value(&definition).map_err(|e| ApiError::internal(e.into()))?;
    value["schedules"] = json!(
        schedules
            .into_iter()
            .map(|(i, t)| json!({"trigger_index":i,"next_run_at":t}))
            .collect::<Vec<_>>()
    );
    Ok(value)
}
async fn list(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<AutomationDefinition>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .automations(project.id, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
fn automation_id(raw: &str) -> Result<AutomationId, ApiError> {
    raw.parse().map_err(|_| invalid())
}
async fn show(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, automation)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let definition = s
        .store
        .automation(project.id, automation_id(&automation)?)
        .await
        .map_err(failure)?
        .ok_or(PlatformError("automation_not_found"))
        .map_err(|e| failure(e.into()))?;
    Ok(Json(definition_view(&s.store, definition).await?))
}
async fn update(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, automation)): Path<(String, String)>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let body: SpecBody = parse(body)?;
    let spec = body.workflow()?;
    if spec.is_none() && body.enabled.is_none() && body.schedules_enabled.is_none() {
        return Err(invalid());
    }
    let definition = s
        .store
        .update_automation(
            project.id,
            automation_id(&automation)?,
            auth.developer_id,
            AutomationPatch {
                spec,
                enabled: body.enabled,
                schedules_enabled: body.schedules_enabled,
            },
        )
        .await
        .map_err(failure)?;
    Ok(Json(definition_view(&s.store, definition).await?))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    #[serde(default, rename = "ref")]
    source_ref: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    /// Intentionally build again even if this commit already has a usable build.
    #[serde(default)]
    fresh_build: bool,
    #[serde(default)]
    idempotency_key: Option<String>,
    /// Receivers of LibreHub events pass `event.chain_depth + 1` when they trigger a run.
    #[serde(default)]
    chain_depth: Option<u32>,
    #[serde(default)]
    correlation_id: Option<String>,
}
fn token_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
async fn trigger(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, automation)): Path<(String, String)>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let automation = automation_id(&automation)?;
    let request: RunRequest = match body {
        Ok(bytes) if bytes.is_empty() => RunRequest::default(),
        other => parse(other)?,
    };
    if request
        .commit
        .as_deref()
        .is_some_and(|c| !librehub_source::valid_commit(c))
        || request
            .source_ref
            .as_deref()
            .is_some_and(|r| !librehub_source::safe_ref(r))
        || request
            .idempotency_key
            .as_deref()
            .is_some_and(|k| !token_safe(k))
        || request
            .correlation_id
            .as_deref()
            .is_some_and(|c| !token_safe(c))
    {
        return Err(invalid());
    }
    let chain_depth = request.chain_depth.unwrap_or(0);
    let input = if auth.is_federated() {
        // The commit and ref come from GitHub's signed claims; a CI identity can only run what
        // GitHub attests it is running.
        let claims = s
            .store
            .exchange_claims(auth.token_id)
            .await
            .map_err(failure)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::FORBIDDEN,
                    "federated_scope_violation",
                    "Credential has no verified identity",
                )
            })?;
        let sha = claims["sha"].as_str().unwrap_or_default().to_owned();
        let git_ref = claims["ref"].as_str().unwrap_or_default().to_owned();
        if request.commit.as_deref().is_some_and(|c| c != sha)
            || request.source_ref.as_deref().is_some_and(|r| r != git_ref)
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "ci_commit_mismatch",
                "A CI identity may only run the commit and ref GitHub attests",
            ));
        }
        let key = format!(
            "ci:{}:{}:{}",
            claims["repository_id"].as_str().unwrap_or("0"),
            claims["run_id"].as_str().unwrap_or("0"),
            claims["run_attempt"].as_str().unwrap_or("0")
        );
        AdmitRun {
            project_id: project.id,
            automation_id: automation,
            trigger: AutomationTrigger::Ci,
            trigger_key: key,
            trigger_detail: json!({
                "provider":"github","repository_id":claims["repository_id"],"run_id":claims["run_id"],"run_attempt":claims["run_attempt"],
                "workflow_ref":claims["workflow_ref"],"event_name":claims["event_name"],"ref":git_ref,"sha":sha,
            }),
            source_ref: Some(git_ref),
            source_commit: Some(sha),
            fresh_build: request.fresh_build,
            chain_depth,
            correlation_id: request.correlation_id,
            expected_owner: Some(auth.developer_id),
            actor: format!("ci:{}", claims["repository_id"].as_str().unwrap_or("0")),
        }
    } else {
        AdmitRun {
            project_id: project.id,
            automation_id: automation,
            trigger: AutomationTrigger::Manual,
            trigger_key: format!(
                "manual:{}",
                request
                    .idempotency_key
                    .clone()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
            ),
            trigger_detail: json!({"developer_id":auth.developer_id}),
            source_ref: Some(
                request
                    .source_ref
                    .clone()
                    .unwrap_or_else(|| project.settings.default_branch.clone()),
            ),
            source_commit: request.commit.clone(),
            fresh_build: request.fresh_build,
            chain_depth,
            correlation_id: request.correlation_id,
            expected_owner: Some(auth.developer_id),
            actor: format!("developer:{}", auth.developer_id),
        }
    };
    let admission = s.store.admit_run(input).await.map_err(failure)?;
    s.wake.notify_one();
    let (status, existing) = if admission.created() {
        (StatusCode::ACCEPTED, false)
    } else {
        (StatusCode::OK, true)
    };
    let run = admission.run();
    let location = format!(
        "/api/v1/projects/{}/automations/runs/{}",
        run.project_id, run.id
    );
    Ok((
        status,
        [(axum::http::header::LOCATION, location)],
        Json(json!({"run":run,"existing":existing})),
    )
        .into_response())
}
async fn runs_of(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, automation)): Path<(String, String)>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<AutomationRun>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .automation_runs(
                project.id,
                Some(automation_id(&automation)?),
                page.limit,
                page.offset,
            )
            .await
            .map_err(failure)?,
    ))
}
async fn project_runs(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<Page>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<AutomationRun>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let page = page(query)?;
    Ok(Json(
        s.store
            .automation_runs(project.id, None, page.limit, page.offset)
            .await
            .map_err(failure)?,
    ))
}
fn run_id(raw: &str) -> Result<AutomationRunId, ApiError> {
    raw.parse().map_err(|_| invalid())
}
async fn run_detail(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, run)): Path<(String, String)>,
) -> Result<Json<AutomationRun>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    Ok(Json(
        s.store
            .automation_run(project.id, run_id(&run)?)
            .await
            .map_err(failure)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "automation_run_not_found",
                    "Run does not exist",
                )
            })?,
    ))
}
async fn run_events(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, run)): Path<(String, String)>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let id = run_id(&run)?;
    s.store
        .automation_run(project.id, id)
        .await
        .map_err(failure)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "automation_run_not_found",
                "Run does not exist",
            )
        })?;
    Ok(Json(
        s.store
            .automation_run_events(id, 200)
            .await
            .map_err(failure)?,
    ))
}
async fn cancel(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path((project, run)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let run = s
        .store
        .cancel_run(project.id, run_id(&run)?, auth.developer_id)
        .await
        .map_err(failure)?;
    s.wake.notify_one();
    let status = if run.status.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(run)).into_response())
}

// ------------------------------------------------------------------ approvals
#[derive(Deserialize)]
struct ApprovalQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}
fn default_limit() -> usize {
    50
}
impl ApprovalQuery {
    fn checked(self) -> Result<(Option<ApprovalStatus>, usize, usize), ApiError> {
        if self.limit == 0 || self.limit > 100 || self.offset > 1_000_000 {
            return Err(invalid());
        }
        let status = self
            .status
            .as_deref()
            .map(|s| s.parse::<ApprovalStatus>())
            .transpose()
            .map_err(|_| invalid())?;
        Ok((status, self.limit, self.offset))
    }
}
async fn project_approvals(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(project): Path<String>,
    query: Result<Query<ApprovalQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<ApprovalRequest>>, ApiError> {
    let project = owned(&s.store, &auth, &project).await?;
    let (status, limit, offset) = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        s.store
            .approvals_for(
                auth.developer_id,
                false,
                Some(project.id),
                status,
                limit,
                offset,
            )
            .await
            .map_err(failure)?,
    ))
}
fn operator(auth: &AuthenticatedDeveloper) -> bool {
    auth.scopes.contains(&Scope::Operator)
}
async fn approvals(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    query: Result<Query<ApprovalQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<ApprovalRequest>>, ApiError> {
    let (status, limit, offset) = query.map_err(|_| invalid())?.0.checked()?;
    Ok(Json(
        s.store
            .approvals_for(
                auth.developer_id,
                operator(&auth),
                None,
                status,
                limit,
                offset,
            )
            .await
            .map_err(failure)?,
    ))
}
async fn approval(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
) -> Result<Json<ApprovalRequest>, ApiError> {
    let id: ApprovalId = id.parse().map_err(|_| invalid())?;
    Ok(Json(
        s.store
            .approval_visible(auth.developer_id, operator(&auth), id)
            .await
            .map_err(failure)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "approval_not_found",
                    "Approval does not exist",
                )
            })?,
    ))
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Decision {
    #[serde(default)]
    reason: Option<String>,
}
async fn decide(
    s: AutomationHttp,
    auth: AuthenticatedDeveloper,
    id: String,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
    decision: ApprovalDecision,
) -> Result<Json<ApprovalRequest>, ApiError> {
    let id: ApprovalId = id.parse().map_err(|_| invalid())?;
    let body: Decision = match body {
        Ok(bytes) if bytes.is_empty() => Decision::default(),
        other => parse(other)?,
    };
    if body
        .reason
        .as_deref()
        .is_some_and(|r| r.len() > 500 || r.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    let decided = s
        .store
        .decide_approval(DecideApproval {
            approval_id: id,
            actor: auth.developer_id,
            operator: operator(&auth),
            decision,
            reason: body.reason,
        })
        .await
        .map_err(failure)?;
    crate::fault::barrier(&s.store.data_dir, "after_approval_decision").await;
    s.wake.notify_one();
    Ok(Json(decided))
}
async fn approve(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<ApprovalRequest>, ApiError> {
    decide(s, auth, id, body, ApprovalDecision::Approve).await
}
async fn reject(
    State(s): State<AutomationHttp>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Json<ApprovalRequest>, ApiError> {
    decide(s, auth, id, body, ApprovalDecision::Reject).await
}

#[allow(dead_code)]
fn _admission_is_send(_: RunAdmission) {}
