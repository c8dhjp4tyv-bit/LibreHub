use crate::{auth::AuthenticatedDeveloper, http::ApiError, store::Store};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::{delete, get, post},
};
use librehub_catalog::CatalogStorage;
use librehub_common::{
    AppSecurityDetails, DomainVerification, ModerationAction, ModerationEvent, ModerationReason,
    ModerationState, PermissionDiff, PermissionSnapshot, PublishId, PublisherVerificationStatus,
    ReleaseSecurityDetails, ReportId, ReportReason, ReportRecord, ReportStatus, Scope, Timestamp,
};
use librehub_security::{DnsResolver, default_resolver};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

#[derive(Clone)]
pub struct SecurityHttp {
    pub store: Store,
    pub data_dir: PathBuf,
    pub dns_resolver: Arc<dyn DnsResolver>,
    pub api_public_url: String,
    pub trusted_proxies: Vec<IpAddr>,
}

impl SecurityHttp {
    pub fn new(store: Store, data_dir: PathBuf, api_public_url: String) -> Self {
        Self {
            store,
            data_dir,
            dns_resolver: default_resolver(),
            api_public_url,
            trusted_proxies: Vec::new(),
        }
    }
}

pub fn public_router(state: SecurityHttp) -> Router {
    Router::new()
        .route("/api/v1/catalog/apps/{id}/security", get(app_security))
        .route("/api/v1/catalog/apps/{id}/trust", get(app_security))
        .route(
            "/api/v1/catalog/apps/{id}/releases/{release_id}/security",
            get(release_security),
        )
        .route(
            "/api/v1/catalog/apps/{id}/releases/{release_id}/sbom",
            get(release_sbom),
        )
        .route(
            "/api/v1/catalog/apps/{id}/releases/{release_id}/sbom/download",
            get(download_sbom),
        )
        .route(
            "/api/v1/catalog/apps/{id}/permissions",
            get(app_permissions),
        )
        .route("/api/v1/catalog/apps/{id}/reports", post(submit_report))
        .with_state(Arc::new(state))
}

pub fn developer_router(state: SecurityHttp) -> Router {
    Router::new()
        .route(
            "/api/v1/verification/domains",
            post(request_domain_verification).get(list_domain_verifications),
        )
        .route(
            "/api/v1/verification/domains/{id}/check",
            post(check_domain_verification_handler),
        )
        .route(
            "/api/v1/verification/domains/{id}",
            delete(revoke_domain_verification),
        )
        .with_state(Arc::new(state))
}

pub fn admin_router(state: SecurityHttp) -> Router {
    Router::new()
        .route(
            "/api/v1/admin/catalog/apps/{id}/moderation",
            post(apply_moderation_handler).get(list_moderation_events_handler),
        )
        .route("/api/v1/admin/reports", get(list_reports_handler))
        .route(
            "/api/v1/admin/reports/{id}/resolve",
            post(resolve_report_handler),
        )
        .with_state(Arc::new(state))
}

// ----------------------------------------------------------------------------
// Public Catalog Handlers
// ----------------------------------------------------------------------------

async fn app_security(
    State(state): State<Arc<SecurityHttp>>,
    Path(app_id): Path<String>,
) -> Result<Json<AppSecurityDetails>, ApiError> {
    // 1. Check if application is removed
    let mod_info = state
        .store
        .get_moderation_state(&app_id)
        .await
        .map_err(ApiError::internal)?;

    if let Some((ModerationState::Removed, _, _)) = mod_info {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "app_removed",
            "This application has been removed from the public catalog",
        ));
    }

    let (moderation_state, moderation_note) = match mod_info {
        Some((st, _, note)) => (st, note),
        None => (ModerationState::Normal, None),
    };

    // 2. Fetch app from catalog to get publisher and latest release
    let catalog_app = state
        .store
        .app(app_id.clone(), librehub_common::RepositoryChannel::Stable)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "app_not_found",
                "Application not found in catalog",
            )
        })?;

    let publisher_id = catalog_app.card.publisher.id.as_deref();
    let mut publisher_verification = PublisherVerificationStatus::Pending;
    let mut verified_domain = None;

    if let Some(pub_id) = publisher_id
        && let Ok(Some(v)) = state.store.get_publisher_verification_info(pub_id).await
    {
        publisher_verification = v.status;
        verified_domain = Some(v.domain);
    }

    let latest_pub = catalog_app
        .current_releases
        .iter()
        .find(|r| r.channel == librehub_common::RepositoryChannel::Stable)
        .or_else(|| catalog_app.current_releases.first());

    let latest_pub_id = latest_pub.map(|r| r.publication_id.as_str());

    let trust_summary = state
        .store
        .compute_trust_summary(&app_id, "stable", publisher_id, latest_pub_id)
        .await
        .map_err(ApiError::internal)?;

    let latest_release = if let Some(pub_id_str) = latest_pub_id
        && let Ok(pub_id) = pub_id_str.parse::<PublishId>()
    {
        state
            .store
            .get_release_security_details(&pub_id)
            .await
            .map_err(ApiError::internal)?
    } else {
        None
    };

    Ok(Json(AppSecurityDetails {
        app_id,
        trust_summary,
        publisher_verification,
        verified_domain,
        moderation_state,
        public_moderation_note: moderation_note,
        latest_release,
    }))
}

async fn release_security(
    State(state): State<Arc<SecurityHttp>>,
    Path((_app_id, release_id)): Path<(String, String)>,
) -> Result<Json<ReleaseSecurityDetails>, ApiError> {
    let pub_id = release_id.parse::<PublishId>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_release_id",
            "Release ID must be a valid UUID",
        )
    })?;

    let details = state
        .store
        .get_release_security_details(&pub_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "release_security_not_found",
                "Security details for this release were not found",
            )
        })?;

    Ok(Json(details))
}

#[derive(Serialize)]
struct SbomSummaryResponse {
    pub publication_id: PublishId,
    pub format: String,
    pub component_count: u32,
    pub sha256: String,
    pub download_url: String,
    pub generated_at: Timestamp,
}

async fn release_sbom(
    State(state): State<Arc<SecurityHttp>>,
    Path((_app_id, release_id)): Path<(String, String)>,
) -> Result<Json<SbomSummaryResponse>, ApiError> {
    let pub_id = release_id.parse::<PublishId>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_release_id",
            "Release ID must be a valid UUID",
        )
    })?;

    let details = state
        .store
        .get_release_security_details(&pub_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "release_not_found",
                "Release was not found",
            )
        })?;

    Ok(Json(SbomSummaryResponse {
        publication_id: details.publication_id,
        format: details.sbom_format,
        component_count: details.sbom_component_count,
        sha256: details.sbom_sha256,
        download_url: details.sbom_download_url,
        generated_at: details.timestamps.sbom_generated_at,
    }))
}

async fn download_sbom(
    State(state): State<Arc<SecurityHttp>>,
    Path((app_id, release_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let pub_id = release_id.parse::<PublishId>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_release_id",
            "Release ID must be a valid UUID",
        )
    })?;

    let details = state
        .store
        .get_release_security_details(&pub_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "release_not_found",
                "Release was not found",
            )
        })?;

    if details.app_id != app_id {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "release_not_found",
            "Release was not found",
        ));
    }

    let _rel_path = details.sbom_path.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "sbom_not_ready",
            "SBOM is not yet ready or available for this release",
        )
    })?;

    let bytes = state
        .store
        .read_sbom_file(&state.data_dir, &pub_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "sbom_file_missing",
                "SBOM artifact file is missing",
            )
        })?;

    let filename = format!("{app_id}-{release_id}.spdx.json");

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/spdx+json")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(
            header::CACHE_CONTROL,
            "public, max-age=86400, stale-while-revalidate=3600",
        )
        .body(axum::body::Body::from(bytes))
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_error",
                "Failed to build response",
            )
        })?;

    Ok(response)
}

#[derive(Serialize)]
struct PermissionHistoryResponse {
    pub app_id: String,
    pub current_permissions: Option<PermissionSnapshot>,
    pub history: Vec<PermissionDiff>,
}

async fn app_permissions(
    State(state): State<Arc<SecurityHttp>>,
    Path(app_id): Path<String>,
) -> Result<Json<PermissionHistoryResponse>, ApiError> {
    let current_permissions = state
        .store
        .get_current_permissions(&app_id, "stable")
        .await
        .map_err(ApiError::internal)?;

    let history = state
        .store
        .get_permission_history(&app_id, "stable", 20)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(PermissionHistoryResponse {
        app_id,
        current_permissions,
        history,
    }))
}

#[derive(Deserialize)]
struct SubmitReportRequest {
    pub reason: ReportReason,
    pub message: Option<String>,
}

async fn submit_report(
    State(state): State<Arc<SecurityHttp>>,
    Path(app_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<SubmitReportRequest>,
) -> Result<(StatusCode, Json<ReportRecord>), ApiError> {
    // Check if app exists
    let app_opt = state
        .store
        .app(app_id.clone(), librehub_common::RepositoryChannel::Stable)
        .await
        .map_err(ApiError::internal)?;
    if app_opt.is_none() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "app_not_found",
            "Application does not exist",
        ));
    }

    let caller_ip = reporter_ip(peer.ip(), &headers, &state.trusted_proxies).to_string();

    let record = state
        .store
        .submit_report(&app_id, payload.reason, payload.message, Some(&caller_ip))
        .await
        .map_err(ApiError::internal)?;

    Ok((StatusCode::CREATED, Json(record)))
}

// ----------------------------------------------------------------------------
// Authenticated Developer Domain Verification Handlers
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct RequestDomainVerificationBody {
    pub domain: String,
}

async fn request_domain_verification(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Json(payload): Json<RequestDomainVerificationBody>,
) -> Result<(StatusCode, Json<DomainVerification>), ApiError> {
    auth.require(Scope::ProjectsWrite)?;

    let verification = state
        .store
        .request_domain_verification(
            &auth.developer_id,
            &payload.domain,
            librehub_common::VerificationMethod::DnsTxt,
        )
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "domain_verification_error",
                e.to_string(),
            )
        })?;

    Ok((StatusCode::CREATED, Json(verification)))
}

async fn list_domain_verifications(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
) -> Result<Json<Vec<DomainVerification>>, ApiError> {
    auth.require(Scope::ProjectsRead)?;

    let list = state
        .store
        .list_domain_verifications(&auth.developer_id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(list))
}

async fn check_domain_verification_handler(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
) -> Result<Json<DomainVerification>, ApiError> {
    auth.require(Scope::ProjectsWrite)?;

    let v_id = id.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_verification_id",
            "Verification ID must be a valid UUID",
        )
    })?;

    let verified = state
        .store
        .check_domain_verification(&auth.developer_id, &v_id, state.dns_resolver.as_ref())
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "verification_check_failed",
                e.to_string(),
            )
        })?;

    Ok(Json(verified))
}

async fn revoke_domain_verification(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    auth.require(Scope::ProjectsWrite)?;

    let v_id = id.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_verification_id",
            "Verification ID must be a valid UUID",
        )
    })?;

    state
        .store
        .revoke_domain_verification(&auth.developer_id, &v_id)
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "verification_not_found",
                e.to_string(),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------------------------------------------------------
// Operator Moderation Handlers
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
struct ApplyModerationBody {
    pub action: ModerationAction,
    pub reason: ModerationReason,
    pub public_note: Option<String>,
    pub internal_note: Option<String>,
}

async fn apply_moderation_handler(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(app_id): Path<String>,
    Json(payload): Json<ApplyModerationBody>,
) -> Result<Json<ModerationEvent>, ApiError> {
    auth.require(Scope::Operator)?;

    let operator_name = format!("developer:{}", auth.developer_id);
    let event = state
        .store
        .apply_moderation(
            &app_id,
            payload.action,
            payload.reason,
            payload.public_note,
            payload.internal_note,
            &operator_name,
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(event))
}

async fn list_moderation_events_handler(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(app_id): Path<String>,
) -> Result<Json<Vec<ModerationEvent>>, ApiError> {
    auth.require(Scope::Operator)?;

    let events = state
        .store
        .get_moderation_history(&app_id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(events))
}

#[derive(Deserialize, Default)]
struct ListReportsQuery {
    pub status: Option<ReportStatus>,
    pub app_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

async fn list_reports_handler(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Query(query): Query<ListReportsQuery>,
) -> Result<Json<Vec<ReportRecord>>, ApiError> {
    auth.require(Scope::Operator)?;

    let reports = state
        .store
        .list_reports(
            query.status,
            query.app_id,
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(reports))
}

#[derive(Deserialize)]
struct ResolveReportBody {
    pub status: ReportStatus,
    pub resolution_note: Option<String>,
}

async fn resolve_report_handler(
    State(state): State<Arc<SecurityHttp>>,
    Extension(auth): Extension<AuthenticatedDeveloper>,
    Path(id): Path<String>,
    Json(payload): Json<ResolveReportBody>,
) -> Result<Json<ReportRecord>, ApiError> {
    auth.require(Scope::Operator)?;

    let rep_id = id.parse::<ReportId>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_report_id",
            "Report ID must be a valid UUID",
        )
    })?;

    let operator_name = format!("developer:{}", auth.developer_id);
    let resolved = state
        .store
        .resolve_report(
            &rep_id,
            payload.status,
            payload.resolution_note,
            &operator_name,
        )
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "report_resolution_error",
                e.to_string(),
            )
        })?;

    Ok(Json(resolved))
}

// Walk from the trusted edge toward the client; never trust a leftmost value
// supplied by an untrusted intermediary or the client itself.
fn reporter_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    let Some(value) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) else {
        return peer;
    };
    let Ok(chain) = value
        .split(',')
        .map(|ip| ip.trim().parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()
    else {
        return peer;
    };
    let mut caller = peer;
    for ip in chain.into_iter().rev() {
        if !trusted_proxies.contains(&caller) {
            break;
        }
        caller = ip;
    }
    caller
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_ip_only_trusts_configured_proxy_chain() {
        let peer = "192.0.2.1".parse().unwrap();
        let client: IpAddr = "198.51.100.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.1, 198.51.100.1".parse().unwrap(),
        );
        assert_eq!(reporter_ip(peer, &headers, &[]), peer);
        assert_eq!(reporter_ip(peer, &headers, &[peer]), client);
        headers.insert("x-forwarded-for", "invalid".parse().unwrap());
        assert_eq!(reporter_ip(peer, &headers, &[peer]), peer);
        assert_eq!(reporter_ip(peer, &HeaderMap::new(), &[peer]), peer);
    }
}
