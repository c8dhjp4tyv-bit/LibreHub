//! Unauthenticated read-only DTO routes. Authenticated APIs never inherit this CORS/cache policy.
use crate::{http::ApiError, store::Store};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use librehub_catalog::*;
use librehub_common::{Architecture, RepositoryChannel};
use librehub_publisher::repository::RepositoryConfig;
use serde::Deserialize;
use sha2::{Digest, Sha256};
#[derive(Clone)]
pub struct CatalogHttp {
    pub store: Store,
    pub api_public_url: String,
    pub repository: Option<RepositoryConfig>,
    pub page_size: usize,
}
#[derive(Debug, Clone)]
pub struct CatalogConfig {
    pub api_public_url: String,
    pub page_size: usize,
}
impl CatalogConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let api_public_url = std::env::var("LIBREHUB_API_PUBLIC_URL")
            .unwrap_or_else(|_| "http://localhost:8080".into());
        // Operator origins may be local HTTP in development. Never read Host headers.
        let url = url::Url::parse(&api_public_url)?;
        anyhow::ensure!(
            ["http", "https"].contains(&url.scheme())
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && !api_public_url.chars().any(char::is_control),
            "Invalid API public URL"
        );
        let page_size = std::env::var("LIBREHUB_CATALOG_PAGE_SIZE")
            .unwrap_or_else(|_| "24".into())
            .parse()?;
        anyhow::ensure!(
            (1..=100).contains(&page_size),
            "Catalog page size must be 1–100"
        );
        Ok(Self {
            api_public_url,
            page_size,
        })
    }
}
pub fn router(state: CatalogHttp) -> Router {
    Router::new()
        .route("/api/v1/catalog/apps", get(list))
        .route("/api/v1/catalog/search", get(list))
        .route("/api/v1/catalog/apps/{id}", get(detail))
        .route("/api/v1/catalog/apps/{id}/releases", get(releases))
        .route("/api/v1/catalog/apps/{id}/flatpakref", get(flatpakref))
        .route("/api/v1/catalog/apps/{id}/icon", get(icon))
        .route("/api/v1/catalog/categories", get(categories))
        .route("/api/v1/catalog/publishers/{id}", get(publisher))
        .with_state(state)
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Options {
    q: Option<String>,
    category: Option<String>,
    architecture: Option<Architecture>,
    channel: Option<RepositoryChannel>,
    sort: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}
impl Options {
    fn query(&self, page_size: usize) -> Result<CatalogQuery, ApiError> {
        let limit = self.limit.unwrap_or(page_size);
        let offset = self.offset.unwrap_or(0);
        let q = self.q.clone().unwrap_or_default();
        if limit == 0
            || limit > 100
            || offset > 100_000
            || search_expression(&q).is_err()
            || self
                .category
                .as_ref()
                .is_some_and(|c| !CATEGORIES.contains(&c.as_str()))
        {
            return Err(invalid());
        }
        let sort = match self.sort.as_deref().unwrap_or("recently_updated") {
            "recently_updated" => CatalogSort::RecentlyUpdated,
            "recently_published" => CatalogSort::RecentlyPublished,
            "name" => CatalogSort::Name,
            _ => return Err(invalid()),
        };
        Ok(CatalogQuery {
            q,
            category: self.category.clone(),
            architecture: self.architecture,
            channel: self.channel.unwrap_or(RepositoryChannel::Stable),
            sort,
            limit,
            offset,
            publisher: None,
        })
    }
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        "invalid_catalog_query",
        "Catalog query exceeds supported bounds or contains invalid filters",
    )
}
fn missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "catalog_app_not_found",
        "Application not found",
    )
}
fn cached(headers: &HeaderMap, bytes: Vec<u8>, content_type: &str) -> Response {
    let etag = format!("\"{:x}\"", Sha256::digest(&bytes));
    let matched = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').any(|s| {
                let s = s.trim().trim_start_matches("W/");
                s == etag || s == "*"
            })
        });
    let mut r = if matched {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        bytes.into_response()
    };
    for (k, v) in [
        (header::ETAG, etag),
        (
            header::CACHE_CONTROL,
            "public, max-age=30, must-revalidate".into(),
        ),
        (header::CONTENT_TYPE, content_type.into()),
        (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".into()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".into()),
        (header::REFERRER_POLICY, "no-referrer".into()),
    ] {
        r.headers_mut().insert(k, v.parse().unwrap());
    }
    r
}
fn json<T: serde::Serialize>(h: &HeaderMap, value: &T) -> Result<Response, ApiError> {
    Ok(cached(
        h,
        serde_json::to_vec(value).map_err(|e| ApiError::internal(e.into()))?,
        "application/json",
    ))
}
async fn list(
    State(s): State<CatalogHttp>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let page = s
        .store
        .apps(o.query(s.page_size)?)
        .await
        .map_err(ApiError::internal)?;
    json(&headers, &page)
}
async fn lookup(
    s: &CatalogHttp,
    id: String,
    channel: RepositoryChannel,
) -> Result<PublicCatalogApp, ApiError> {
    let mut app = s
        .store
        .app(id, channel)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(missing)?;
    let suffix = if channel == RepositoryChannel::Stable {
        "librehub.flatpakrepo"
    } else {
        "librehub-beta.flatpakrepo"
    };
    app.install.remote_descriptor_url =
        format!("{}/{suffix}", s.api_public_url.trim_end_matches('/'));
    app.install.flatpakref_url = format!(
        "{}{}",
        s.api_public_url.trim_end_matches('/'),
        app.install.flatpakref_url
    );
    Ok(app)
}
async fn detail(
    State(s): State<CatalogHttp>,
    Path(id): Path<String>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let q = o.query(s.page_size)?;
    json(&headers, &lookup(&s, id, q.channel).await?)
}
async fn releases(
    State(s): State<CatalogHttp>,
    Path(id): Path<String>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let q = o.query(s.page_size)?;
    lookup(&s, id.clone(), q.channel).await?;
    json(
        &headers,
        &s.store
            .releases(id, q.channel, q.limit, q.offset)
            .await
            .map_err(ApiError::internal)?,
    )
}
async fn categories(
    State(s): State<CatalogHttp>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    json(
        &headers,
        &s.store.categories().await.map_err(ApiError::internal)?,
    )
}
async fn publisher(
    State(s): State<CatalogHttp>,
    Path(id): Path<String>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let q = o.query(s.page_size)?;
    let page = s
        .store
        .catalog_publisher(id, q.limit, q.offset)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "catalog_publisher_not_found",
                "Publisher not found",
            )
        })?;
    json(&headers, &page)
}
async fn icon(
    State(s): State<CatalogHttp>,
    Path(id): Path<String>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let q = o.query(s.page_size)?;
    let png = s
        .store
        .catalog_icon(id, q.channel)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(missing)?;
    Ok(cached(&headers, png, "image/png"))
}
async fn flatpakref(
    State(s): State<CatalogHttp>,
    Path(id): Path<String>,
    headers: HeaderMap,
    options: Result<Query<Options>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(o) = options.map_err(|_| invalid())?;
    let q = o.query(s.page_size)?;
    let app = lookup(&s, id.clone(), q.channel).await?;
    let repository = s.repository.ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "publishing_disabled",
            "Repository is not configured",
        )
    })?;
    let release = app
        .current_releases
        .iter()
        .find(|r| Some(r.architecture) == q.architecture)
        .or_else(|| {
            if q.architecture.is_none() {
                app.current_releases.first()
            } else {
                None
            }
        })
        .ok_or_else(missing)?;
    let branch = release.flatpak_ref.rsplit('/').next().ok_or_else(missing)?;
    let text = format!(
        "[Flatpak Ref]\nVersion=1\nName={id}\nBranch={branch}\nTitle={}\nIsRuntime=false\nUrl={}\nGPGKey={}\nRuntimeRepo={}\nSuggestRemoteName={}\n",
        id,
        repository.url(q.channel),
        STANDARD.encode(&repository.public_key),
        repository.runtime_repo_url,
        app.install.remote
    );
    let mut response = cached(&headers, text.into_bytes(), "application/vnd.flatpak.ref");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{id}.flatpakref\"")
            .parse()
            .map_err(|_| invalid())?,
    );
    Ok(response)
}
