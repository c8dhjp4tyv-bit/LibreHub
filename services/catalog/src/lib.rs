//! Public catalog domain and bounded extraction. Never expose internal platform records.
pub mod extract;
pub mod metadata;
use librehub_common::{Architecture, RepositoryChannel, Timestamp};
use serde::{Deserialize, Serialize};

pub const CATEGORIES: &[&str] = &[
    "Development",
    "Games",
    "Graphics",
    "AudioVideo",
    "Education",
    "Network",
    "Office",
    "Science",
    "System",
    "Utility",
];
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogPermissions {
    pub network: bool,
    pub filesystem: Vec<String>,
    pub devices: Vec<String>,
    pub sockets: Vec<String>,
    pub dbus: Vec<String>,
    pub shared: Vec<String>,
    pub other: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogScreenshot {
    pub url: String,
    pub caption: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogMetadata {
    pub name: String,
    pub summary: String,
    pub description: String,
    pub developer_name: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub categories: Vec<String>,
    pub keywords: Vec<String>,
    pub screenshots: Vec<CatalogScreenshot>,
    pub icon_url: Option<String>,
    pub version: Option<String>,
    pub release_notes: String,
    pub content_rating: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicPublisher {
    pub id: Option<String>,
    pub display_name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRelease {
    pub publication_id: String,
    pub build_id: String,
    pub source_commit: Option<String>,
    pub source_url: Option<String>,
    pub channel: RepositoryChannel,
    pub architecture: Architecture,
    pub flatpak_ref: String,
    pub ostree_checksum: String,
    pub published_at: Timestamp,
    pub version: String,
    pub release_notes: String,
    pub permissions: CatalogPermissions,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCatalogCard {
    pub app_id: String,
    pub slug: String,
    pub name: String,
    pub summary: String,
    pub icon: Option<String>,
    pub publisher: PublicPublisher,
    pub project_id: Option<String>,
    pub source_url: Option<String>,
    pub categories: Vec<String>,
    pub architectures: Vec<Architecture>,
    pub channel: RepositoryChannel,
    pub archived: bool,
    pub updated_at: Timestamp,
    pub published_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogInstall {
    pub remote: String,
    pub remote_descriptor_url: String,
    pub flatpakref_url: String,
    pub command: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCatalogApp {
    #[serde(flatten)]
    pub card: PublicCatalogCard,
    pub description: String,
    pub screenshots: Vec<CatalogScreenshot>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub developer_name: Option<String>,
    pub content_rating: Vec<String>,
    pub current_stable_release: Option<PublicRelease>,
    pub current_beta_release: Option<PublicRelease>,
    /// One current ref per architecture in the selected channel, with its own actual permissions.
    pub current_releases: Vec<PublicRelease>,
    pub install: CatalogInstall,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPage<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogCategory {
    pub id: String,
    pub count: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicPublisherPage {
    pub publisher: PublicPublisher,
    pub apps: CatalogPage<PublicCatalogCard>,
}

/// Explicit storage/search boundary shared by the public API and indexing supervisor.
#[async_trait::async_trait]
pub trait CatalogStorage: Send + Sync {
    async fn apps(&self, query: CatalogQuery) -> anyhow::Result<CatalogPage<PublicCatalogCard>>;
    async fn app(
        &self,
        app_id: String,
        channel: RepositoryChannel,
    ) -> anyhow::Result<Option<PublicCatalogApp>>;
    async fn releases(
        &self,
        app_id: String,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<CatalogPage<PublicRelease>>;
    async fn categories(&self) -> anyhow::Result<Vec<CatalogCategory>>;
}
#[derive(Debug, Clone)]
pub struct CatalogQuery {
    pub q: String,
    pub category: Option<String>,
    pub architecture: Option<Architecture>,
    pub channel: RepositoryChannel,
    pub sort: CatalogSort,
    pub limit: usize,
    pub offset: usize,
    pub publisher: Option<String>,
}
#[derive(Debug, Clone, Copy, Default)]
pub enum CatalogSort {
    #[default]
    RecentlyUpdated,
    Name,
    RecentlyPublished,
}
impl Default for CatalogQuery {
    fn default() -> Self {
        Self {
            q: String::new(),
            category: None,
            architecture: None,
            channel: RepositoryChannel::Stable,
            sort: CatalogSort::RecentlyUpdated,
            limit: 24,
            offset: 0,
            publisher: None,
        }
    }
}
/// Literal tokens only. No FTS operators, column selectors, quotes or SQL are accepted.
pub fn search_expression(query: &str) -> anyhow::Result<String> {
    anyhow::ensure!(query.len() <= 200, "Query exceeds 200 bytes");
    let terms: Vec<_> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    anyhow::ensure!(terms.len() <= 16, "Query exceeds 16 tokens");
    Ok(terms
        .iter()
        .map(|s| format!("\"{s}\"*"))
        .collect::<Vec<_>>()
        .join(" AND "))
}
#[cfg(test)]
mod tests;
