//! Additive developer-platform domain. Secrets never belong in these public records.
use crate::{BuildId, RepositoryChannel, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
macro_rules! identity {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}
identity!(DeveloperId);
identity!(TokenId);
identity!(ProjectId);
identity!(SourceEventId);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeveloperStatus {
    Active,
    Disabled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Developer {
    pub id: DeveloperId,
    pub display_name: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub status: DeveloperStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "projects:read")]
    ProjectsRead,
    #[serde(rename = "projects:write")]
    ProjectsWrite,
    #[serde(rename = "builds:read")]
    BuildsRead,
    #[serde(rename = "builds:write")]
    BuildsWrite,
    #[serde(rename = "publishes:read")]
    PublishesRead,
    #[serde(rename = "publishes:write")]
    PublishesWrite,
    #[serde(rename = "webhooks:write")]
    WebhooksWrite,
    #[serde(rename = "tokens:read")]
    TokensRead,
    #[serde(rename = "tokens:write")]
    TokensWrite,
    #[serde(rename = "audit:read")]
    AuditRead,
    /// Operator-only access to historical unowned M1/M2 jobs. Never issued by public handlers.
    #[serde(rename = "operator")]
    Operator,
}
impl Scope {
    pub fn developer_defaults() -> Vec<Self> {
        vec![
            Self::ProjectsRead,
            Self::ProjectsWrite,
            Self::BuildsRead,
            Self::BuildsWrite,
            Self::PublishesRead,
            Self::PublishesWrite,
            Self::WebhooksWrite,
            Self::TokensRead,
            Self::TokensWrite,
            Self::AuditRead,
        ]
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: TokenId,
    pub developer_id: DeveloperId,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub created_at: Timestamp,
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    Active,
    Disabled,
    Archived,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryProvider {
    Git,
    Github,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSource {
    pub provider: RepositoryProvider,
    pub url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSettings {
    pub default_branch: String,
    pub manifest_path: Option<String>,
    pub auto_build: bool,
    pub build_branches: Vec<String>,
    pub build_tags: bool,
    pub auto_publish_channel: Option<RepositoryChannel>,
    /// Stable publication can be restricted to tags without imposing a global policy.
    pub auto_publish_tags_only: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub owner_developer_id: DeveloperId,
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub repository: ProjectSource,
    #[serde(flatten)]
    pub settings: ProjectSettings,
    pub status: ProjectStatus,
    pub policy_version: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    Manual,
    WebhookPush,
    WebhookTag,
    Api,
    Retry,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRevision {
    pub repository: String,
    pub commit: String,
    pub source_ref: String,
    pub resolved_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub sha256: String,
    pub size_bytes: u64,
    pub file_count: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildProvenance {
    pub project_id: ProjectId,
    pub revision: SourceRevision,
    pub manifest_path: String,
    pub snapshot: SourceSnapshot,
    pub trigger: TriggerType,
    pub trigger_event_id: SourceEventId,
    pub policy_version: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceEventStatus {
    Queued,
    Resolving,
    Fetching,
    Handoff,
    Completed,
    Ignored,
    Failed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEvent {
    pub id: SourceEventId,
    pub project_id: ProjectId,
    pub build_id: BuildId,
    pub trigger: TriggerType,
    pub delivery_id: Option<String>,
    pub source_ref: String,
    pub revision: Option<SourceRevision>,
    pub policy: Project,
    pub status: SourceEventStatus,
    pub attempts: u32,
    pub received_at: Timestamp,
    pub processed_at: Option<Timestamp>,
    pub error: Option<SourceFailure>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub developer_id: DeveloperId,
    pub action: String,
    pub project_id: Option<ProjectId>,
    pub target_id: String,
    pub timestamp: Timestamp,
    pub result: String,
}
