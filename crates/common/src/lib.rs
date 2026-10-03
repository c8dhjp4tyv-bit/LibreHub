//! Shared domain types. JSON values only preserve Flatpak's extensible manifest options.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, str::FromStr};
use uuid::Uuid;

pub type Timestamp = DateTime<Utc>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BuildId(Uuid);
impl BuildId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
impl Default for BuildId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for BuildId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    #[default]
    X86_64,
    Aarch64,
}
impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}
impl Architecture {
    pub fn native() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::X86_64
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestFormat {
    #[default]
    Json,
    Yaml,
}

/// Optional request envelope; raw JSON/YAML manifests are also accepted by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub manifest: String,
    #[serde(default)]
    pub format: ManifestFormat,
    #[serde(default = "Architecture::native")]
    pub architecture: Architecture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatpakManifest {
    #[serde(rename = "app-id", alias = "id")]
    pub app_id: String,
    pub runtime: String,
    #[serde(rename = "runtime-version")]
    pub runtime_version: String,
    pub sdk: String,
    pub command: String,
    pub modules: Vec<Module>,
    #[serde(flatten)]
    pub options: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Source>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<Module>,
    #[serde(flatten)]
    pub options: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    #[serde(rename = "type")]
    pub kind: SourceKind,
    #[serde(flatten)]
    pub options: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Archive,
    Git,
    File,
    Script,
    Inline,
    Patch,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    Queued,
    Validating,
    Building,
    Succeeded,
    Failed,
    Cancelled,
}
impl BuildStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Queued,
                Self::Validating | Self::Failed | Self::Cancelled
            ) | (
                Self::Validating,
                Self::Building | Self::Failed | Self::Cancelled
            ) | (
                Self::Building,
                Self::Succeeded | Self::Failed | Self::Cancelled
            )
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub code: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildError {
    pub code: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Relative to the configured data directory; never supplied by a manifest.
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildResult {
    pub exit_code: Option<i32>,
    pub artifacts: Vec<Artifact>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMetadata {
    pub app_id: String,
    pub runtime: String,
    pub runtime_version: String,
    pub sdk: String,
}
impl From<&FlatpakManifest> for ManifestMetadata {
    fn from(m: &FlatpakManifest) -> Self {
        Self {
            app_id: m.app_id.clone(),
            runtime: m.runtime.clone(),
            runtime_version: m.runtime_version.clone(),
            sdk: m.sdk.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub id: BuildId,
    pub status: BuildStatus,
    pub architecture: Architecture,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub manifest: ManifestMetadata,
    pub result: Option<BuildResult>,
    pub error: Option<BuildError>,
    pub cancellation_requested: bool,
    pub logs_truncated: bool,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    System,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildLogEntry {
    pub sequence: u64,
    pub timestamp: Timestamp,
    pub stream: LogStream,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transitions_are_one_way() {
        use BuildStatus::*;
        assert!(Queued.can_transition_to(Validating));
        assert!(Validating.can_transition_to(Building));
        for next in [Succeeded, Failed, Cancelled] {
            assert!(Building.can_transition_to(next));
        }
        for terminal in [Succeeded, Failed, Cancelled] {
            for next in [Queued, Validating, Building, Succeeded, Failed, Cancelled] {
                assert!(!terminal.can_transition_to(next));
            }
        }
        assert!(!Queued.can_transition_to(Succeeded));
        assert!(!Building.can_transition_to(Queued));
    }
    #[test]
    fn ids_cannot_contain_paths() {
        assert!("../../etc/passwd".parse::<BuildId>().is_err());
    }
}
