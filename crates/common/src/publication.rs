use crate::{Architecture, BuildId, Timestamp};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublishId(Uuid);
impl PublishId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
impl Default for PublishId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for PublishId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for PublishId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// Channels select separate repositories; Flatpak branches remain manifest-defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RepositoryChannel {
    Stable,
    Beta,
}
impl fmt::Display for RepositoryChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        })
    }
}
impl FromStr for RepositoryChannel {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            _ => Err("Unsupported repository channel"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishStatus {
    Queued,
    Preparing,
    Uploading,
    Committing,
    Publishing,
    Succeeded,
    Failed,
    Cancelled,
}
impl PublishStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
    pub fn can_cancel(self) -> bool {
        self == Self::Queued
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        use PublishStatus::*;
        matches!(
            (self, next),
            (Queued, Preparing | Cancelled | Failed)
                | (Preparing, Uploading | Failed)
                | (Uploading, Committing | Failed)
                | (Committing, Publishing | Failed)
                | (Publishing, Succeeded | Failed)
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub channel: RepositoryChannel,
}

/// Construct only through `new`; deserialization also enforces path-safe components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepositoryRef(String);
impl RepositoryRef {
    pub fn new(
        app_id: &str,
        architecture: Architecture,
        branch: &str,
    ) -> Result<Self, &'static str> {
        let parts: Vec<_> = app_id.split('.').collect();
        if parts.len() < 3
            || app_id.len() > 255
            || !parts
                .iter()
                .all(|p| component(p) && p.as_bytes()[0].is_ascii_alphabetic())
            || !component(branch)
        {
            return Err("Invalid application ref");
        }
        Ok(Self(format!("app/{app_id}/{architecture}/{branch}")))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl TryFrom<String> for RepositoryRef {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let p: Vec<_> = s.split('/').collect();
        if p.len() != 4 || p[0] != "app" {
            return Err("Invalid application ref");
        }
        let arch = match p[2] {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            _ => return Err("Unsupported architecture"),
        };
        Self::new(p[1], arch, p[3])
    }
}
impl From<RepositoryRef> for String {
    fn from(r: RepositoryRef) -> Self {
        r.0
    }
}
impl fmt::Display for RepositoryRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
pub fn valid_checksum(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningMetadata {
    pub fingerprint: String,
    pub public_key_url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedRef {
    pub ref_name: RepositoryRef,
    pub commit: String,
    pub source_commit: String,
    pub repository_url: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    pub published_ref: PublishedRef,
    pub signing: SigningMetadata,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRecord {
    pub id: PublishId,
    pub build_id: BuildId,
    pub channel: RepositoryChannel,
    pub status: PublishStatus,
    pub architecture: Architecture,
    pub app_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub flat_manager_build_id: Option<i32>,
    #[serde(default)]
    pub create_requested: bool,
    pub source_commit: Option<String>,
    pub result: Option<PublishResult>,
    pub error: Option<PublishFailure>,
    /// Suspended operations are reconciled on restart, never blindly replayed.
    pub needs_attention: bool,
    pub attempts: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_states_and_cancellation() {
        use PublishStatus::*;
        for (from, to) in [
            (Queued, Preparing),
            (Preparing, Uploading),
            (Uploading, Committing),
            (Committing, Publishing),
            (Publishing, Succeeded),
        ] {
            assert!(from.can_transition_to(to));
        }
        for state in [Succeeded, Failed, Cancelled] {
            assert!(!state.can_transition_to(Queued));
            assert!(!state.can_cancel());
        }
        assert!(Queued.can_cancel());
        assert!(!Uploading.can_cancel());
        assert!(!Queued.can_transition_to(Succeeded));
    }
    #[test]
    fn channels_and_refs_reject_injection() {
        assert_eq!(
            "stable".parse::<RepositoryChannel>().unwrap(),
            RepositoryChannel::Stable
        );
        assert_eq!(
            "beta".parse::<RepositoryChannel>().unwrap(),
            RepositoryChannel::Beta
        );
        for bad in ["../stable", "nightly", "stable\n", ""] {
            assert!(bad.parse::<RepositoryChannel>().is_err());
        }
        for bad in [
            "app/org.example.Hello/ppc64/master",
            "app/org.example.Hello/x86_64/../../escape",
            "runtime/org.example.Hello/x86_64/master",
        ] {
            assert!(RepositoryRef::try_from(bad.to_owned()).is_err());
        }
        assert!(RepositoryRef::new("org.example.Hello", Architecture::native(), "master").is_ok());
        assert!(RepositoryRef::new("org.example.Hello", Architecture::native(), "1.2").is_ok());
    }
}
