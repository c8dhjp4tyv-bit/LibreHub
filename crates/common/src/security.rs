//! M5 Trust, Security & Moderation domain models.
//! Explicit strongly typed boundaries prevent loose JSON blobs and accidental state bypass.
use crate::{DeveloperId, PublishId, Timestamp};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};
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
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

identity!(VerificationId);
identity!(ReportId);

/// User-facing public trust state for catalog displays.
///
/// NOTE: `VerifiedPublisher` confirms publisher domain/source ownership.
/// It DOES NOT mean or imply the software is 100% bug-free, malware-free, or audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Unverified,
    VerifiedPublisher,
    Community,
    Restricted,
    Removed,
}

impl fmt::Display for TrustState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unverified => "unverified",
            Self::VerifiedPublisher => "verified_publisher",
            Self::Community => "community",
            Self::Restricted => "restricted",
            Self::Removed => "removed",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherVerificationStatus {
    Pending,
    Verified,
    Revoked,
    Expired,
}

impl fmt::Display for PublisherVerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        })
    }
}

impl FromStr for PublisherVerificationStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err("Invalid publisher verification status"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    DnsTxt,
}

impl fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DnsTxt => "dns_txt",
        })
    }
}

impl FromStr for VerificationMethod {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dns_txt" => Ok(Self::DnsTxt),
            _ => Err("Invalid verification method"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerification {
    pub id: VerificationId,
    pub developer_id: DeveloperId,
    pub domain: String,
    pub method: VerificationMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
    pub challenge_expires_at: Timestamp,
    pub status: PublisherVerificationStatus,
    pub verified_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModerationState {
    #[default]
    Normal,
    UnderReview,
    Restricted,
    Removed,
}

impl fmt::Display for ModerationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::UnderReview => "under_review",
            Self::Restricted => "restricted",
            Self::Removed => "removed",
        })
    }
}

impl FromStr for ModerationState {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(Self::Normal),
            "under_review" => Ok(Self::UnderReview),
            "restricted" => Ok(Self::Restricted),
            "removed" => Ok(Self::Removed),
            _ => Err("Invalid moderation state"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    MarkUnderReview,
    Restrict,
    Remove,
    Restore,
}

impl fmt::Display for ModerationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MarkUnderReview => "mark_under_review",
            Self::Restrict => "restrict",
            Self::Remove => "remove",
            Self::Restore => "restore",
        })
    }
}

impl FromStr for ModerationAction {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mark_under_review" => Ok(Self::MarkUnderReview),
            "restrict" => Ok(Self::Restrict),
            "remove" => Ok(Self::Remove),
            "restore" => Ok(Self::Restore),
            _ => Err("Invalid moderation action"),
        }
    }
}

impl ModerationAction {
    pub fn target_state(self) -> ModerationState {
        match self {
            Self::MarkUnderReview => ModerationState::UnderReview,
            Self::Restrict => ModerationState::Restricted,
            Self::Remove => ModerationState::Removed,
            Self::Restore => ModerationState::Normal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationReason {
    MalwareReport,
    Copyright,
    Impersonation,
    SecurityRisk,
    PolicyViolation,
    DeveloperRequest,
    Other,
}

impl fmt::Display for ModerationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalwareReport => "malware_report",
            Self::Copyright => "copyright",
            Self::Impersonation => "impersonation",
            Self::SecurityRisk => "security_risk",
            Self::PolicyViolation => "policy_violation",
            Self::DeveloperRequest => "developer_request",
            Self::Other => "other",
        })
    }
}

impl FromStr for ModerationReason {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "malware_report" => Ok(Self::MalwareReport),
            "copyright" => Ok(Self::Copyright),
            "impersonation" => Ok(Self::Impersonation),
            "security_risk" => Ok(Self::SecurityRisk),
            "policy_violation" => Ok(Self::PolicyViolation),
            "developer_request" => Ok(Self::DeveloperRequest),
            "other" => Ok(Self::Other),
            _ => Err("Invalid moderation reason"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationEvent {
    pub id: i64,
    pub app_id: String,
    pub action: ModerationAction,
    pub from_state: ModerationState,
    pub to_state: ModerationState,
    pub reason: ModerationReason,
    pub public_note: Option<String>,
    pub internal_note: Option<String>,
    pub operator: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSecurityState {
    Pending,
    Analyzing,
    Ready,
    Failed,
    Unavailable,
}

impl fmt::Display for ReleaseSecurityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Analyzing => "analyzing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Unavailable => "unavailable",
        })
    }
}

impl FromStr for ReleaseSecurityState {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "analyzing" => Ok(Self::Analyzing),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err("Invalid release security state"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSnapshot {
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sockets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dbus: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PermissionSeverity {
    #[default]
    None,
    Low,
    Moderate,
    Significant,
}

impl fmt::Display for PermissionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::Significant => "significant",
        })
    }
}

impl FromStr for PermissionSeverity {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "low" => Ok(Self::Low),
            "moderate" => Ok(Self::Moderate),
            "significant" => Ok(Self::Significant),
            _ => Err("Invalid permission severity"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionDiff {
    pub from_publication_id: Option<String>,
    pub to_publication_id: String,
    pub severity: PermissionSeverity,
    pub added: PermissionSnapshot,
    pub removed: PermissionSnapshot,
    pub changed_network: Option<NetworkChange>,
    pub summary_notes: Vec<String>,
    pub generated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkChange {
    pub from: bool,
    pub to: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomPackage {
    pub name: String,
    pub version: Option<String>,
    pub package_type: String,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub source: Option<String>,
    pub hashes: BTreeMap<String, String>,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomCreationInfo {
    pub created: String,
    pub creators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomRelationship {
    #[serde(rename = "spdxElementId")]
    pub spdx_element_id: String,
    #[serde(rename = "relatedSpdxElement")]
    pub related_spdx_element: String,
    #[serde(rename = "relationshipType")]
    pub relationship_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    #[serde(rename = "spdxVersion")]
    pub spdx_version: String,
    #[serde(rename = "dataLicense")]
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    #[serde(rename = "documentNamespace")]
    pub document_namespace: String,
    #[serde(rename = "creationInfo")]
    pub creation_info: SbomCreationInfo,
    pub packages: Vec<SbomPackage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<SbomRelationship>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilitySeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for VulnerabilitySeverity {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Self::Unknown),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err("Invalid vulnerability severity"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnerabilityFinding {
    pub vulnerability_id: String,
    pub component_name: String,
    pub component_version: String,
    pub severity: VulnerabilitySeverity,
    pub summary: String,
    pub reference_url: Option<String>,
    pub source_provider: String,
    pub checked_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilitiesStatus {
    Clean,
    Vulnerable,
    Unavailable,
}

impl fmt::Display for VulnerabilitiesStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clean => "clean",
            Self::Vulnerable => "vulnerable",
            Self::Unavailable => "unavailable",
        })
    }
}

impl FromStr for VulnerabilitiesStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "clean" => Ok(Self::Clean),
            "vulnerable" => Ok(Self::Vulnerable),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err("Invalid vulnerabilities status"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportReason {
    Malware,
    SecurityVulnerability,
    PrivacyViolation,
    CopyrightInfringement,
    Impersonation,
    PolicyViolation,
    BrokenBuild,
    Other,
}

impl fmt::Display for ReportReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malware => "malware",
            Self::SecurityVulnerability => "security_vulnerability",
            Self::PrivacyViolation => "privacy_violation",
            Self::CopyrightInfringement => "copyright_infringement",
            Self::Impersonation => "impersonation",
            Self::PolicyViolation => "policy_violation",
            Self::BrokenBuild => "broken_build",
            Self::Other => "other",
        })
    }
}

impl FromStr for ReportReason {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "malware" => Ok(Self::Malware),
            "security_vulnerability" => Ok(Self::SecurityVulnerability),
            "privacy_violation" => Ok(Self::PrivacyViolation),
            "copyright_infringement" => Ok(Self::CopyrightInfringement),
            "impersonation" => Ok(Self::Impersonation),
            "policy_violation" => Ok(Self::PolicyViolation),
            "broken_build" => Ok(Self::BrokenBuild),
            "other" => Ok(Self::Other),
            _ => Err("Invalid report reason"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    #[default]
    Open,
    Resolved,
    Dismissed,
}

impl fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
            Self::Dismissed => "dismissed",
        })
    }
}

impl FromStr for ReportStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "resolved" => Ok(Self::Resolved),
            "dismissed" => Ok(Self::Dismissed),
            _ => Err("Invalid report status"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRecord {
    pub id: ReportId,
    pub app_id: String,
    pub reason: ReportReason,
    pub message: Option<String>,
    pub status: ReportStatus,
    pub resolution_note: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<Timestamp>,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnerabilityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

impl VulnerabilityCounts {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.unknown
    }

    pub fn from_findings(findings: &[VulnerabilityFinding]) -> Self {
        let mut counts = Self::default();
        for f in findings {
            match f.severity {
                VulnerabilitySeverity::Critical => counts.critical += 1,
                VulnerabilitySeverity::High => counts.high += 1,
                VulnerabilitySeverity::Medium => counts.medium += 1,
                VulnerabilitySeverity::Low => counts.low += 1,
                VulnerabilitySeverity::Unknown => counts.unknown += 1,
            }
        }
        counts
    }
}

/// Compact trust summary DTO for public catalog app cards and detail pages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustSummary {
    pub trust_state: TrustState,
    pub publisher_verification: String,
    pub verified_domain: Option<String>,
    pub source_available: bool,
    pub signed_repository: bool,
    pub security_analysis: String,
    pub known_vulnerabilities: VulnerabilityCounts,
    pub latest_permission_change: PermissionSeverity,
    pub moderation_state: ModerationState,
    #[serde(default)]
    pub moderation_notice: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSecurityDetails {
    pub app_id: String,
    pub trust_summary: TrustSummary,
    pub publisher_verification: PublisherVerificationStatus,
    pub verified_domain: Option<String>,
    pub moderation_state: ModerationState,
    pub public_moderation_note: Option<String>,
    pub latest_release: Option<ReleaseSecurityDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseSecurityDetails {
    pub publication_id: PublishId,
    pub app_id: String,
    pub channel: String,
    pub status: ReleaseSecurityState,
    pub sbom_format: String,
    pub sbom_component_count: u32,
    pub sbom_sha256: String,
    pub sbom_download_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_path: Option<String>,
    pub vulnerabilities_status: VulnerabilitiesStatus,
    pub vulnerabilities_checked_at: Option<Timestamp>,
    pub vulnerability_counts: VulnerabilityCounts,
    pub findings: Vec<VulnerabilityFinding>,
    pub permissions_extracted_at: Timestamp,
    pub permission_severity: PermissionSeverity,
    pub permission_diff: Option<PermissionDiff>,
    pub timestamps: SecurityTimestamps,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTimestamps {
    pub sbom_generated_at: Timestamp,
    pub vulnerabilities_checked_at: Option<Timestamp>,
    pub permissions_extracted_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderation_action_transitions() {
        assert_eq!(
            ModerationAction::MarkUnderReview.target_state(),
            ModerationState::UnderReview
        );
        assert_eq!(
            ModerationAction::Restrict.target_state(),
            ModerationState::Restricted
        );
        assert_eq!(
            ModerationAction::Remove.target_state(),
            ModerationState::Removed
        );
        assert_eq!(
            ModerationAction::Restore.target_state(),
            ModerationState::Normal
        );
    }

    #[test]
    fn severity_ordering() {
        assert!(PermissionSeverity::Significant > PermissionSeverity::Moderate);
        assert!(PermissionSeverity::Moderate > PermissionSeverity::Low);
        assert!(PermissionSeverity::Low > PermissionSeverity::None);

        assert!(VulnerabilitySeverity::Critical > VulnerabilitySeverity::High);
        assert!(VulnerabilitySeverity::High > VulnerabilitySeverity::Medium);
        assert!(VulnerabilitySeverity::Medium > VulnerabilitySeverity::Low);
        assert!(VulnerabilitySeverity::Low > VulnerabilitySeverity::Unknown);
    }

    #[test]
    fn parsing_from_strings() {
        assert_eq!(
            "normal".parse::<ModerationState>().unwrap(),
            ModerationState::Normal
        );
        assert_eq!(
            "under_review".parse::<ModerationState>().unwrap(),
            ModerationState::UnderReview
        );
        assert_eq!(
            "dns_txt".parse::<VerificationMethod>().unwrap(),
            VerificationMethod::DnsTxt
        );
        assert_eq!(
            "significant".parse::<PermissionSeverity>().unwrap(),
            PermissionSeverity::Significant
        );
        assert_eq!(
            "critical".parse::<VulnerabilitySeverity>().unwrap(),
            VulnerabilitySeverity::Critical
        );
        assert_eq!(
            "malware".parse::<ReportReason>().unwrap(),
            ReportReason::Malware
        );
        assert_eq!(
            "resolved".parse::<ReportStatus>().unwrap(),
            ReportStatus::Resolved
        );
    }
}
