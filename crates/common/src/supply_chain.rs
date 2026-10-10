//! Versioned supply-chain evidence. Worker statements never establish trust themselves.
use crate::{Architecture, BuildId, BuildProvenance, PublishId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_V1: &str = "https://slsa.dev/provenance/v1";
pub const RELEASE_V1: &str = "https://librehub.org/attestations/release/v1";
pub const BUILD_TYPE_V1: &str = "https://librehub.org/build/flatpak/v1";
pub const BUILDER_ID: &str = "https://librehub.org/builders/container/v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationPolicy {
    #[default]
    Compatibility,
    Hardened,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BuildEnvironmentIdentity {
    pub container_runtime: String,
    pub builder_version: String,
    /// OCI image configuration digest: immutable local image ID, not a mutable tag.
    pub image_config_digest: String,
    pub runtime_ref: String,
    pub runtime_commit: String,
    pub sdk_ref: String,
    pub sdk_commit: String,
    pub flatpak_builder_version: String,
    pub architecture: Architecture,
    pub isolation: IsolationPolicy,
    pub network: String,
    pub writable_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_date_epoch: Option<u64>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainPolicy {
    #[default]
    Development,
    AuditOnly,
    Enforce,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Verified,
    Failed,
    LegacyUnattested,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Active,
    Retired,
    Revoked,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestorPublicKey {
    pub key_id: String,
    pub public_key: String,
    pub state: KeyState,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBundle {
    pub version: u32,
    pub keys: Vec<AttestorPublicKey>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<AttestationSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ProvenancePredicate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProvenancePredicate {
    Build(Box<SlsaProvenance>),
    Release(Box<ReleaseProvenance>),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SlsaProvenance {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildDefinition {
    pub build_type: String,
    pub external_parameters: BuildInvocation,
    pub internal_parameters: BuildEnvironmentIdentity,
    pub resolved_dependencies: Vec<SourceMaterial>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildInvocation {
    pub build_id: BuildId,
    pub app_id: String,
    pub architecture: Architecture,
    pub branch: String,
    pub source: BuildProvenance,
    pub declared_dependencies: Vec<DeclaredDependency>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeclaredDependency {
    pub kind: String,
    pub uri: Option<String>,
    pub pin: Option<String>,
    pub immutable: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMaterial {
    pub uri: String,
    pub digest: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunDetails {
    pub builder: BuilderIdentity,
    pub metadata: BuildMetadata,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderIdentity {
    pub id: String,
    pub version: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildMetadata {
    pub invocation_id: String,
    pub started_on: Timestamp,
    pub finished_on: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseProvenance {
    pub publication_id: PublishId,
    pub build_id: BuildId,
    pub app_id: String,
    pub architecture: Architecture,
    pub channel: String,
    pub repository: String,
    pub flatpak_ref: String,
    pub build_statement_sha256: String,
    pub build_artifact_sha256: String,
    pub source_ostree_commit: String,
    pub sbom_sha256: String,
    pub published_on: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<AttestationSignature>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSignature {
    pub keyid: String,
    pub sig: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub code: String,
    pub key_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub code: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub mode: SupplyChainPolicy,
    pub violations: Vec<PolicyViolation>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproducibilityState {
    NotChecked,
    Reproduced,
    NonReproducible,
    Inconclusive,
    Unsupported,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityResult {
    pub original_build_id: BuildId,
    pub rebuild_id: Option<BuildId>,
    pub state: ReproducibilityState,
    pub reason: String,
    pub original_content: Option<String>,
    pub rebuild_content: Option<String>,
    pub checked_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBundle {
    pub version: u32,
    pub build: DsseEnvelope,
    pub release: DsseEnvelope,
}
