//! M7 automation and integration domain. Records here are public/serializable and never
//! contain credentials, webhook secrets or third-party tokens.
use crate::{BuildId, DeveloperId, ProjectId, PublishId, SourceEventId, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::developer::identity;
identity!(AutomationId);
identity!(AutomationRunId);
identity!(ApprovalId);
identity!(IntegrationId);
identity!(WebhookId);
identity!(DeliveryId);
identity!(EventId);

/// Monotonic version of one automation's definition. Runs keep the version they were admitted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AutomationVersion(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationRunStatus {
    Queued,
    Running,
    WaitingForBuild,
    WaitingForPublication,
    WaitingForSecurity,
    WaitingForApproval,
    Completed,
    Failed,
    Cancelled,
}
impl AutomationRunStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
    pub fn is_waiting(self) -> bool {
        matches!(
            self,
            Self::WaitingForBuild
                | Self::WaitingForPublication
                | Self::WaitingForSecurity
                | Self::WaitingForApproval
        )
    }
    /// Explicit transition table. A run is never completed by trigger admission alone.
    pub fn can_transition_to(self, next: Self) -> bool {
        use AutomationRunStatus::*;
        if self.is_terminal() {
            return false;
        }
        match (self, next) {
            (a, b) if a == b => true,
            (Queued, Running | Failed | Cancelled) => true,
            (Running, n) => n.is_waiting() || matches!(n, Completed | Failed | Cancelled),
            (w, Running | Failed | Cancelled) if w.is_waiting() => true,
            (w, n) if w.is_waiting() && n.is_waiting() => true,
            (w, Completed) if w.is_waiting() => true,
            _ => false,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::WaitingForBuild => "waiting_for_build",
            Self::WaitingForPublication => "waiting_for_publication",
            Self::WaitingForSecurity => "waiting_for_security",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}
impl std::str::FromStr for AutomationRunStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "waiting_for_build" => Self::WaitingForBuild,
            "waiting_for_publication" => Self::WaitingForPublication,
            "waiting_for_security" => Self::WaitingForSecurity,
            "waiting_for_approval" => Self::WaitingForApproval,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return Err("Unknown automation run status"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationStepStatus {
    Pending,
    Running,
    /// Waiting for state owned by another subsystem (build, publication, analysis, approval).
    Waiting,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
}
impl AutomationStepStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Skipped | Self::Cancelled
        )
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        use AutomationStepStatus::*;
        if self.is_terminal() {
            return false;
        }
        match (self, next) {
            (a, b) if a == b => true,
            (Pending, Running | Skipped | Cancelled | Failed) => true,
            (Running, Waiting | Succeeded | Failed | Skipped | Cancelled) => true,
            (Waiting, Running | Succeeded | Failed | Skipped | Cancelled) => true,
            _ => false,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
        }
    }
}
impl std::str::FromStr for AutomationStepStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "waiting" => Self::Waiting,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "skipped" => Self::Skipped,
            "cancelled" => Self::Cancelled,
            _ => return Err("Unknown automation step status"),
        })
    }
}

/// How a run entered LibreHub. Only the first three are authenticated developer or
/// owner-configured sources; `Ci` is a federated external identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationTrigger {
    Manual,
    Push,
    Tag,
    Schedule,
    Ci,
}
impl AutomationTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Push => "push",
            Self::Tag => "tag",
            Self::Schedule => "schedule",
            Self::Ci => "ci",
        }
    }
}
impl std::str::FromStr for AutomationTrigger {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "manual" => Self::Manual,
            "push" => Self::Push,
            "tag" => Self::Tag,
            "schedule" => Self::Schedule,
            "ci" => Self::Ci,
            _ => return Err("Unknown automation trigger"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Requested,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}
impl ApprovalStatus {
    pub fn is_terminal(self) -> bool {
        self != Self::Requested
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        self == Self::Requested && next != Self::Requested
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}
impl std::str::FromStr for ApprovalStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "requested" => Self::Requested,
            "approved" => Self::Approved,
            "rejected" => Self::Rejected,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => return Err("Unknown approval status"),
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

/// Who may decide an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverRole {
    ProjectOwner,
    AuthorizedReleaseApprover,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivering,
    Delivered,
    RetryWait,
    Failed,
    DeadLetter,
}
impl DeliveryStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::DeadLetter)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivering => "delivering",
            Self::Delivered => "delivered",
            Self::RetryWait => "retry_wait",
            Self::Failed => "failed",
            Self::DeadLetter => "dead_letter",
        }
    }
}
impl std::str::FromStr for DeliveryStatus {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pending" => Self::Pending,
            "delivering" => Self::Delivering,
            "delivered" => Self::Delivered,
            "retry_wait" => Self::RetryWait,
            "failed" => Self::Failed,
            "dead_letter" => Self::DeadLetter,
            _ => return Err("Unknown delivery status"),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

/// Mutable head of a workflow. Every change creates an immutable version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationDefinition {
    pub id: AutomationId,
    pub project_id: ProjectId,
    pub name: String,
    pub enabled: bool,
    pub schedules_enabled: bool,
    pub current_version: AutomationVersion,
    /// Runs admitted before this version cannot publish or promote.
    pub min_valid_version: AutomationVersion,
    pub spec: serde_json::Value,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationStep {
    pub id: String,
    pub kind: String,
    pub needs: Vec<String>,
    pub status: AutomationStepStatus,
    pub attempts: u32,
    pub next_attempt_at: Option<Timestamp>,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    /// Non-secret references and progress (build/publication IDs, severities...).
    pub output: serde_json::Value,
    pub error: Option<AutomationFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationRun {
    pub id: AutomationRunId,
    pub automation_id: AutomationId,
    pub project_id: ProjectId,
    pub definition_version: AutomationVersion,
    pub status: AutomationRunStatus,
    pub trigger: AutomationTrigger,
    pub trigger_key: String,
    /// Non-secret description of the verified trigger (webhook delivery, CI run, schedule...).
    pub trigger_detail: serde_json::Value,
    pub source_ref: Option<String>,
    pub source_commit: Option<String>,
    pub source_event_id: Option<SourceEventId>,
    pub build_id: Option<BuildId>,
    pub beta_publication_id: Option<PublishId>,
    pub stable_publication_id: Option<PublishId>,
    pub current_step: Option<String>,
    pub project_policy_version: u64,
    pub chain_depth: u32,
    pub correlation_id: String,
    pub cancel_requested: bool,
    pub error: Option<AutomationFailure>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<AutomationStep>,
}

/// The immutable release candidate an approval applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseCandidate {
    pub project_id: ProjectId,
    pub automation_id: AutomationId,
    pub run_id: AutomationRunId,
    pub definition_version: AutomationVersion,
    pub build_id: BuildId,
    pub source_commit: String,
    pub snapshot_sha256: String,
    pub app_id: String,
    pub beta_publication_id: Option<PublishId>,
    pub beta_ostree_commit: Option<String>,
    pub target_channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: ApprovalId,
    pub project_id: ProjectId,
    pub run_id: AutomationRunId,
    pub step_id: String,
    pub status: ApprovalStatus,
    pub candidate: ReleaseCandidate,
    pub candidate_sha256: String,
    pub definition_version: AutomationVersion,
    pub project_policy_version: u64,
    pub requested_by: String,
    pub requested_at: Timestamp,
    pub expires_at: Timestamp,
    pub decided_by: Option<DeveloperId>,
    pub decided_role: Option<ApproverRole>,
    pub decided_at: Option<Timestamp>,
    pub reason: Option<String>,
    pub consumed_at: Option<Timestamp>,
}

/// A trusted external CI identity. The policy contains no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConnection {
    pub id: IntegrationId,
    pub project_id: ProjectId,
    pub kind: String,
    pub name: String,
    pub policy: serde_json::Value,
    pub fingerprint: String,
    pub enabled: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastDelivery {
    pub delivery_id: DeliveryId,
    pub status: DeliveryStatus,
    pub http_status: Option<u16>,
    pub at: Timestamp,
}
/// An outbound webhook subscription. The signing secret is never part of this view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookView {
    pub id: WebhookId,
    pub project_id: ProjectId,
    pub url: String,
    pub description: String,
    pub event_types: Vec<String>,
    pub exclude_origins: Vec<String>,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
    pub secret_fingerprint: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub secret_rotated_at: Option<Timestamp>,
    pub last_delivery: Option<LastDelivery>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryView {
    pub id: DeliveryId,
    pub webhook_id: WebhookId,
    pub event_id: EventId,
    pub event_type: String,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub next_attempt_at: Timestamp,
    pub last_http_status: Option<u16>,
    pub last_error: Option<String>,
    pub replay_of: Option<DeliveryId>,
    pub created_at: Timestamp,
    pub delivered_at: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptView {
    pub attempt: u32,
    pub started_at: Timestamp,
    pub duration_ms: u64,
    pub http_status: Option<u16>,
    pub outcome: String,
    pub error: Option<String>,
}

pub const OUTBOUND_EVENT_TYPES: &[&str] = &[
    "build.started",
    "build.succeeded",
    "build.failed",
    "publication.started",
    "publication.succeeded",
    "publication.failed",
    "security.analysis_ready",
    "security.analysis_failed",
    "attestation.ready",
    "attestation.failed",
    "automation.started",
    "automation.completed",
    "automation.failed",
    "automation.approval_required",
];

#[cfg(test)]
mod tests {
    use super::*;
    use AutomationRunStatus::*;
    #[test]
    fn terminal_runs_never_transition() {
        for t in [Completed, Failed, Cancelled] {
            for n in [Queued, Running, WaitingForBuild, Completed, Failed] {
                assert!(!t.can_transition_to(n));
            }
        }
    }
    #[test]
    fn admission_alone_cannot_complete_a_run() {
        assert!(!Queued.can_transition_to(Completed));
        assert!(Queued.can_transition_to(Running));
        assert!(Running.can_transition_to(WaitingForBuild));
        assert!(WaitingForBuild.can_transition_to(WaitingForPublication));
        assert!(WaitingForApproval.can_transition_to(Completed));
        assert!(!Queued.can_transition_to(WaitingForBuild));
    }
    #[test]
    fn approvals_are_single_decision() {
        assert!(ApprovalStatus::Requested.can_transition_to(ApprovalStatus::Approved));
        assert!(!ApprovalStatus::Approved.can_transition_to(ApprovalStatus::Rejected));
        assert!(!ApprovalStatus::Expired.can_transition_to(ApprovalStatus::Approved));
    }
    #[test]
    fn step_transitions_are_explicit() {
        use AutomationStepStatus::*;
        assert!(Pending.can_transition_to(Running));
        assert!(!Pending.can_transition_to(Succeeded));
        assert!(!Succeeded.can_transition_to(Running));
        assert!(Waiting.can_transition_to(Succeeded));
    }
    #[test]
    fn statuses_round_trip() {
        for s in [Queued, WaitingForSecurity, Completed] {
            assert_eq!(s.as_str().parse::<AutomationRunStatus>().unwrap(), s);
        }
    }
}
