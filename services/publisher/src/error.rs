use librehub_common::PublishFailure;

/// Deliberately contains no raw remote response, URL, token, or filesystem error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PublishError {
    #[error("Only successful builds can be published")]
    Ineligible,
    #[error("The build artifact does not match its recorded metadata or SHA-256")]
    Integrity,
    #[error("The application ref or metadata does not match the source build")]
    Metadata,
    #[error("No publisher supports this architecture")]
    Architecture,
    #[error("The publishing filesystem boundary is invalid or unavailable")]
    Storage,
    #[error("Flatpak/OSTree preparation failed")]
    Preparation,
    #[error("flat-manager rejected authentication")]
    Unauthorized,
    #[error("flat-manager rejected the operation (HTTP {0})")]
    Rejected(u16),
    #[error("flat-manager is temporarily unavailable")]
    Unavailable,
    #[error("A publishing operation exceeded its time limit")]
    Timeout,
    #[error("flat-manager returned an invalid response")]
    Malformed,
    #[error("flat-manager did not persist the complete upload")]
    PartialUpload,
    #[error("flat-manager commit failed")]
    Commit,
    #[error("flat-manager publication or repository update failed")]
    Publish,
    #[error("Published ref, checksum, or signature could not be verified")]
    Verification,
    #[error("The remote creation outcome is uncertain; operator reconciliation is required")]
    Uncertain,
    #[error("Publication persistence failed")]
    Persistence,
}
impl PublishError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Ineligible => "build_not_publishable",
            Self::Integrity => "artifact_integrity_failed",
            Self::Metadata => "artifact_metadata_mismatch",
            Self::Architecture => "unsupported_architecture",
            Self::Storage => "publication_storage_unavailable",
            Self::Preparation => "repository_preparation_failed",
            Self::Unauthorized => "flat_manager_unauthorized",
            Self::Rejected(_) => "flat_manager_rejected",
            Self::Unavailable => "flat_manager_unavailable",
            Self::Timeout => "publish_timeout",
            Self::Malformed => "flat_manager_malformed_response",
            Self::PartialUpload => "partial_upload",
            Self::Commit => "commit_failed",
            Self::Publish => "publish_failed",
            Self::Verification => "repository_verification_failed",
            Self::Uncertain => "publication_outcome_uncertain",
            Self::Persistence => "publication_persistence_failed",
        }
    }
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::Timeout | Self::PartialUpload | Self::Verification
        )
    }
    pub fn failure(&self) -> PublishFailure {
        PublishFailure {
            code: self.code().into(),
            message: self.to_string(),
            retryable: self.retryable(),
        }
    }
}
