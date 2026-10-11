//! Failure classification and bounded exponential backoff with jitter.
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Safe to retry: the same operation can succeed later without side-effect duplication.
    Transient,
    /// Retrying cannot help (authorization, invalid input, policy, moderation).
    Permanent,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepFailure {
    pub kind: FailureKind,
    pub code: &'static str,
    pub message: String,
}
impl StepFailure {
    pub fn permanent(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Permanent,
            code,
            message: message.into(),
        }
    }
    pub fn transient(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Transient,
            code,
            message: message.into(),
        }
    }
}

/// Codes that are known to be transient. Everything else defaults to permanent, so a new
/// error cannot accidentally be retried forever.
pub fn classify(code: &str) -> FailureKind {
    match code {
        "source_queue_full"
        | "queue_full"
        | "publish_queue_full"
        | "database_busy"
        | "source_unavailable"
        | "publisher_unavailable"
        | "temporarily_unavailable"
        | "build_queue_full"
        | "security_provider_unavailable" => FailureKind::Transient,
        _ => FailureKind::Permanent,
    }
}

pub const BASE_DELAY: Duration = Duration::from_secs(5);
pub const MAX_DELAY: Duration = Duration::from_secs(900);
pub const MAX_ATTEMPTS: u32 = 8;

/// `jitter` is a value in `[0,1)`; the delay varies by ±25%. Deterministic for tests.
pub fn backoff(attempt: u32, jitter: f64) -> Duration {
    let exp = BASE_DELAY.as_secs_f64() * 2f64.powi(attempt.saturating_sub(1).min(16) as i32);
    let capped = exp.min(MAX_DELAY.as_secs_f64());
    let factor = 0.75 + 0.5 * jitter.clamp(0.0, 0.999_999);
    Duration::from_secs_f64((capped * factor).min(MAX_DELAY.as_secs_f64() * 1.25))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backoff_grows_and_is_bounded() {
        let a = backoff(1, 0.5);
        let b = backoff(2, 0.5);
        let c = backoff(30, 0.5);
        assert!(b > a);
        assert!(c <= Duration::from_secs_f64(MAX_DELAY.as_secs_f64() * 1.25));
        assert!(backoff(3, 0.0) < backoff(3, 0.99));
    }
    #[test]
    fn unknown_failures_are_permanent() {
        assert_eq!(classify("source_queue_full"), FailureKind::Transient);
        assert_eq!(classify("insufficient_scope"), FailureKind::Permanent);
        assert_eq!(
            classify("supply_chain_policy_denied"),
            FailureKind::Permanent
        );
        assert_eq!(classify("something_new"), FailureKind::Permanent);
    }
}
