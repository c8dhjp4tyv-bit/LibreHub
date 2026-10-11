//! Bounded polling with backoff and a precise definition of "done" for runs and steps.
use crate::{api::Client, error::CliError};
use serde_json::Value;
use std::time::{Duration, Instant};

pub struct Poller {
    deadline: Instant,
    interval: Duration,
    pub timeout: u64,
}
impl Poller {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(timeout_secs),
            interval: Duration::from_millis(500),
            timeout: timeout_secs,
        }
    }
    /// Sleep before the next poll or fail once the overall budget is spent.
    pub async fn tick(&mut self, what: &str) -> Result<(), CliError> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(CliError::Timeout(format!(
                "Timed out after {}s waiting for {what}",
                self.timeout
            )));
        }
        let pause = self.interval.min(self.deadline - now);
        tokio::time::sleep(pause).await;
        self.interval = (self.interval * 3 / 2).min(Duration::from_secs(5));
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Done,
    Pending,
    Failed { code: String, message: String },
}

/// Map friendly names to a step: an exact step ID wins, then the step kind.
pub fn find_step<'a>(run: &'a Value, target: &str) -> Option<&'a Value> {
    let steps = run["steps"].as_array()?;
    if let Some(step) = steps.iter().find(|s| s["id"] == target) {
        return Some(step);
    }
    let kind = match target {
        "build" => "librehub/build",
        "verify" | "verify-provenance" => "librehub/verify-provenance",
        "publish-beta" | "publish" | "beta" => "librehub/publish",
        "security" | "check-security" => "librehub/check-security",
        "approval" | "approval-requested" => "librehub/approval",
        "promote" | "stable" | "publish-stable" => "librehub/promote",
        _ => return None,
    };
    steps.iter().find(|s| s["kind"] == kind)
}
fn failure(run: &Value, step: Option<&Value>) -> Check {
    let error = step
        .and_then(|s| s["error"].as_object())
        .or_else(|| run["error"].as_object());
    Check::Failed {
        code: error.and_then(|e| e["code"].as_str()).map_or_else(
            || format!("run_{}", run["status"].as_str().unwrap_or("failed")),
            str::to_owned,
        ),
        message: error
            .and_then(|e| e["message"].as_str())
            .unwrap_or("The run did not complete")
            .to_owned(),
    }
}
/// Has the run reached `target`? `None`/`completed` means the whole run.
pub fn check(run: &Value, target: Option<&str>) -> Result<Check, CliError> {
    let status = run["status"].as_str().unwrap_or("");
    let terminal_bad = matches!(status, "failed" | "cancelled");
    match target {
        None | Some("completed") => Ok(match status {
            "completed" => Check::Done,
            _ if terminal_bad => failure(run, None),
            _ => Check::Pending,
        }),
        Some(target) => {
            let step = find_step(run, target).ok_or_else(|| {
                CliError::usage(format!("This run has no step or stage named `{target}`"))
            })?;
            let step_status = step["status"].as_str().unwrap_or("");
            if target == "approval-requested" {
                return Ok(match (step_status, status) {
                    ("succeeded" | "skipped", _) | ("waiting", "waiting_for_approval") => {
                        Check::Done
                    }
                    ("failed" | "cancelled", _) => failure(run, Some(step)),
                    _ if terminal_bad => failure(run, Some(step)),
                    _ => Check::Pending,
                });
            }
            Ok(match step_status {
                "succeeded" | "skipped" => Check::Done,
                "failed" | "cancelled" => failure(run, Some(step)),
                _ if terminal_bad => failure(run, Some(step)),
                _ => Check::Pending,
            })
        }
    }
}

pub async fn wait_run(
    client: &Client,
    project: &str,
    run: &str,
    target: Option<&str>,
    timeout: u64,
) -> Result<Value, CliError> {
    let mut poller = Poller::new(timeout);
    loop {
        let view = client
            .get(
                &format!("/api/v1/projects/{project}/automations/runs/{run}"),
                &[],
            )
            .await?;
        match check(&view, target)? {
            Check::Done => return Ok(view),
            Check::Failed { code, message } => return Err(CliError::Failed { code, message }),
            Check::Pending => {
                poller
                    .tick(&format!(
                        "{} (currently {})",
                        target.unwrap_or("the run to finish"),
                        view["status"].as_str().unwrap_or("unknown")
                    ))
                    .await?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn run(status: &str, steps: Vec<(&str, &str, &str)>) -> Value {
        json!({"status": status, "steps": steps.into_iter().map(|(id, kind, s)| json!({"id":id,"kind":kind,"status":s,"error":null})).collect::<Vec<_>>()})
    }
    #[test]
    fn steps_resolve_by_id_or_kind() {
        let r = run(
            "running",
            vec![
                ("compile", "librehub/build", "succeeded"),
                ("beta", "librehub/publish", "waiting"),
            ],
        );
        assert_eq!(find_step(&r, "build").unwrap()["id"], "compile");
        assert_eq!(find_step(&r, "publish-beta").unwrap()["id"], "beta");
        assert_eq!(find_step(&r, "beta").unwrap()["id"], "beta");
        assert!(find_step(&r, "nonsense").is_none());
        assert!(check(&r, Some("nonsense")).is_err());
    }
    #[test]
    fn a_step_target_is_done_when_the_step_succeeded_even_if_the_run_continues() {
        let r = run(
            "waiting_for_security",
            vec![
                ("build", "librehub/build", "succeeded"),
                ("p", "librehub/publish", "succeeded"),
                ("s", "librehub/check-security", "waiting"),
            ],
        );
        assert_eq!(check(&r, Some("publish-beta")).unwrap(), Check::Done);
        assert_eq!(check(&r, Some("security")).unwrap(), Check::Pending);
        assert_eq!(check(&r, None).unwrap(), Check::Pending);
    }
    #[test]
    fn failures_are_reported_for_the_awaited_step_only() {
        let mut r = run(
            "failed",
            vec![
                ("build", "librehub/build", "succeeded"),
                ("p", "librehub/publish", "failed"),
            ],
        );
        r["steps"][1]["error"] = json!({"code":"supply_chain_policy_denied","message":"denied"});
        assert_eq!(check(&r, Some("build")).unwrap(), Check::Done);
        assert!(
            matches!(check(&r, Some("publish-beta")).unwrap(), Check::Failed { code, .. } if code == "supply_chain_policy_denied")
        );
        assert!(matches!(check(&r, None).unwrap(), Check::Failed { .. }));
        let cancelled = run("cancelled", vec![("build", "librehub/build", "cancelled")]);
        assert!(matches!(
            check(&cancelled, Some("build")).unwrap(),
            Check::Failed { .. }
        ));
    }
    #[test]
    fn approval_requested_is_a_waiting_state() {
        let r = run(
            "waiting_for_approval",
            vec![("a", "librehub/approval", "waiting")],
        );
        assert_eq!(check(&r, Some("approval-requested")).unwrap(), Check::Done);
        assert_eq!(check(&r, Some("approval")).unwrap(), Check::Pending);
    }
    #[tokio::test]
    async fn polling_is_bounded() {
        let mut poller = Poller::new(0);
        assert!(matches!(poller.tick("x").await, Err(CliError::Timeout(_))));
    }
}
