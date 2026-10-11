//! Declarative, bounded release workflows. A workflow only *names* existing LibreHub
//! operations (build, verify, publish, analyse, approve, promote). It carries no commands,
//! scripts, paths or credentials, so it cannot become a second code-execution platform.
use chrono::Weekday;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SPEC_BYTES: usize = 64 * 1024;
pub const MAX_STEPS: usize = 16;
pub const MAX_TRIGGERS: usize = 8;
pub const MAX_DEPTH: usize = 12;
pub const MAX_NODES: usize = 4096;
pub const MAX_PATTERNS: usize = 16;
pub const MAX_APPROVERS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct WorkflowError {
    pub code: &'static str,
    pub message: String,
}
fn err<T>(code: &'static str, message: impl Into<String>) -> Result<T, WorkflowError> {
    Err(WorkflowError {
        code,
        message: message.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSpec {
    pub name: String,
    pub triggers: Vec<TriggerSpec>,
    pub steps: Vec<StepSpec>,
    #[serde(default)]
    pub policy: PolicySpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerSpec {
    /// Verified GitHub push webhook (M3 delivery identity) to one of these branches.
    Push { branches: Vec<String> },
    /// Verified GitHub tag push/create webhook whose tag matches one of these patterns.
    Tag { patterns: Vec<String> },
    /// Daily or weekly UTC schedule.
    Schedule(ScheduleSpec),
    /// Authenticated developer API run (`automations:run`).
    Manual {},
    /// Federated external CI (GitHub Actions OIDC) restricted additionally by these refs.
    Ci {
        #[serde(default)]
        refs: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Every {
    Daily,
    Weekly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CatchUp {
    /// A missed occurrence is recorded as skipped (default).
    #[default]
    Skip,
    /// Run the most recent missed occurrence once.
    RunOnce,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleSpec {
    pub every: Every,
    /// `HH:MM`, always interpreted as UTC.
    pub at: String,
    #[serde(default)]
    pub weekday: Option<String>,
    /// Branch or tag to build (resolved to an immutable commit at occurrence time).
    #[serde(default, rename = "ref")]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub catch_up: CatchUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepKind {
    #[serde(rename = "librehub/build")]
    Build,
    #[serde(rename = "librehub/verify-provenance")]
    VerifyProvenance,
    #[serde(rename = "librehub/publish")]
    Publish,
    #[serde(rename = "librehub/check-security")]
    CheckSecurity,
    #[serde(rename = "librehub/approval")]
    Approval,
    #[serde(rename = "librehub/promote")]
    Promote,
}
impl StepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "librehub/build",
            Self::VerifyProvenance => "librehub/verify-provenance",
            Self::Publish => "librehub/publish",
            Self::CheckSecurity => "librehub/check-security",
            Self::Approval => "librehub/approval",
            Self::Promote => "librehub/promote",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub id: String,
    pub uses: StepKind,
    #[serde(default, deserialize_with = "one_or_many")]
    pub needs: Vec<String>,
    #[serde(default)]
    pub with: Map<String, Value>,
}
/// Accept both `needs: build` and `needs: [build, verify]`.
fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Either::deserialize(d)? {
        Either::One(one) => vec![one],
        Either::Many(many) => many,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// Always enforced: no downstream step runs after a failed build.
    #[serde(default = "yes")]
    pub require_build_success: bool,
    #[serde(default)]
    pub require_valid_build_attestation: bool,
    #[serde(default)]
    pub require_allowed_builder: bool,
    #[serde(default = "yes")]
    pub require_successful_beta_publication: bool,
    #[serde(default)]
    pub require_security_analysis_complete: bool,
    #[serde(default = "yes")]
    pub require_no_blocking_moderation: bool,
    /// Defaults to true: stable promotion needs an approval unless the owner opts out.
    #[serde(default = "yes")]
    pub require_manual_approval: bool,
    /// Additional developers (IDs) who may approve besides the project owner.
    #[serde(default)]
    pub release_approvers: Vec<String>,
}
fn yes() -> bool {
    true
}
impl Default for PolicySpec {
    fn default() -> Self {
        Self {
            require_build_success: true,
            require_valid_build_attestation: false,
            require_allowed_builder: false,
            require_successful_beta_publication: true,
            require_security_analysis_complete: false,
            require_no_blocking_moderation: true,
            require_manual_approval: true,
            release_approvers: vec![],
        }
    }
}

/// Typed, validated step parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum StepParams {
    Build {
        reuse_existing: bool,
    },
    VerifyProvenance,
    Publish {
        channel: Channel,
    },
    CheckSecurity {
        fail_on_severity: SeverityGate,
        on_unavailable: Unavailable,
        timeout_seconds: u64,
    },
    Approval {
        required: bool,
        expires_in_hours: u64,
    },
    Promote {
        channel: Channel,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Beta,
    Stable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityGate {
    Never,
    Critical,
    High,
    Medium,
    Low,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    Wait,
    Fail,
}

impl WorkflowSpec {
    pub fn step(&self, id: &str) -> Option<&StepSpec> {
        self.steps.iter().find(|s| s.id == id)
    }
    /// Re-parse validated parameters. Only call on a spec that passed `validate`.
    pub fn params(&self, id: &str) -> Option<StepParams> {
        self.step(id).and_then(|s| step_params(s).ok())
    }
    /// All transitive prerequisites of a step.
    pub fn ancestors(&self, id: &str) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id.to_owned()];
        while let Some(current) = stack.pop() {
            if let Some(step) = self.step(&current) {
                for need in &step.needs {
                    if seen.insert(need.clone()) {
                        stack.push(need.clone());
                    }
                }
            }
        }
        seen
    }
    pub fn first_of(&self, kind: StepKind) -> Option<&StepSpec> {
        self.steps.iter().find(|s| s.uses == kind)
    }
    pub fn has_ancestor_kind(&self, id: &str, kind: StepKind) -> bool {
        self.ancestors(id)
            .iter()
            .filter_map(|a| self.step(a))
            .any(|s| s.uses == kind)
    }
    /// Topological order, stable for equal depth (declaration order).
    pub fn order(&self) -> Vec<String> {
        let mut done: Vec<String> = vec![];
        let mut remaining: Vec<&StepSpec> = self.steps.iter().collect();
        while !remaining.is_empty() {
            let before = remaining.len();
            let mut next = vec![];
            for step in remaining {
                if step.needs.iter().all(|n| done.contains(n)) {
                    done.push(step.id.clone());
                } else {
                    next.push(step);
                }
            }
            remaining = next;
            if remaining.len() == before {
                break;
            }
        }
        done
    }
}

pub fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.as_bytes()[0].is_ascii_lowercase()
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn valid_pattern(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && !p.starts_with(['/', '-'])
        && !p.contains("..")
        && !p.contains("//")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/*-+".contains(&b))
}
/// `*` matches any run of characters (including `/`). No other metacharacters exist.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
pub fn parse_weekday(value: &str) -> Option<Weekday> {
    Some(match value {
        "mon" => Weekday::Mon,
        "tue" => Weekday::Tue,
        "wed" => Weekday::Wed,
        "thu" => Weekday::Thu,
        "fri" => Weekday::Fri,
        "sat" => Weekday::Sat,
        "sun" => Weekday::Sun,
        _ => return None,
    })
}
pub fn parse_time_of_day(value: &str) -> Option<(u32, u32)> {
    let (h, m) = value.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
    (h < 24 && m < 60).then_some((h, m))
}

fn depth_and_nodes(value: &Value, depth: usize, nodes: &mut usize) -> usize {
    *nodes += 1;
    if *nodes > MAX_NODES {
        return usize::MAX;
    }
    match value {
        Value::Array(items) => items
            .iter()
            .map(|v| depth_and_nodes(v, depth + 1, nodes))
            .max()
            .unwrap_or(depth + 1),
        Value::Object(map) => map
            .values()
            .map(|v| depth_and_nodes(v, depth + 1, nodes))
            .max()
            .unwrap_or(depth + 1),
        _ => depth + 1,
    }
}

/// YAML anchors, aliases, tags and merge keys can expand input exponentially or select
/// arbitrary types, so they are refused instead of being interpreted.
fn reject_yaml_indirection(text: &str) -> Result<(), WorkflowError> {
    for line in text.lines() {
        let mut quote: Option<char> = None;
        let mut previous = ' ';
        let bytes: Vec<char> = line.chars().collect();
        for (i, &c) in bytes.iter().enumerate() {
            match quote {
                Some(q) => {
                    if c == q && previous != '\\' {
                        quote = None;
                    }
                }
                None => {
                    if (c == '"' || c == '\'')
                        && (previous.is_whitespace() || "[{,:-".contains(previous))
                    {
                        quote = Some(c);
                    } else if c == '#' && previous.is_whitespace() {
                        break;
                    } else if ['&', '*', '!'].contains(&c)
                        && (previous.is_whitespace() || "[{,:-".contains(previous))
                        && bytes.get(i + 1).is_some_and(|n| !n.is_whitespace())
                    {
                        return err(
                            "workflow_yaml_unsupported",
                            "YAML anchors, aliases and tags are not supported",
                        );
                    }
                }
            }
            previous = c;
        }
        if line.trim_start().starts_with("<<:") {
            return err(
                "workflow_yaml_unsupported",
                "YAML merge keys are not supported",
            );
        }
    }
    Ok(())
}

/// Parse and fully validate YAML or JSON text.
pub fn parse_workflow(text: &str) -> Result<WorkflowSpec, WorkflowError> {
    if text.len() > MAX_SPEC_BYTES {
        return err("workflow_too_large", "Workflow exceeds 64 KiB");
    }
    let value: Value = if text.trim_start().starts_with('{') {
        serde_json::from_str(text)
            .or_else(|_| err("workflow_invalid", "Workflow is not valid JSON"))?
    } else {
        reject_yaml_indirection(text)?;
        serde_yaml_ng::from_str(text)
            .or_else(|_| err("workflow_invalid", "Workflow is not valid YAML"))?
    };
    parse_workflow_value(value)
}
pub fn parse_workflow_value(value: Value) -> Result<WorkflowSpec, WorkflowError> {
    if serde_json::to_vec(&value).map_or(true, |v| v.len() > MAX_SPEC_BYTES) {
        return err("workflow_too_large", "Workflow exceeds 64 KiB");
    }
    let mut nodes = 0;
    if depth_and_nodes(&value, 0, &mut nodes) > MAX_DEPTH || nodes > MAX_NODES {
        return err(
            "workflow_too_complex",
            "Workflow nesting or size is too large",
        );
    }
    let spec: WorkflowSpec = serde_json::from_value(value).map_err(|e| WorkflowError {
        code: "workflow_invalid",
        message: format!(
            "Workflow does not match the schema: {}",
            sanitize(&e.to_string())
        ),
    })?;
    validate(&spec)?;
    Ok(spec)
}
fn sanitize(message: &str) -> String {
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

fn bool_param(with: &Map<String, Value>, key: &str, default: bool) -> Result<bool, WorkflowError> {
    match with.get(key) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => err("step_parameter_invalid", format!("{key} must be a boolean")),
    }
}
fn int_param(
    with: &Map<String, Value>,
    key: &str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, WorkflowError> {
    match with.get(key) {
        None => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if range.contains(&n) => Ok(n),
            _ => err(
                "step_parameter_invalid",
                format!(
                    "{key} must be an integer in {}..={}",
                    range.start(),
                    range.end()
                ),
            ),
        },
    }
}
fn only_keys(with: &Map<String, Value>, allowed: &[&str]) -> Result<(), WorkflowError> {
    if let Some(key) = with.keys().find(|k| !allowed.contains(&k.as_str())) {
        return err(
            "step_parameter_invalid",
            format!("Unknown parameter {}", sanitize(key)),
        );
    }
    Ok(())
}
fn channel_param(with: &Map<String, Value>, expected: Channel) -> Result<Channel, WorkflowError> {
    let want = match expected {
        Channel::Beta => "beta",
        Channel::Stable => "stable",
    };
    match with.get("channel").and_then(Value::as_str) {
        Some(c) if c == want => Ok(expected),
        _ => err(
            "step_parameter_invalid",
            format!("channel must be {want} for this step"),
        ),
    }
}

pub fn step_params(step: &StepSpec) -> Result<StepParams, WorkflowError> {
    let with = &step.with;
    match step.uses {
        StepKind::Build => {
            only_keys(with, &["reuse_existing"])?;
            Ok(StepParams::Build {
                reuse_existing: bool_param(with, "reuse_existing", true)?,
            })
        }
        StepKind::VerifyProvenance => {
            only_keys(with, &[])?;
            Ok(StepParams::VerifyProvenance)
        }
        StepKind::Publish => {
            only_keys(with, &["channel"])?;
            Ok(StepParams::Publish {
                channel: channel_param(with, Channel::Beta)?,
            })
        }
        StepKind::Promote => {
            only_keys(with, &["channel"])?;
            Ok(StepParams::Promote {
                channel: channel_param(with, Channel::Stable)?,
            })
        }
        StepKind::CheckSecurity => {
            only_keys(
                with,
                &["fail_on_severity", "on_unavailable", "timeout_seconds"],
            )?;
            let fail_on_severity = match with.get("fail_on_severity").map(Value::as_str) {
                None => SeverityGate::Critical,
                Some(Some("never")) => SeverityGate::Never,
                Some(Some("critical")) => SeverityGate::Critical,
                Some(Some("high")) => SeverityGate::High,
                Some(Some("medium")) => SeverityGate::Medium,
                Some(Some("low")) => SeverityGate::Low,
                _ => return err("step_parameter_invalid", "fail_on_severity is invalid"),
            };
            let on_unavailable = match with.get("on_unavailable").map(Value::as_str) {
                None | Some(Some("wait")) => Unavailable::Wait,
                Some(Some("fail")) => Unavailable::Fail,
                _ => {
                    return err(
                        "step_parameter_invalid",
                        "on_unavailable must be wait or fail",
                    );
                }
            };
            Ok(StepParams::CheckSecurity {
                fail_on_severity,
                on_unavailable,
                timeout_seconds: int_param(with, "timeout_seconds", 3600, 60..=86_400)?,
            })
        }
        StepKind::Approval => {
            only_keys(with, &["required", "expires_in_hours"])?;
            Ok(StepParams::Approval {
                required: bool_param(with, "required", true)?,
                expires_in_hours: int_param(with, "expires_in_hours", 72, 1..=720)?,
            })
        }
    }
}

pub fn validate(spec: &WorkflowSpec) -> Result<(), WorkflowError> {
    if spec.name.trim().is_empty()
        || spec.name.len() > 80
        || spec.name.chars().any(char::is_control)
    {
        return err("workflow_invalid", "name must be 1–80 printable characters");
    }
    if spec.triggers.is_empty() || spec.triggers.len() > MAX_TRIGGERS {
        return err("workflow_invalid", "1–8 triggers are required");
    }
    if spec.steps.is_empty() || spec.steps.len() > MAX_STEPS {
        return err("workflow_too_complex", "1–16 steps are required");
    }
    let mut schedules = 0;
    for trigger in &spec.triggers {
        match trigger {
            TriggerSpec::Push { branches } => check_patterns(branches)?,
            TriggerSpec::Tag { patterns } => check_patterns(patterns)?,
            TriggerSpec::Ci { refs } => {
                if !refs.is_empty() {
                    check_patterns(refs)?
                }
            }
            TriggerSpec::Manual {} => {}
            TriggerSpec::Schedule(s) => {
                schedules += 1;
                if parse_time_of_day(&s.at).is_none() {
                    return err("schedule_invalid", "at must be HH:MM in UTC");
                }
                match (s.every, s.weekday.as_deref()) {
                    (Every::Weekly, Some(day)) if parse_weekday(day).is_some() => {}
                    (Every::Weekly, _) => {
                        return err("schedule_invalid", "weekly schedules need weekday mon..sun");
                    }
                    (Every::Daily, None) => {}
                    (Every::Daily, Some(_)) => {
                        return err("schedule_invalid", "daily schedules cannot set weekday");
                    }
                }
                if s.source_ref
                    .as_deref()
                    .is_some_and(|r| !valid_pattern(r) || r.contains('*'))
                {
                    return err("schedule_invalid", "ref is not a valid branch or tag name");
                }
            }
        }
    }
    if schedules > 2 {
        return err(
            "schedule_invalid",
            "At most two schedule triggers are allowed",
        );
    }
    let mut ids = BTreeSet::new();
    for step in &spec.steps {
        if !valid_identifier(&step.id) {
            return err(
                "step_invalid",
                format!("Invalid step id {}", sanitize(&step.id)),
            );
        }
        if !ids.insert(step.id.as_str()) {
            return err("step_invalid", format!("Duplicate step id {}", step.id));
        }
        if step.needs.len() > MAX_STEPS {
            return err("step_invalid", "Too many dependencies");
        }
        step_params(step)?;
    }
    for step in &spec.steps {
        let mut seen = BTreeSet::new();
        for need in &step.needs {
            if !ids.contains(need.as_str()) {
                return err(
                    "step_invalid",
                    format!("{} needs unknown step {}", step.id, sanitize(need)),
                );
            }
            if need == &step.id || !seen.insert(need) {
                return err(
                    "workflow_cycle",
                    format!("{} has an invalid dependency", step.id),
                );
            }
        }
    }
    if spec.order().len() != spec.steps.len() {
        return err("workflow_cycle", "Step dependencies contain a cycle");
    }
    // Structure: exactly one build; everything else is rooted in it.
    let builds: Vec<_> = spec
        .steps
        .iter()
        .filter(|s| s.uses == StepKind::Build)
        .collect();
    if builds.len() != 1 || !builds[0].needs.is_empty() {
        return err(
            "workflow_invalid",
            "Exactly one build step without dependencies is required",
        );
    }
    for step in &spec.steps {
        if step.uses != StepKind::Build && !spec.has_ancestor_kind(&step.id, StepKind::Build) {
            return err(
                "workflow_invalid",
                format!("{} must depend on the build step", step.id),
            );
        }
        match step.uses {
            StepKind::CheckSecurity if !spec.has_ancestor_kind(&step.id, StepKind::Publish) => {
                return err(
                    "workflow_invalid",
                    "check-security must follow a publish step",
                );
            }
            StepKind::Promote => {
                let p = &spec.policy;
                if !spec.has_ancestor_kind(&step.id, StepKind::VerifyProvenance)
                    && p.require_valid_build_attestation
                {
                    return err(
                        "workflow_invalid",
                        "promote must follow verify-provenance when attestation is required",
                    );
                }
                if p.require_successful_beta_publication
                    && !spec.has_ancestor_kind(&step.id, StepKind::Publish)
                {
                    return err(
                        "workflow_invalid",
                        "promote must follow a beta publish step",
                    );
                }
                if p.require_security_analysis_complete
                    && !spec.has_ancestor_kind(&step.id, StepKind::CheckSecurity)
                {
                    return err("workflow_invalid", "promote must follow check-security");
                }
                if p.require_manual_approval {
                    let approved = spec
                        .ancestors(&step.id)
                        .iter()
                        .filter_map(|a| spec.step(a))
                        .any(|s| {
                            s.uses == StepKind::Approval
                                && matches!(
                                    step_params(s),
                                    Ok(StepParams::Approval { required: true, .. })
                                )
                        });
                    if !approved {
                        return err(
                            "workflow_invalid",
                            "stable promotion requires a preceding required approval step",
                        );
                    }
                }
            }
            _ => {}
        }
    }
    if spec.policy.require_valid_build_attestation
        && spec.first_of(StepKind::VerifyProvenance).is_none()
    {
        return err(
            "workflow_invalid",
            "require_valid_build_attestation needs a verify-provenance step",
        );
    }
    if spec.policy.release_approvers.len() > MAX_APPROVERS
        || spec
            .policy
            .release_approvers
            .iter()
            .any(|a| a.parse::<uuid::Uuid>().is_err())
    {
        return err(
            "workflow_invalid",
            "release_approvers must be up to 8 developer UUIDs",
        );
    }
    if !spec.policy.require_build_success {
        return err(
            "workflow_invalid",
            "require_build_success cannot be disabled",
        );
    }
    // M5 moderation is an operator decision; a workflow cannot opt out of honouring it.
    if !spec.policy.require_no_blocking_moderation {
        return err(
            "workflow_invalid",
            "require_no_blocking_moderation cannot be disabled",
        );
    }
    Ok(())
}
fn check_patterns(patterns: &[String]) -> Result<(), WorkflowError> {
    if patterns.is_empty()
        || patterns.len() > MAX_PATTERNS
        || !patterns.iter().all(|p| valid_pattern(p))
    {
        return err(
            "workflow_invalid",
            "Patterns must be 1–16 safe ref patterns",
        );
    }
    Ok(())
}

/// Trigger matching used at webhook admission.
pub fn matches_push(spec: &WorkflowSpec, branch: &str) -> bool {
    spec.triggers.iter().any(|t| matches!(t, TriggerSpec::Push { branches } if branches.iter().any(|b| glob_match(b, branch))))
}
pub fn matches_tag(spec: &WorkflowSpec, tag: &str) -> bool {
    spec.triggers.iter().any(|t| matches!(t, TriggerSpec::Tag { patterns } if patterns.iter().any(|b| glob_match(b, tag))))
}
pub fn allows_manual(spec: &WorkflowSpec) -> bool {
    spec.triggers
        .iter()
        .any(|t| matches!(t, TriggerSpec::Manual {}))
}
pub fn allows_ci(spec: &WorkflowSpec, source_ref: &str) -> bool {
    spec.triggers.iter().any(|t| match t {
        TriggerSpec::Ci { refs } => {
            refs.is_empty()
                || refs.iter().any(|r| {
                    glob_match(r, source_ref)
                        || glob_match(
                            r,
                            source_ref
                                .trim_start_matches("refs/heads/")
                                .trim_start_matches("refs/tags/"),
                        )
                })
        }
        _ => false,
    })
}
pub fn schedules(spec: &WorkflowSpec) -> Vec<(usize, &ScheduleSpec)> {
    spec.triggers
        .iter()
        .enumerate()
        .filter_map(|(i, t)| match t {
            TriggerSpec::Schedule(s) => Some((i, s)),
            _ => None,
        })
        .collect()
}

/// Content digest of the canonical (key-sorted) spec, used to bind approvals and history.
pub fn spec_sha256(spec: &WorkflowSpec) -> String {
    use sha2::{Digest, Sha256};
    let value = serde_json::to_value(spec).unwrap_or(Value::Null);
    fn canon(value: &Value) -> Value {
        match value {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), canon(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(canon).collect()),
            v => v.clone(),
        }
    }
    let bytes = serde_json::to_vec(&canon(&value)).unwrap_or_default();
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Release workflow used by documentation, the CLI template and tests.
pub const EXAMPLE_RELEASE_PIPELINE: &str = r#"name: Release Pipeline
triggers:
  - type: push
    branches: [main]
  - type: tag
    patterns: ["v*"]
  - type: manual
  - type: ci
steps:
  - id: build
    uses: librehub/build
  - id: verify
    uses: librehub/verify-provenance
    needs: [build]
  - id: publish-beta
    uses: librehub/publish
    needs: [verify]
    with:
      channel: beta
  - id: security
    uses: librehub/check-security
    needs: [publish-beta]
  - id: approval
    uses: librehub/approval
    needs: [security]
    with:
      required: true
  - id: publish-stable
    uses: librehub/promote
    needs: [approval]
    with:
      channel: stable
policy:
  require_security_analysis_complete: true
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<WorkflowSpec, WorkflowError> {
        parse_workflow(text)
    }
    #[test]
    fn example_pipeline_is_valid_and_ordered() {
        let spec = parse(EXAMPLE_RELEASE_PIPELINE).unwrap();
        assert_eq!(spec.steps.len(), 6);
        assert_eq!(
            spec.order(),
            [
                "build",
                "verify",
                "publish-beta",
                "security",
                "approval",
                "publish-stable"
            ]
        );
        assert!(matches_push(&spec, "main"));
        assert!(!matches_push(&spec, "feature"));
        assert!(matches_tag(&spec, "v1.2.3"));
        assert!(allows_manual(&spec));
        assert_eq!(
            spec_sha256(&spec),
            spec_sha256(&parse(EXAMPLE_RELEASE_PIPELINE).unwrap())
        );
    }
    #[test]
    fn json_and_yaml_are_equivalent() {
        let spec = parse(EXAMPLE_RELEASE_PIPELINE).unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(parse(&json).unwrap(), spec);
    }
    #[test]
    fn cycles_and_unknown_dependencies_are_rejected() {
        let base = |steps: &str| {
            format!(
                "name: x\ntriggers: [{{type: manual}}]\npolicy: {{require_manual_approval: false, require_successful_beta_publication: false}}\nsteps:\n{steps}"
            )
        };
        let cycle = base(
            "  - {id: build, uses: librehub/build}\n  - {id: a, uses: librehub/verify-provenance, needs: [b]}\n  - {id: b, uses: librehub/verify-provenance, needs: [a]}\n",
        );
        assert_eq!(parse(&cycle).unwrap_err().code, "workflow_cycle");
        let unknown = base(
            "  - {id: build, uses: librehub/build}\n  - {id: a, uses: librehub/verify-provenance, needs: [ghost]}\n",
        );
        assert_eq!(parse(&unknown).unwrap_err().code, "step_invalid");
        let self_dep = base(
            "  - {id: build, uses: librehub/build}\n  - {id: a, uses: librehub/verify-provenance, needs: [a]}\n",
        );
        assert_eq!(parse(&self_dep).unwrap_err().code, "workflow_cycle");
    }
    #[test]
    fn unsupported_steps_and_shell_fields_are_rejected() {
        for bad in [
            "  - {id: build, uses: librehub/build}\n  - {id: x, uses: shell/run, needs: [build]}\n",
            "  - {id: build, uses: librehub/build}\n  - {id: x, uses: librehub/verify-provenance, needs: [build], run: 'rm -rf /'}\n",
            "  - {id: build, uses: librehub/build, with: {path: /etc}}\n",
        ] {
            let text = format!("name: x\ntriggers: [{{type: manual}}]\nsteps:\n{bad}");
            assert!(parse(&text).is_err(), "{bad}");
        }
    }
    #[test]
    fn oversized_and_deep_workflows_are_rejected() {
        let big = format!("name: {}\n", "a".repeat(MAX_SPEC_BYTES));
        assert_eq!(parse(&big).unwrap_err().code, "workflow_too_large");
        let mut steps = String::new();
        for i in 0..20 {
            steps.push_str(&format!(
                "  - {{id: s{i}, uses: librehub/verify-provenance, needs: [build]}}\n"
            ));
        }
        let many = format!(
            "name: x\ntriggers: [{{type: manual}}]\nsteps:\n  - {{id: build, uses: librehub/build}}\n{steps}"
        );
        assert_eq!(parse(&many).unwrap_err().code, "workflow_too_complex");
        let nested = format!("{}1{}", "[".repeat(40), "]".repeat(40));
        let deep = format!("{{\"name\":\"x\",\"triggers\":[],\"steps\":[],\"extra\":{nested}}}");
        assert_eq!(parse(&deep).unwrap_err().code, "workflow_too_complex");
    }
    #[test]
    fn yaml_indirection_is_rejected() {
        let alias = "name: &a x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n";
        assert_eq!(parse(alias).unwrap_err().code, "workflow_yaml_unsupported");
        let reference = "name: *a\ntriggers: []\nsteps: []\n";
        assert_eq!(
            parse(reference).unwrap_err().code,
            "workflow_yaml_unsupported"
        );
        let tagged = "name: !!str x\ntriggers: []\nsteps: []\n";
        assert_eq!(parse(tagged).unwrap_err().code, "workflow_yaml_unsupported");
        // Quoted wildcard patterns remain legal.
        assert!(parse(EXAMPLE_RELEASE_PIPELINE).is_ok());
    }
    #[test]
    fn stable_promotion_needs_approval_and_beta_by_default() {
        let no_approval = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n  - {id: beta, uses: librehub/publish, needs: [build], with: {channel: beta}}\n  - {id: stable, uses: librehub/promote, needs: [beta], with: {channel: stable}}\n";
        assert!(parse(no_approval).is_err());
        let opted_out = format!("{no_approval}policy: {{require_manual_approval: false}}\n");
        assert!(parse(&opted_out).is_ok());
        let no_beta = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n  - {id: a, uses: librehub/approval, needs: [build]}\n  - {id: stable, uses: librehub/promote, needs: [a], with: {channel: stable}}\n";
        assert!(parse(no_beta).is_err());
        let optional = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n  - {id: beta, uses: librehub/publish, needs: [build], with: {channel: beta}}\n  - {id: a, uses: librehub/approval, needs: [beta], with: {required: false}}\n  - {id: stable, uses: librehub/promote, needs: [a], with: {channel: stable}}\n";
        assert!(
            parse(optional).is_err(),
            "an optional approval does not satisfy the policy"
        );
    }
    #[test]
    fn publish_channel_is_beta_only_and_promote_stable_only() {
        let publish_stable = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n  - {id: p, uses: librehub/publish, needs: [build], with: {channel: stable}}\n";
        assert!(parse(publish_stable).is_err());
    }
    #[test]
    fn schedules_are_validated_in_utc() {
        let ok = "name: x\ntriggers:\n  - {type: schedule, every: weekly, weekday: mon, at: '03:30'}\nsteps:\n  - {id: build, uses: librehub/build}\n";
        assert!(parse(ok).is_ok());
        for bad in [
            "{type: schedule, every: weekly, at: '03:30'}",
            "{type: schedule, every: daily, weekday: mon, at: '03:30'}",
            "{type: schedule, every: daily, at: '25:00'}",
            "{type: schedule, every: daily, at: '3:30'}",
        ] {
            let text = format!(
                "name: x\ntriggers: [{bad}]\nsteps:\n  - {{id: build, uses: librehub/build}}\n"
            );
            assert_eq!(parse(&text).unwrap_err().code, "schedule_invalid", "{bad}");
        }
    }
    #[test]
    fn moderation_and_build_success_gates_cannot_be_disabled() {
        for flag in ["require_build_success", "require_no_blocking_moderation"] {
            let text = format!(
                "name: x\ntriggers: [{{type: manual}}]\nsteps:\n  - {{id: build, uses: librehub/build}}\npolicy: {{{flag}: false}}\n"
            );
            assert_eq!(parse(&text).unwrap_err().code, "workflow_invalid", "{flag}");
        }
    }
    #[test]
    fn exactly_one_build_is_required() {
        let none = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: a, uses: librehub/verify-provenance}\n";
        assert!(parse(none).is_err());
        let two = "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: librehub/build}\n  - {id: b2, uses: librehub/build}\n";
        assert!(parse(two).is_err());
    }
    #[test]
    fn globs_match_without_regex_surprises() {
        assert!(glob_match("v*", "v1.0"));
        assert!(glob_match("release/*", "release/1.x/beta"));
        assert!(glob_match("main", "main"));
        assert!(!glob_match("main", "main2"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("v*", "x1"));
        assert!(glob_match("refs/heads/*", "refs/heads/a/b"));
    }
}
