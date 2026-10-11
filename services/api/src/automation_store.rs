//! Durable automation state. Every transition is a SQLite transaction, so a crash can never
//! leave a run half-admitted, an approval half-consumed or an event half-recorded.
use crate::{
    platform_store::{Admission, PlatformError, SourceAdmission, admit_source_in, audit},
    store::Store,
};
use chrono::{DateTime, Utc};
use librehub_automation::{
    schedule::{self, Due},
    workflow::{self, StepKind, WorkflowSpec},
};
use librehub_common::*;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Finite defaults; every limit refuses admission instead of dropping history.
#[derive(Debug, Clone)]
pub struct AutomationLimits {
    pub automations_per_project: usize,
    pub active_runs_per_project: usize,
    pub active_runs_global: usize,
    pub runs_per_project: usize,
    pub runs_per_hour_per_automation: usize,
    pub pending_approvals_per_project: usize,
    pub max_chain_depth: u32,
    pub step_concurrency: usize,
    pub webhooks_per_project: usize,
    pub connections_per_project: usize,
    pub oidc_exchanges_per_hour: usize,
    pub integration_audit_per_project: usize,
}
impl Default for AutomationLimits {
    fn default() -> Self {
        Self {
            automations_per_project: 8,
            active_runs_per_project: 8,
            active_runs_global: 64,
            runs_per_project: 5000,
            runs_per_hour_per_automation: 60,
            pending_approvals_per_project: 16,
            max_chain_depth: 3,
            step_concurrency: 4,
            webhooks_per_project: 8,
            connections_per_project: 4,
            oidc_exchanges_per_hour: 120,
            integration_audit_per_project: 10_000,
        }
    }
}

impl AutomationLimits {
    /// `LIBREHUB_AUTOMATION_*` overrides, each bounded so a typo cannot disable a limit.
    pub fn from_env() -> anyhow::Result<Self> {
        fn read(key: &str, default: usize, max: usize) -> anyhow::Result<usize> {
            match std::env::var(key) {
                Err(_) => Ok(default),
                Ok(v) => {
                    let n: usize = v.parse().map_err(|_| anyhow::anyhow!("Invalid {key}"))?;
                    anyhow::ensure!((1..=max).contains(&n), "{key} must be between 1 and {max}");
                    Ok(n)
                }
            }
        }
        let d = Self::default();
        Ok(Self {
            automations_per_project: read(
                "LIBREHUB_AUTOMATION_MAX_PER_PROJECT",
                d.automations_per_project,
                64,
            )?,
            active_runs_per_project: read(
                "LIBREHUB_AUTOMATION_MAX_ACTIVE_RUNS_PER_PROJECT",
                d.active_runs_per_project,
                64,
            )?,
            active_runs_global: read(
                "LIBREHUB_AUTOMATION_MAX_ACTIVE_RUNS",
                d.active_runs_global,
                512,
            )?,
            runs_per_hour_per_automation: read(
                "LIBREHUB_AUTOMATION_MAX_RUNS_PER_HOUR",
                d.runs_per_hour_per_automation,
                600,
            )?,
            max_chain_depth: read(
                "LIBREHUB_AUTOMATION_MAX_CHAIN_DEPTH",
                d.max_chain_depth as usize,
                8,
            )? as u32,
            step_concurrency: read(
                "LIBREHUB_AUTOMATION_STEP_CONCURRENCY",
                d.step_concurrency,
                16,
            )?,
            webhooks_per_project: read(
                "LIBREHUB_WEBHOOKS_MAX_PER_PROJECT",
                d.webhooks_per_project,
                32,
            )?,
            oidc_exchanges_per_hour: read(
                "LIBREHUB_OIDC_MAX_EXCHANGES_PER_HOUR",
                d.oidc_exchanges_per_hour,
                3600,
            )?,
            ..d
        })
    }
}

fn now_s() -> String {
    Utc::now().to_rfc3339()
}
fn parse_time(raw: &str) -> anyhow::Result<Timestamp> {
    Ok(raw.parse()?)
}
fn opt_time(raw: Option<String>) -> anyhow::Result<Option<Timestamp>> {
    raw.map(|r| parse_time(&r)).transpose()
}

pub const RUN_COLUMNS: &str = "id,automation_id,project_id,definition_version,status,trigger_kind,trigger_key,trigger_detail,source_ref,source_commit,source_event_id,build_id,beta_publication_id,stable_publication_id,current_step,project_policy_version,chain_depth,correlation_id,cancel_requested,error_code,error_message,error_retryable,created_at,updated_at,started_at,finished_at";

struct RawRun {
    id: String,
    automation_id: String,
    project_id: String,
    version: u32,
    status: String,
    trigger: String,
    trigger_key: String,
    detail: String,
    source_ref: Option<String>,
    source_commit: Option<String>,
    source_event_id: Option<String>,
    build_id: Option<String>,
    beta: Option<String>,
    stable: Option<String>,
    current_step: Option<String>,
    policy_version: i64,
    chain_depth: u32,
    correlation_id: String,
    cancel_requested: bool,
    error_code: Option<String>,
    error_message: Option<String>,
    error_retryable: Option<bool>,
    created_at: String,
    updated_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
}
impl RawRun {
    fn from_row(r: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            automation_id: r.get(1)?,
            project_id: r.get(2)?,
            version: r.get(3)?,
            status: r.get(4)?,
            trigger: r.get(5)?,
            trigger_key: r.get(6)?,
            detail: r.get(7)?,
            source_ref: r.get(8)?,
            source_commit: r.get(9)?,
            source_event_id: r.get(10)?,
            build_id: r.get(11)?,
            beta: r.get(12)?,
            stable: r.get(13)?,
            current_step: r.get(14)?,
            policy_version: r.get(15)?,
            chain_depth: r.get(16)?,
            correlation_id: r.get(17)?,
            cancel_requested: r.get(18)?,
            error_code: r.get(19)?,
            error_message: r.get(20)?,
            error_retryable: r.get(21)?,
            created_at: r.get(22)?,
            updated_at: r.get(23)?,
            started_at: r.get(24)?,
            finished_at: r.get(25)?,
        })
    }
    fn into_run(self) -> anyhow::Result<AutomationRun> {
        Ok(AutomationRun {
            id: self.id.parse()?,
            automation_id: self.automation_id.parse()?,
            project_id: self.project_id.parse()?,
            definition_version: AutomationVersion(self.version),
            status: self
                .status
                .parse()
                .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
            trigger: self
                .trigger
                .parse()
                .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
            trigger_key: self.trigger_key,
            trigger_detail: serde_json::from_str(&self.detail)?,
            source_ref: self.source_ref,
            source_commit: self.source_commit,
            source_event_id: self.source_event_id.map(|v| v.parse()).transpose()?,
            build_id: self.build_id.map(|v| v.parse()).transpose()?,
            beta_publication_id: self.beta.map(|v| v.parse()).transpose()?,
            stable_publication_id: self.stable.map(|v| v.parse()).transpose()?,
            current_step: self.current_step,
            project_policy_version: self.policy_version as u64,
            chain_depth: self.chain_depth,
            correlation_id: self.correlation_id,
            cancel_requested: self.cancel_requested,
            error: self.error_code.map(|code| AutomationFailure {
                code,
                message: self.error_message.unwrap_or_default(),
                retryable: self.error_retryable.unwrap_or(false),
            }),
            created_at: parse_time(&self.created_at)?,
            updated_at: parse_time(&self.updated_at)?,
            started_at: opt_time(self.started_at)?,
            finished_at: opt_time(self.finished_at)?,
            steps: vec![],
        })
    }
}

fn read_run(db: &Connection, id: &str) -> anyhow::Result<Option<AutomationRun>> {
    let raw = db
        .query_row(
            &format!("SELECT {RUN_COLUMNS} FROM automation_runs WHERE id=?1"),
            [id],
            RawRun::from_row,
        )
        .optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let mut run = raw.into_run()?;
    run.steps = read_steps(db, id)?;
    Ok(Some(run))
}
fn read_steps(db: &Connection, run_id: &str) -> anyhow::Result<Vec<AutomationStep>> {
    let mut q = db.prepare("SELECT step_id,kind,needs,status,attempts,next_attempt_at,started_at,finished_at,output,error_code,error_message FROM automation_steps WHERE run_id=?1 ORDER BY ordinal")?;
    let rows = q
        .query_map([run_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, u32>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(
            |(
                id,
                kind,
                needs,
                status,
                attempts,
                next,
                started,
                finished,
                output,
                code,
                message,
            )| {
                Ok(AutomationStep {
                    id,
                    kind,
                    needs: serde_json::from_str(&needs)?,
                    status: status
                        .parse()
                        .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
                    attempts,
                    next_attempt_at: opt_time(next)?,
                    started_at: opt_time(started)?,
                    finished_at: opt_time(finished)?,
                    output: serde_json::from_str(&output)?,
                    error: code.map(|code| AutomationFailure {
                        code,
                        message: message.unwrap_or_default(),
                        retryable: false,
                    }),
                })
            },
        )
        .collect()
}

pub fn run_event(db: &Connection, run_id: &str, kind: &str, detail: Value) -> anyhow::Result<()> {
    db.execute(
        "INSERT INTO automation_run_events(run_id,at,kind,detail) VALUES(?1,?2,?3,?4)",
        params![run_id, now_s(), kind, detail.to_string()],
    )?;
    db.execute(
        "DELETE FROM automation_run_events WHERE run_id=?1 AND id NOT IN (SELECT id FROM automation_run_events WHERE run_id=?1 ORDER BY id DESC LIMIT 200)",
        [run_id],
    )?;
    Ok(())
}

/// Explicit-origin outbox insert for events the engine itself creates.
#[allow(clippy::too_many_arguments)]
pub fn outbox_insert(
    db: &Connection,
    project: &str,
    event_type: &str,
    subject: &str,
    data: Value,
    run: Option<&AutomationRun>,
    dedupe_key: &str,
) -> anyhow::Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,origin_kind,origin_run_id,correlation_id,chain_depth,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            EventId::new().to_string(),
            dedupe_key,
            project,
            event_type,
            subject,
            data.to_string(),
            run.map(|_| "automation"),
            run.map(|r| r.id.to_string()),
            run.map(|r| r.correlation_id.clone()),
            run.map(|r| r.chain_depth),
            now_s()
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct RunContext {
    pub run: AutomationRun,
    pub owner: DeveloperId,
    pub spec: WorkflowSpec,
    pub fresh_build: bool,
}

#[derive(Debug, Clone)]
pub struct AdmitRun {
    pub project_id: ProjectId,
    pub automation_id: AutomationId,
    pub trigger: AutomationTrigger,
    pub trigger_key: String,
    pub trigger_detail: Value,
    pub source_ref: Option<String>,
    pub source_commit: Option<String>,
    pub fresh_build: bool,
    pub chain_depth: u32,
    pub correlation_id: Option<String>,
    /// API callers must own the project; unattended triggers pass `None`.
    pub expected_owner: Option<DeveloperId>,
    pub actor: String,
}
#[derive(Debug)]
pub enum RunAdmission {
    Created(Box<AutomationRun>),
    Existing(Box<AutomationRun>),
}
impl RunAdmission {
    pub fn run(&self) -> &AutomationRun {
        match self {
            Self::Created(r) | Self::Existing(r) => r,
        }
    }
    pub fn created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

#[derive(Debug, Default, Clone)]
pub struct StepPatch {
    pub status: Option<AutomationStepStatus>,
    pub output: Option<Value>,
    pub error: Option<(String, String)>,
    /// `Some(None)` clears the retry timestamp.
    pub next_attempt_at: Option<Option<Timestamp>>,
    pub bump_attempt: bool,
}

pub struct NewAutomation {
    pub project_id: ProjectId,
    pub owner: DeveloperId,
    pub spec: WorkflowSpec,
}
#[derive(Default)]
pub struct AutomationPatch {
    pub spec: Option<WorkflowSpec>,
    pub enabled: Option<bool>,
    pub schedules_enabled: Option<bool>,
}

fn read_definition(
    db: &Connection,
    project: &str,
    id: &str,
) -> anyhow::Result<Option<AutomationDefinition>> {
    let row = db
        .query_row(
            "SELECT d.id,d.project_id,d.name,d.enabled,d.schedules_enabled,d.current_version,d.min_valid_version,v.spec,d.created_at,d.updated_at FROM automation_definitions d JOIN automation_versions v ON v.automation_id=d.id AND v.version=d.current_version WHERE d.id=?1 AND d.project_id=?2",
            params![id, project],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, u32>(5)?,
                    r.get::<_, u32>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(id, project, name, enabled, schedules, cur, min, spec, created, updated)| {
            Ok(AutomationDefinition {
                id: id.parse()?,
                project_id: project.parse()?,
                name,
                enabled,
                schedules_enabled: schedules,
                current_version: AutomationVersion(cur),
                min_valid_version: AutomationVersion(min),
                spec: serde_json::from_str(&spec)?,
                created_at: parse_time(&created)?,
                updated_at: parse_time(&updated)?,
            })
        },
    )
    .transpose()
}

fn install_schedules(
    tx: &Transaction,
    automation: &str,
    version: u32,
    spec: &WorkflowSpec,
) -> anyhow::Result<()> {
    tx.execute(
        "DELETE FROM automation_triggers WHERE automation_id=?1",
        [automation],
    )?;
    let now = Utc::now();
    for (index, s) in workflow::schedules(spec) {
        if let Some(next) = schedule::next_after(s, now) {
            tx.execute(
                "INSERT INTO automation_triggers(automation_id,trigger_index,version,next_run_at) VALUES(?1,?2,?3,?4)",
                params![automation, index as i64, version, next.to_rfc3339()],
            )?;
        }
    }
    Ok(())
}

fn require_project(tx: &Connection, id: ProjectId) -> anyhow::Result<(Project, bool)> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT record FROM projects WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let project: Project = serde_json::from_str(&raw.ok_or(PlatformError("project_not_found"))?)?;
    let active: bool = tx.query_row(
        "SELECT status='active' FROM developers WHERE id=?1",
        [project.owner_developer_id.to_string()],
        |r| r.get(0),
    )?;
    Ok((project, active))
}

fn spec_of(raw: &str) -> anyhow::Result<WorkflowSpec> {
    Ok(workflow::parse_workflow_value(serde_json::from_str(raw)?)
        .map_err(|_| PlatformError("workflow_invalid"))?)
}

/// Core admission, shared by API, webhook and scheduler triggers.
fn admit_run_in(
    tx: &Transaction,
    limits: &AutomationLimits,
    input: &AdmitRun,
) -> anyhow::Result<RunAdmission> {
    // Idempotency first: a repeated trigger identity returns the original run, whatever has changed since.
    let existing = tx
        .query_row(
            "SELECT id FROM automation_runs WHERE automation_id=?1 AND trigger_key=?2",
            params![input.automation_id.to_string(), input.trigger_key],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    if let Some(id) = existing {
        let run = read_run(tx, &id)?.ok_or(PlatformError("automation_run_not_found"))?;
        if input.expected_owner.is_some() && run.project_id != input.project_id {
            return Err(PlatformError("automation_not_found").into());
        }
        return Ok(RunAdmission::Existing(Box::new(run)));
    }
    let (project, developer_active) = require_project(tx, input.project_id)?;
    if input
        .expected_owner
        .is_some_and(|o| o != project.owner_developer_id)
    {
        return Err(PlatformError("project_not_found").into());
    }
    let definition = read_definition(
        tx,
        &input.project_id.to_string(),
        &input.automation_id.to_string(),
    )?
    .ok_or(PlatformError("automation_not_found"))?;
    // Explicit policy for disabled/archived/moderated state: no new work is admitted.
    if project.status != ProjectStatus::Active || !developer_active {
        return Err(PlatformError("project_not_active").into());
    }
    if !definition.enabled {
        return Err(PlatformError("automation_disabled").into());
    }
    if input.chain_depth > limits.max_chain_depth {
        return Err(PlatformError("automation_loop_detected").into());
    }
    let spec = spec_of(&definition.spec.to_string())?;
    let trigger_allowed = match input.trigger {
        AutomationTrigger::Manual => workflow::allows_manual(&spec),
        AutomationTrigger::Ci => {
            workflow::allows_ci(&spec, input.source_ref.as_deref().unwrap_or(""))
        }
        AutomationTrigger::Push | AutomationTrigger::Tag | AutomationTrigger::Schedule => true,
    };
    if !trigger_allowed {
        return Err(PlatformError("automation_trigger_not_allowed").into());
    }
    let project_id = input.project_id.to_string();
    let active_project: i64 = tx.query_row(
        "SELECT count(*) FROM automation_runs WHERE project_id=?1 AND status NOT IN ('completed','failed','cancelled')",
        [&project_id],
        |r| r.get(0),
    )?;
    let active_global: i64 = tx.query_row(
        "SELECT count(*) FROM automation_runs WHERE status NOT IN ('completed','failed','cancelled')",
        [],
        |r| r.get(0),
    )?;
    if active_project >= limits.active_runs_per_project as i64
        || active_global >= limits.active_runs_global as i64
    {
        return Err(PlatformError("automation_queue_full").into());
    }
    let total: i64 = tx.query_row(
        "SELECT count(*) FROM automation_runs WHERE project_id=?1",
        [&project_id],
        |r| r.get(0),
    )?;
    if total >= limits.runs_per_project as i64 {
        return Err(PlatformError("automation_history_limit").into());
    }
    let hour_ago = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let recent: i64 = tx.query_row(
        "SELECT count(*) FROM automation_runs WHERE automation_id=?1 AND created_at>?2",
        params![input.automation_id.to_string(), hour_ago],
        |r| r.get(0),
    )?;
    if recent >= limits.runs_per_hour_per_automation as i64 {
        return Err(PlatformError("automation_rate_limited").into());
    }
    let id = AutomationRunId::new();
    let now = now_s();
    let correlation = input
        .correlation_id
        .clone()
        .unwrap_or_else(|| id.to_string());
    if correlation.len() > 128 || correlation.chars().any(char::is_control) {
        return Err(PlatformError("invalid_request").into());
    }
    tx.execute(
        "INSERT INTO automation_runs(id,automation_id,project_id,owner,definition_version,spec,status,trigger_kind,trigger_key,trigger_detail,source_ref,source_commit,project_policy_version,chain_depth,correlation_id,fresh_build,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,'queued',?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
        params![
            id.to_string(),
            input.automation_id.to_string(),
            project_id,
            project.owner_developer_id.to_string(),
            definition.current_version.0,
            definition.spec.to_string(),
            input.trigger.as_str(),
            input.trigger_key,
            input.trigger_detail.to_string(),
            input.source_ref,
            input.source_commit,
            project.policy_version as i64,
            input.chain_depth,
            correlation,
            input.fresh_build,
            now,
        ],
    )?;
    for (ordinal, step_id) in spec.order().iter().enumerate() {
        let step = spec
            .step(step_id)
            .ok_or(PlatformError("workflow_invalid"))?;
        tx.execute(
            "INSERT INTO automation_steps(run_id,step_id,kind,needs,ordinal,status) VALUES(?1,?2,?3,?4,?5,'pending')",
            params![id.to_string(), step.id, step.uses.as_str(), serde_json::to_string(&step.needs)?, ordinal as i64],
        )?;
    }
    run_event(
        tx,
        &id.to_string(),
        "admitted",
        json!({"trigger":input.trigger.as_str(),"actor":input.actor,"definition_version":definition.current_version.0}),
    )?;
    audit(
        tx,
        project.owner_developer_id,
        "automation.triggered",
        Some(input.project_id),
        &id.to_string(),
        input.trigger.as_str(),
    )?;
    let run = read_run(tx, &id.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
    outbox_insert(
        tx,
        &project_id,
        "automation.started",
        &id.to_string(),
        json!({"automation_id":input.automation_id,"run_id":id,"trigger":input.trigger.as_str()}),
        Some(&run),
        &format!("automation.started:{id}"),
    )?;
    Ok(RunAdmission::Created(Box::new(run)))
}

fn definition_changed_materially(old: &WorkflowSpec, new: &WorkflowSpec) -> bool {
    old.policy != new.policy || old.steps != new.steps
}

impl Store {
    pub async fn create_automation(
        &self,
        input: NewAutomation,
    ) -> anyhow::Result<AutomationDefinition> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let (project, _) = require_project(&tx, input.project_id)?;
            if project.owner_developer_id != input.owner {
                return Err(PlatformError("project_not_found").into());
            }
            if project.status != ProjectStatus::Active {
                return Err(PlatformError("project_not_active").into());
            }
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM automation_definitions WHERE project_id=?1",
                [input.project_id.to_string()],
                |r| r.get(0),
            )?;
            if count >= limits.automations_per_project as i64 {
                return Err(PlatformError("automation_limit_exceeded").into());
            }
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM automation_definitions WHERE project_id=?1 AND name=?2)",
                params![input.project_id.to_string(), input.spec.name],
                |r| r.get(0),
            )?;
            if taken {
                return Err(PlatformError("automation_name_taken").into());
            }
            let id = AutomationId::new();
            let now = now_s();
            let spec_json = serde_json::to_string(&input.spec)?;
            tx.execute(
                "INSERT INTO automation_definitions(id,project_id,owner,name,current_version,min_valid_version,created_at,updated_at) VALUES(?1,?2,?3,?4,1,1,?5,?5)",
                params![id.to_string(), input.project_id.to_string(), input.owner.to_string(), input.spec.name, now],
            )?;
            tx.execute(
                "INSERT INTO automation_versions(automation_id,version,spec,spec_sha256,created_at,created_by) VALUES(?1,1,?2,?3,?4,?5)",
                params![id.to_string(), spec_json, workflow::spec_sha256(&input.spec), now, input.owner.to_string()],
            )?;
            install_schedules(&tx, &id.to_string(), 1, &input.spec)?;
            audit(&tx, input.owner, "automation.created", Some(input.project_id), &id.to_string(), "succeeded")?;
            let definition = read_definition(&tx, &input.project_id.to_string(), &id.to_string())?
                .ok_or(PlatformError("automation_not_found"))?;
            tx.commit()?;
            Ok(definition)
        })
        .await
    }
    pub async fn automations(
        &self,
        project: ProjectId,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<AutomationDefinition>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM automation_definitions WHERE project_id=?1 ORDER BY created_at, id LIMIT ?2 OFFSET ?3")?
                .query_map(params![project.to_string(), limit as i64, offset as i64], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids.iter()
                .map(|id| read_definition(db, &project.to_string(), id)?.ok_or_else(|| anyhow::anyhow!("automation vanished")))
                .collect()
        })
        .await
    }
    pub async fn automation(
        &self,
        project: ProjectId,
        id: AutomationId,
    ) -> anyhow::Result<Option<AutomationDefinition>> {
        self.run(move |db| read_definition(db, &project.to_string(), &id.to_string()))
            .await
    }
    pub async fn update_automation(
        &self,
        project: ProjectId,
        id: AutomationId,
        owner: DeveloperId,
        patch: AutomationPatch,
    ) -> anyhow::Result<AutomationDefinition> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let (p, _) = require_project(&tx, project)?;
            if p.owner_developer_id != owner {
                return Err(PlatformError("project_not_found").into());
            }
            if p.status == ProjectStatus::Archived {
                return Err(PlatformError("project_not_active").into());
            }
            let current = read_definition(&tx, &project.to_string(), &id.to_string())?
                .ok_or(PlatformError("automation_not_found"))?;
            let old_spec = spec_of(&current.spec.to_string())?;
            let mut version = current.current_version.0;
            let mut min_valid = current.min_valid_version.0;
            let mut name = current.name.clone();
            let mut action = "automation.updated";
            if let Some(spec) = &patch.spec {
                if spec.name != current.name {
                    let taken: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM automation_definitions WHERE project_id=?1 AND name=?2 AND id<>?3)",
                        params![project.to_string(), spec.name, id.to_string()],
                        |r| r.get(0),
                    )?;
                    if taken {
                        return Err(PlatformError("automation_name_taken").into());
                    }
                }
                if spec != &old_spec {
                    version += 1;
                    name = spec.name.clone();
                    // A material change invalidates the publishing rights of older in-flight runs.
                    if definition_changed_materially(&old_spec, spec) {
                        min_valid = version;
                    }
                    tx.execute(
                        "INSERT INTO automation_versions(automation_id,version,spec,spec_sha256,created_at,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
                        params![id.to_string(), version, serde_json::to_string(spec)?, workflow::spec_sha256(spec), now_s(), owner.to_string()],
                    )?;
                    install_schedules(&tx, &id.to_string(), version, spec)?;
                }
            }
            let enabled = patch.enabled.unwrap_or(current.enabled);
            if !enabled && current.enabled {
                action = "automation.disabled";
                // Disabling is a material change: in-flight runs may not publish or promote.
                min_valid = min_valid.max(version + 1);
                version += 1;
                let spec_now = patch.spec.clone().unwrap_or(old_spec.clone());
                tx.execute(
                    "INSERT INTO automation_versions(automation_id,version,spec,spec_sha256,created_at,created_by) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![id.to_string(), version, serde_json::to_string(&spec_now)?, workflow::spec_sha256(&spec_now), now_s(), owner.to_string()],
                )?;
            }
            let schedules_enabled = patch.schedules_enabled.unwrap_or(current.schedules_enabled);
            tx.execute(
                "UPDATE automation_definitions SET name=?2,enabled=?3,schedules_enabled=?4,current_version=?5,min_valid_version=?6,updated_at=?7 WHERE id=?1",
                params![id.to_string(), name, enabled, schedules_enabled, version, min_valid, now_s()],
            )?;
            if enabled && !current.enabled {
                // Re-enabling restarts schedules from now; missed occurrences are not replayed.
                let spec_now = patch.spec.clone().unwrap_or(old_spec);
                install_schedules(&tx, &id.to_string(), version, &spec_now)?;
            }
            audit(&tx, owner, action, Some(project), &id.to_string(), "succeeded")?;
            let definition = read_definition(&tx, &project.to_string(), &id.to_string())?
                .ok_or(PlatformError("automation_not_found"))?;
            tx.commit()?;
            Ok(definition)
        })
        .await
    }

    pub async fn admit_run(&self, input: AdmitRun) -> anyhow::Result<RunAdmission> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            let result = admit_run_in(&tx, &limits, &input)?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
    /// Verified push/tag webhook: admit every enabled matching automation. Each run is
    /// idempotent by `(automation, delivery)`, so GitHub redelivery and crashes cannot duplicate it.
    pub async fn admit_webhook_runs(
        &self,
        project: ProjectId,
        delivery: String,
        tag: bool,
        name: String,
        source_ref: String,
        commit: Option<String>,
    ) -> anyhow::Result<Vec<RunAdmission>> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM automation_definitions WHERE project_id=?1 AND enabled=1 ORDER BY created_at")?
                .query_map([project.to_string()], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let mut out = vec![];
            for id in ids {
                let Some(definition) = read_definition(db, &project.to_string(), &id)? else { continue };
                let Ok(spec) = spec_of(&definition.spec.to_string()) else { continue };
                let matched = if tag { workflow::matches_tag(&spec, &name) } else { workflow::matches_push(&spec, &name) };
                if !matched {
                    continue;
                }
                let input = AdmitRun {
                    project_id: project,
                    automation_id: id.parse()?,
                    trigger: if tag { AutomationTrigger::Tag } else { AutomationTrigger::Push },
                    trigger_key: format!("delivery:{delivery}"),
                    trigger_detail: json!({"provider":"github","delivery_id":delivery,"ref":source_ref}),
                    source_ref: Some(source_ref.clone()),
                    source_commit: commit.clone(),
                    fresh_build: false,
                    chain_depth: 0,
                    correlation_id: None,
                    expected_owner: None,
                    actor: "webhook:github".into(),
                };
                let tx = db.transaction()?;
                match admit_run_in(&tx, &limits, &input) {
                    Ok(result) => {
                        tx.commit()?;
                        out.push(result);
                    }
                    Err(e) if e.downcast_ref::<PlatformError>().is_some() => {
                        // One automation's limit must not drop the others or fail the webhook.
                        drop(tx);
                        tracing::warn!(project_id=%project, automation_id=%id, code=%e, "Automation was not admitted for webhook");
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(out)
        })
        .await
    }

    pub async fn run_context(&self, id: AutomationRunId) -> anyhow::Result<Option<RunContext>> {
        self.run(move |db| {
            let Some(run) = read_run(db, &id.to_string())? else {
                return Ok(None);
            };
            let (owner, spec, fresh): (String, String, bool) = db.query_row(
                "SELECT owner,spec,fresh_build FROM automation_runs WHERE id=?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            Ok(Some(RunContext {
                run,
                owner: owner.parse()?,
                spec: spec_of(&spec)?,
                fresh_build: fresh,
            }))
        })
        .await
    }
    pub async fn automation_run(
        &self,
        project: ProjectId,
        id: AutomationRunId,
    ) -> anyhow::Result<Option<AutomationRun>> {
        self.run(move |db| Ok(read_run(db, &id.to_string())?.filter(|r| r.project_id == project)))
            .await
    }
    pub async fn automation_runs(
        &self,
        project: ProjectId,
        automation: Option<AutomationId>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<AutomationRun>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT id FROM automation_runs WHERE project_id=?1 AND (?2 IS NULL OR automation_id=?2) ORDER BY rowid DESC LIMIT ?3 OFFSET ?4")?
                .query_map(params![project.to_string(), automation.map(|a| a.to_string()), limit as i64, offset as i64], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids.iter()
                .map(|id| read_run(db, id)?.ok_or_else(|| anyhow::anyhow!("run vanished")))
                .collect()
        })
        .await
    }
    pub async fn automation_run_events(
        &self,
        run: AutomationRunId,
        limit: usize,
    ) -> anyhow::Result<Vec<Value>> {
        self.run(move |db| {
            let rows = db
                .prepare("SELECT id,at,kind,detail FROM automation_run_events WHERE run_id=?1 ORDER BY id DESC LIMIT ?2")?
                .query_map(params![run.to_string(), limit as i64], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows
                .into_iter()
                .map(|(id, at, kind, detail)| json!({"id":id,"at":at,"kind":kind,"detail":serde_json::from_str::<Value>(&detail).unwrap_or(Value::Null)}))
                .collect())
        })
        .await
    }
    pub async fn active_run_ids(&self, limit: usize) -> anyhow::Result<Vec<AutomationRunId>> {
        self.run(move |db| {
            db.prepare("SELECT id FROM automation_runs WHERE status NOT IN ('completed','failed','cancelled') ORDER BY rowid LIMIT ?1")?
                .query_map([limit as i64], |r| r.get::<_, String>(0))?
                .map(|r| Ok(r?.parse()?))
                .collect()
        })
        .await
    }
    pub async fn automation_ready(&self) -> bool {
        self.run(|db| {
            db.query_row("SELECT count(*) FROM automation_runs WHERE status NOT IN ('completed','failed','cancelled')", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        })
        .await
        .is_ok()
    }

    /// Update one step. Transitions are validated; terminal steps never change.
    pub async fn step_patch(
        &self,
        run: AutomationRunId,
        step: String,
        patch: StepPatch,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let current: String = tx.query_row(
                "SELECT status FROM automation_steps WHERE run_id=?1 AND step_id=?2",
                params![run.to_string(), step],
                |r| r.get(0),
            )?;
            let current: AutomationStepStatus = current.parse().map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?;
            let next = patch.status.unwrap_or(current);
            if !current.can_transition_to(next) {
                return Err(PlatformError("invalid_step_transition").into());
            }
            let now = now_s();
            tx.execute(
                "UPDATE automation_steps SET status=?3,started_at=COALESCE(started_at,CASE WHEN ?3<>'pending' THEN ?4 END),finished_at=CASE WHEN ?5 THEN ?4 ELSE finished_at END,output=COALESCE(?6,output),error_code=COALESCE(?7,error_code),error_message=COALESCE(?8,error_message),attempts=attempts+?9 WHERE run_id=?1 AND step_id=?2",
                params![
                    run.to_string(), step, next.as_str(), now, next.is_terminal(),
                    patch.output.map(|o| o.to_string()),
                    patch.error.as_ref().map(|e| e.0.clone()),
                    patch.error.as_ref().map(|e| e.1.clone()),
                    patch.bump_attempt as i64
                ],
            )?;
            if let Some(next_at) = patch.next_attempt_at {
                tx.execute(
                    "UPDATE automation_steps SET next_attempt_at=?3 WHERE run_id=?1 AND step_id=?2",
                    params![run.to_string(), step, next_at.map(|t| t.to_rfc3339())],
                )?;
            }
            if next != current {
                run_event(&tx, &run.to_string(), "step", json!({"step":step,"status":next.as_str()}))?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Move the run to `status`, recording terminal outcome, history, audit and events atomically.
    pub async fn run_transition(
        &self,
        id: AutomationRunId,
        status: AutomationRunStatus,
        current_step: Option<String>,
        error: Option<AutomationFailure>,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let run = read_run(&tx, &id.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
            if run.status == status && run.current_step == current_step && error.is_none() {
                return Ok(());
            }
            if run.status.is_terminal() {
                return Ok(());
            }
            if !run.status.can_transition_to(status) {
                return Err(PlatformError("invalid_run_transition").into());
            }
            if status == AutomationRunStatus::Completed {
                let open: i64 = tx.query_row(
                    "SELECT count(*) FROM automation_steps WHERE run_id=?1 AND status NOT IN ('succeeded','skipped')",
                    [id.to_string()],
                    |r| r.get(0),
                )?;
                if open > 0 {
                    return Err(PlatformError("invalid_run_transition").into());
                }
            }
            let now = now_s();
            tx.execute(
                "UPDATE automation_runs SET status=?2,current_step=?3,updated_at=?4,started_at=COALESCE(started_at,CASE WHEN ?2<>'queued' THEN ?4 END),finished_at=CASE WHEN ?5 THEN ?4 ELSE finished_at END,error_code=COALESCE(?6,error_code),error_message=COALESCE(?7,error_message),error_retryable=COALESCE(?8,error_retryable) WHERE id=?1",
                params![
                    id.to_string(), status.as_str(), current_step, now, status.is_terminal(),
                    error.as_ref().map(|e| e.code.clone()), error.as_ref().map(|e| e.message.clone()), error.as_ref().map(|e| e.retryable)
                ],
            )?;
            if run.status != status {
                run_event(&tx, &id.to_string(), "run", json!({"status":status.as_str(),"step":current_step}))?;
            }
            if status.is_terminal() {
                let owner: String = tx.query_row("SELECT owner FROM automation_runs WHERE id=?1", [id.to_string()], |r| r.get(0))?;
                let owner: DeveloperId = owner.parse()?;
                let (action, event) = match status {
                    AutomationRunStatus::Completed => ("automation.completed", Some("automation.completed")),
                    AutomationRunStatus::Failed => ("automation.failed", Some("automation.failed")),
                    _ => ("automation.cancelled", None),
                };
                audit(&tx, owner, action, Some(run.project_id), &id.to_string(), status.as_str())?;
                if let Some(event) = event {
                    let mut data = json!({"automation_id":run.automation_id,"run_id":id,"status":status.as_str(),"build_id":run.build_id,"source_commit":run.source_commit});
                    if let Some(e) = &error {
                        data["error_code"] = json!(e.code);
                    }
                    outbox_insert(&tx, &run.project_id.to_string(), event, &id.to_string(), data, Some(&run), &format!("{event}:{id}"))?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn cancel_run(
        &self,
        project: ProjectId,
        id: AutomationRunId,
        actor: DeveloperId,
    ) -> anyhow::Result<AutomationRun> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let run = read_run(&tx, &id.to_string())?
                .filter(|r| r.project_id == project)
                .ok_or(PlatformError("automation_run_not_found"))?;
            if !run.status.is_terminal() {
                tx.execute(
                    "UPDATE automation_runs SET cancel_requested=1,updated_at=?2 WHERE id=?1",
                    params![id.to_string(), now_s()],
                )?;
                run_event(
                    &tx,
                    &id.to_string(),
                    "cancel_requested",
                    json!({"by":actor.to_string()}),
                )?;
                audit(
                    &tx,
                    actor,
                    "automation.cancel_requested",
                    Some(project),
                    &id.to_string(),
                    "requested",
                )?;
            }
            let run =
                read_run(&tx, &id.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
            tx.commit()?;
            Ok(run)
        })
        .await
    }
    /// Operator/automatic cancellation of every active run, e.g. when a project is archived.
    pub async fn request_cancel_project_runs(
        &self,
        project: ProjectId,
        reason: &'static str,
    ) -> anyhow::Result<usize> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let ids: Vec<String> = tx
                .prepare("SELECT id FROM automation_runs WHERE project_id=?1 AND status NOT IN ('completed','failed','cancelled') AND cancel_requested=0")?
                .query_map([project.to_string()], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            for id in &ids {
                tx.execute("UPDATE automation_runs SET cancel_requested=1,updated_at=?2 WHERE id=?1", params![id, now_s()])?;
                run_event(&tx, id, "cancel_requested", json!({"reason":reason}))?;
            }
            tx.commit()?;
            Ok(ids.len())
        })
        .await
    }

    /// Stop an automation-created source event that has not started resolving, so no build appears.
    pub async fn ignore_unstarted_source(&self, event: SourceEventId) -> anyhow::Result<bool> {
        self.run(move |db| {
            Ok(db.execute(
                "UPDATE source_events SET status='ignored',record=json_set(record,'$.status','ignored','$.processed_at',?2) WHERE id=?1 AND status='queued' AND intent_key LIKE 'automation-run:%'",
                params![event.to_string(), now_s()],
            )? == 1)
        })
        .await
    }
    pub async fn bind_run_commit(&self, id: AutomationRunId, commit: String) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let current: Option<String> = tx.query_row(
                "SELECT source_commit FROM automation_runs WHERE id=?1",
                [id.to_string()],
                |r| r.get(0),
            )?;
            match current {
                None => {
                    tx.execute(
                        "UPDATE automation_runs SET source_commit=?2 WHERE id=?1",
                        params![id.to_string(), commit],
                    )?;
                    tx.commit()?;
                    Ok(())
                }
                Some(existing) if existing == commit => Ok(()),
                Some(_) => Err(PlatformError("source_commit_changed").into()),
            }
        })
        .await
    }

    /// Atomically bind the run to a source event/build: reuse an equivalent in-flight or
    /// successful build of the same commit, or admit exactly one new M3 source event.
    pub async fn bind_source_for_run(
        &self,
        id: AutomationRunId,
        reuse: bool,
    ) -> anyhow::Result<BuildBinding> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let run = read_run(&tx, &id.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
            let (owner, fresh): (String, bool) = tx.query_row("SELECT owner,fresh_build FROM automation_runs WHERE id=?1", [id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            if let (Some(event), Some(build)) = (run.source_event_id, run.build_id) {
                return Ok(BuildBinding { source_event_id: event, build_id: build, reused: false, created: false, already_bound: true });
            }
            if run.cancel_requested || run.status.is_terminal() {
                return Err(PlatformError("automation_cancelled").into());
            }
            let commit = run.source_commit.clone().ok_or(PlatformError("source_commit_unresolved"))?;
            let (project, active) = require_project(&tx, run.project_id)?;
            if project.status != ProjectStatus::Active || !active {
                return Err(PlatformError("project_not_active").into());
            }
            let found: Option<(String, String)> = if reuse && !fresh {
                tx.query_row(
                    "SELECT e.id,e.build_id FROM source_events e LEFT JOIN builds b ON b.id=e.build_id WHERE e.project_id=?1 AND json_extract(e.record,'$.revision.commit')=?2 AND (e.status IN ('queued','resolving','fetching','handoff') OR (e.status='completed' AND b.status IN ('queued','validating','building','succeeded'))) ORDER BY e.rowid DESC LIMIT 1",
                    params![run.project_id.to_string(), commit],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
            } else {
                None
            };
            let (event, build, reused, created) = if let Some((event, build)) = found {
                (event.parse::<SourceEventId>()?, build.parse::<BuildId>()?, true, false)
            } else {
                let admission = SourceAdmission {
                    project_id: run.project_id,
                    owner: Some(owner.parse()?),
                    trigger: TriggerType::Automation,
                    source_ref: run.source_ref.clone().unwrap_or_else(|| project.settings.default_branch.clone()),
                    commit: Some(commit.clone()),
                    webhook: None,
                    intent_key: Some(format!("automation-run:{id}")),
                    skip_auto_publish: true,
                };
                match admit_source_in(&tx, admission, false)? {
                    Admission::Created(event) => (event.id, event.build_id, false, true),
                    Admission::Duplicate(Some(event)) => {
                        let build: String = tx.query_row("SELECT build_id FROM source_events WHERE id=?1", [event.to_string()], |r| r.get(0))?;
                        (event, build.parse()?, false, false)
                    }
                    _ => return Err(PlatformError("project_not_active").into()),
                }
            };
            tx.execute(
                "UPDATE automation_runs SET source_event_id=?2,build_id=?3,updated_at=?4 WHERE id=?1",
                params![id.to_string(), event.to_string(), build.to_string(), now_s()],
            )?;
            run_event(&tx, &id.to_string(), "source_bound", json!({"source_event_id":event,"build_id":build,"reused":reused}))?;
            tx.commit()?;
            Ok(BuildBinding { source_event_id: event, build_id: build, reused, created, already_bound: false })
        })
        .await
    }
    pub async fn bind_publication(
        &self,
        id: AutomationRunId,
        channel: RepositoryChannel,
        publication: PublishId,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let column = match channel {
                RepositoryChannel::Beta => "beta_publication_id",
                RepositoryChannel::Stable => "stable_publication_id",
                _ => anyhow::bail!(PlatformError("invalid_request")),
            };
            let changed = db.execute(
                &format!("UPDATE automation_runs SET {column}=?2,updated_at=?3 WHERE id=?1 AND ({column} IS NULL OR {column}=?2)"),
                params![id.to_string(), publication.to_string(), now_s()],
            )?;
            anyhow::ensure!(changed == 1, PlatformError("publication_binding_conflict"));
            Ok(())
        })
        .await
    }
    pub async fn record_run_event(
        &self,
        id: AutomationRunId,
        kind: &'static str,
        detail: Value,
    ) -> anyhow::Result<()> {
        self.run(move |db| run_event(db, &id.to_string(), kind, detail))
            .await
    }

    /// Current head state used to re-check a run before any publication side effect.
    pub async fn automation_head(
        &self,
        project: ProjectId,
        id: AutomationId,
    ) -> anyhow::Result<Option<(bool, u32, u32)>> {
        self.run(move |db| {
            Ok(db
                .query_row(
                    "SELECT enabled,current_version,min_valid_version FROM automation_definitions WHERE id=?1 AND project_id=?2",
                    params![id.to_string(), project.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?)
        })
        .await
    }
    pub async fn project_state(
        &self,
        project: ProjectId,
    ) -> anyhow::Result<Option<(Project, bool)>> {
        self.run(move |db| match require_project(db, project) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.downcast_ref::<PlatformError>().is_some() => Ok(None),
            Err(e) => Err(e),
        })
        .await
    }
    pub async fn source_event_public(
        &self,
        id: SourceEventId,
    ) -> anyhow::Result<Option<SourceEvent>> {
        self.run(move |db| {
            let raw: Option<String> = db
                .query_row(
                    "SELECT record FROM source_events WHERE id=?1",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
                .transpose()
        })
        .await
    }
    pub async fn attestation_state(
        &self,
        kind: &'static str,
        target: String,
    ) -> anyhow::Result<(bool, Option<String>)> {
        // (verified evidence exists, job state)
        self.run(move |db| {
            let table = if kind == "build" {
                "build_attestations WHERE build_id"
            } else {
                "release_attestations WHERE publication_id"
            };
            let exists: bool = db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table}=?1)"),
                [&target],
                |r| r.get(0),
            )?;
            let job: Option<String> = db
                .query_row(
                    "SELECT state FROM attestation_jobs WHERE kind=?1 AND target_id=?2",
                    params![kind, target],
                    |r| r.get(0),
                )
                .optional()?;
            Ok((exists, job))
        })
        .await
    }
    /// `(release_security.status, vulnerabilities_status, permission_severity, job state, max finding severity rank)`.
    pub async fn security_state(&self, publication: PublishId) -> anyhow::Result<SecurityState> {
        self.run(move |db| {
            let id = publication.to_string();
            let summary: Option<(String, String, String)> = db
                .query_row(
                    "SELECT status,vulnerabilities_status,permission_severity FROM release_security WHERE publication_id=?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let job: Option<String> = db
                .query_row("SELECT state FROM security_jobs WHERE publication_id=?1", [&id], |r| r.get(0))
                .optional()?;
            let mut worst = None::<String>;
            let mut q = db.prepare("SELECT severity FROM vulnerability_findings WHERE publication_id=?1")?;
            let rank = |s: &str| match s {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0,
            };
            for s in q.query_map([&id], |r| r.get::<_, String>(0))? {
                let s = s?;
                if worst.as_deref().is_none_or(|w| rank(&s) > rank(w)) {
                    worst = Some(s);
                }
            }
            Ok(SecurityState {
                status: summary.as_ref().map(|s| s.0.clone()),
                vulnerabilities: summary.as_ref().map(|s| s.1.clone()),
                permission_severity: summary.map(|s| s.2),
                job,
                worst_finding: worst,
            })
        })
        .await
    }
    pub async fn moderation_blocks(&self, app_id: String) -> anyhow::Result<Option<String>> {
        let state = self.get_moderation_state(&app_id).await?;
        Ok(state.and_then(|(s, reason, _)| {
            matches!(s, ModerationState::Restricted | ModerationState::Removed).then_some(reason)
        }))
    }

    // ---------------------------------------------------------------- approvals

    pub async fn request_approval(
        &self,
        run: AutomationRunId,
        step: String,
        candidate: ReleaseCandidate,
        expires_in_hours: u64,
        requested_by: String,
    ) -> anyhow::Result<ApprovalRequest> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let tx = db.transaction()?;
            if let Some(existing) = read_approval_for_step(&tx, &run.to_string(), &step)? {
                return Ok(existing);
            }
            let run_row = read_run(&tx, &run.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
            let pending: i64 = tx.query_row(
                "SELECT count(*) FROM automation_approvals WHERE project_id=?1 AND status='requested' AND expires_at>?2",
                params![run_row.project_id.to_string(), now_s()],
                |r| r.get(0),
            )?;
            if pending >= limits.pending_approvals_per_project as i64 {
                return Err(PlatformError("approval_limit_exceeded").into());
            }
            let (owner, _): (String, bool) = tx.query_row("SELECT owner,0 FROM automation_runs WHERE id=?1", [run.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let (project, _) = require_project(&tx, run_row.project_id)?;
            let id = ApprovalId::new();
            let now = Utc::now();
            let expires = now + chrono::Duration::hours(expires_in_hours as i64);
            let candidate_json = serde_json::to_string(&candidate)?;
            let digest = hex(&Sha256::digest(candidate_json.as_bytes()));
            tx.execute(
                "INSERT INTO automation_approvals(id,run_id,step_id,project_id,owner,status,candidate,candidate_sha256,definition_version,project_policy_version,requested_by,requested_at,expires_at) VALUES(?1,?2,?3,?4,?5,'requested',?6,?7,?8,?9,?10,?11,?12)",
                params![
                    id.to_string(), run.to_string(), step, run_row.project_id.to_string(), owner, candidate_json, digest,
                    run_row.definition_version.0, project.policy_version as i64, requested_by, now.to_rfc3339(), expires.to_rfc3339()
                ],
            )?;
            audit(&tx, owner.parse()?, "release.approval_requested", Some(run_row.project_id), &id.to_string(), "requested")?;
            outbox_insert(
                &tx,
                &run_row.project_id.to_string(),
                "automation.approval_required",
                &id.to_string(),
                json!({"approval_id":id,"run_id":run,"build_id":candidate.build_id,"source_commit":candidate.source_commit,"expires_at":expires}),
                Some(&run_row),
                &format!("automation.approval_required:{id}"),
            )?;
            run_event(&tx, &run.to_string(), "approval_requested", json!({"approval_id":id}))?;
            let approval = read_approval(&tx, &id.to_string())?.ok_or(PlatformError("approval_not_found"))?;
            tx.commit()?;
            Ok(approval)
        })
        .await
    }
    pub async fn approval_for_step(
        &self,
        run: AutomationRunId,
        step: String,
    ) -> anyhow::Result<Option<ApprovalRequest>> {
        self.run(move |db| read_approval_for_step(db, &run.to_string(), &step))
            .await
    }
    pub async fn set_approval_status(
        &self,
        id: ApprovalId,
        status: ApprovalStatus,
        reason: &'static str,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let current = read_approval(&tx, &id.to_string())?.ok_or(PlatformError("approval_not_found"))?;
            if !current.status.can_transition_to(status) {
                return Ok(());
            }
            tx.execute(
                "UPDATE automation_approvals SET status=?2,decided_at=?3,reason=COALESCE(reason,?4) WHERE id=?1 AND status='requested'",
                params![id.to_string(), status.as_str(), now_s(), reason],
            )?;
            let owner: String = tx.query_row("SELECT owner FROM automation_approvals WHERE id=?1", [id.to_string()], |r| r.get(0))?;
            audit(&tx, owner.parse()?, &format!("release.approval_{}", status.as_str()), Some(current.project_id), &id.to_string(), reason)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    /// Single use: the approval is consumed by the promote step of the run that requested it.
    pub async fn consume_approval(
        &self,
        id: ApprovalId,
        run: AutomationRunId,
    ) -> anyhow::Result<()> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let a =
                read_approval(&tx, &id.to_string())?.ok_or(PlatformError("approval_not_found"))?;
            if a.run_id != run || a.status != ApprovalStatus::Approved {
                return Err(PlatformError("approval_invalid").into());
            }
            tx.execute(
                "UPDATE automation_approvals SET consumed_at=COALESCE(consumed_at,?2) WHERE id=?1",
                params![id.to_string(), now_s()],
            )?;
            run_event(
                &tx,
                &run.to_string(),
                "approval_consumed",
                json!({"approval_id":id}),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn decide_approval(&self, input: DecideApproval) -> anyhow::Result<ApprovalRequest> {
        self.run(move |db| {
            let tx = db.transaction()?;
            let approval = read_approval(&tx, &input.approval_id.to_string())?.ok_or(PlatformError("approval_not_found"))?;
            let spec_raw: String = tx.query_row("SELECT spec FROM automation_runs WHERE id=?1", [approval.run_id.to_string()], |r| r.get(0))?;
            let spec = spec_of(&spec_raw)?;
            let role = approver_role(&tx, input.actor, input.operator, &approval, &spec)?
                .ok_or(PlatformError("approval_not_found"))?;
            if approval.status != ApprovalStatus::Requested {
                return Err(PlatformError("approval_not_pending").into());
            }
            if approval.expires_at <= Utc::now() {
                tx.execute("UPDATE automation_approvals SET status='expired',decided_at=?2,reason=COALESCE(reason,'expired') WHERE id=?1", params![approval.id.to_string(), now_s()])?;
                tx.commit()?;
                return Err(PlatformError("approval_expired").into());
            }
            let run = read_run(&tx, &approval.run_id.to_string())?.ok_or(PlatformError("automation_run_not_found"))?;
            if run.status.is_terminal() || run.cancel_requested {
                return Err(PlatformError("approval_not_pending").into());
            }
            let (project, active) = require_project(&tx, approval.project_id)?;
            if project.status != ProjectStatus::Active || !active {
                return Err(PlatformError("project_not_active").into());
            }
            if run.build_id != Some(approval.candidate.build_id) || run.source_commit.as_deref() != Some(approval.candidate.source_commit.as_str()) {
                return Err(PlatformError("approval_stale").into());
            }
            let (status, action) = match input.decision {
                ApprovalDecision::Approve => (ApprovalStatus::Approved, "release.approved"),
                ApprovalDecision::Reject => (ApprovalStatus::Rejected, "release.rejected"),
            };
            let reason = input.reason.map(|r| r.chars().take(500).collect::<String>());
            tx.execute(
                "UPDATE automation_approvals SET status=?2,decided_by=?3,decided_role=?4,decided_at=?5,reason=?6 WHERE id=?1 AND status='requested'",
                params![
                    approval.id.to_string(), status.as_str(), input.actor.to_string(),
                    serde_json::to_value(role)?.as_str(), now_s(), reason
                ],
            )?;
            audit(&tx, input.actor, action, Some(approval.project_id), &approval.id.to_string(), status.as_str())?;
            run_event(&tx, &approval.run_id.to_string(), "approval_decided", json!({"approval_id":approval.id,"decision":status.as_str(),"by":input.actor,"role":role}))?;
            let out = read_approval(&tx, &approval.id.to_string())?.ok_or(PlatformError("approval_not_found"))?;
            tx.commit()?;
            Ok(out)
        })
        .await
    }
    pub async fn approvals_for(
        &self,
        actor: DeveloperId,
        operator: bool,
        project: Option<ProjectId>,
        status: Option<ApprovalStatus>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<Vec<ApprovalRequest>> {
        self.run(move |db| {
            let ids: Vec<String> = db
                .prepare("SELECT a.id FROM automation_approvals a JOIN automation_runs r ON r.id=a.run_id WHERE (?1=1 OR a.owner=?2 OR EXISTS(SELECT 1 FROM json_each(json_extract(r.spec,'$.policy.release_approvers')) WHERE value=?2)) AND (?3 IS NULL OR a.project_id=?3) AND (?4 IS NULL OR a.status=?4) ORDER BY a.rowid DESC LIMIT ?5 OFFSET ?6")?
                .query_map(
                    params![operator, actor.to_string(), project.map(|p| p.to_string()), status.map(|s| s.as_str()), limit as i64, offset as i64],
                    |r| r.get(0),
                )?
                .collect::<Result<_, _>>()?;
            ids.iter()
                .map(|id| read_approval(db, id)?.ok_or_else(|| anyhow::anyhow!("approval vanished")))
                .collect()
        })
        .await
    }
    pub async fn approval_visible(
        &self,
        actor: DeveloperId,
        operator: bool,
        id: ApprovalId,
    ) -> anyhow::Result<Option<ApprovalRequest>> {
        self.run(move |db| {
            let Some(approval) = read_approval(db, &id.to_string())? else {
                return Ok(None);
            };
            let spec_raw: String = db.query_row(
                "SELECT spec FROM automation_runs WHERE id=?1",
                [approval.run_id.to_string()],
                |r| r.get(0),
            )?;
            let spec = spec_of(&spec_raw)?;
            Ok(approver_role(db, actor, operator, &approval, &spec)?.map(|_| approval))
        })
        .await
    }

    // ---------------------------------------------------------------- scheduling

    /// Evaluate every due schedule trigger. Each occurrence is admitted at most once because
    /// the run's `schedule:<index>:<occurrence>` key is unique and the cursor advances in the
    /// same transaction.
    pub async fn fire_due_schedules(
        &self,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Vec<AutomationRunId>> {
        let limits = self.automation_limits.clone();
        self.run(move |db| {
            let due: Vec<(String, i64, String)> = db
                .prepare("SELECT t.automation_id,t.trigger_index,t.next_run_at FROM automation_triggers t JOIN automation_definitions d ON d.id=t.automation_id JOIN projects p ON p.id=d.project_id WHERE t.next_run_at<=?1 AND d.enabled=1 AND d.schedules_enabled=1 AND p.status='active' ORDER BY t.next_run_at LIMIT 32")?
                .query_map([now.to_rfc3339()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            let mut started = vec![];
            for (automation, index, next_run_at) in due {
                let tx = db.transaction()?;
                let project: String = tx.query_row("SELECT project_id FROM automation_definitions WHERE id=?1", [&automation], |r| r.get(0))?;
                let Some(definition) = read_definition(&tx, &project, &automation)? else { continue };
                let spec = spec_of(&definition.spec.to_string())?;
                let Some((_, schedule_spec)) = workflow::schedules(&spec).into_iter().find(|(i, _)| *i as i64 == index) else {
                    tx.execute("DELETE FROM automation_triggers WHERE automation_id=?1 AND trigger_index=?2", params![automation, index])?;
                    tx.commit()?;
                    continue;
                };
                let scheduled: DateTime<Utc> = next_run_at.parse()?;
                let decision = schedule::due(schedule_spec, scheduled, now);
                let following = schedule::next_after(schedule_spec, now).unwrap_or(now + chrono::Duration::days(1));
                let occurrence = match decision {
                    Due::Wait => continue,
                    Due::Skip(at) => {
                        audit(&tx, definition_owner(&tx, &automation)?, "automation.schedule_skipped", Some(project.parse()?), &automation, &at.to_rfc3339())?;
                        None
                    }
                    Due::Run(at) => Some(at),
                };
                // Compare-and-set the cursor: whoever advances it owns the occurrence.
                let advanced = tx.execute(
                    "UPDATE automation_triggers SET next_run_at=?4,last_occurrence=COALESCE(?5,last_occurrence) WHERE automation_id=?1 AND trigger_index=?2 AND next_run_at=?3",
                    params![automation, index, next_run_at, following.to_rfc3339(), occurrence.map(|o| o.to_rfc3339())],
                )?;
                if advanced != 1 {
                    continue;
                }
                if let Some(at) = occurrence {
                    let input = AdmitRun {
                        project_id: project.parse()?,
                        automation_id: automation.parse()?,
                        trigger: AutomationTrigger::Schedule,
                        trigger_key: format!("schedule:{index}:{}", at.to_rfc3339()),
                        trigger_detail: json!({"occurrence":at.to_rfc3339(),"trigger_index":index}),
                        source_ref: Some(schedule_spec.source_ref.clone().unwrap_or_else(|| "".into())).filter(|s| !s.is_empty()),
                        source_commit: None,
                        fresh_build: false,
                        chain_depth: 0,
                        correlation_id: None,
                        expected_owner: None,
                        actor: "schedule".into(),
                    };
                    match admit_run_in(&tx, &limits, &input) {
                        Ok(result) => {
                            if result.created() {
                                started.push(result.run().id);
                            }
                            tx.commit()?;
                        }
                        Err(e) if e.downcast_ref::<PlatformError>().is_some() => {
                            tracing::warn!(automation_id=%automation, code=%e, "Scheduled occurrence was not admitted");
                            // Keep the cursor advance but record the refusal; the occurrence is not retried.
                            audit(&tx, definition_owner(&tx, &automation)?, "automation.schedule_refused", Some(project.parse()?), &automation, &e.to_string())?;
                            tx.commit()?;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    tx.commit()?;
                }
            }
            Ok(started)
        })
        .await
    }
    pub async fn next_schedule_times(
        &self,
        automation: AutomationId,
    ) -> anyhow::Result<Vec<(i64, String)>> {
        self.run(move |db| {
            Ok(db
                .prepare("SELECT trigger_index,next_run_at FROM automation_triggers WHERE automation_id=?1 ORDER BY trigger_index")?
                .query_map([automation.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?)
        })
        .await
    }
}

fn definition_owner(db: &Connection, automation: &str) -> anyhow::Result<DeveloperId> {
    let owner: String = db.query_row(
        "SELECT owner FROM automation_definitions WHERE id=?1",
        [automation],
        |r| r.get(0),
    )?;
    Ok(owner.parse()?)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone)]
pub struct BuildBinding {
    pub source_event_id: SourceEventId,
    pub build_id: BuildId,
    pub reused: bool,
    pub created: bool,
    pub already_bound: bool,
}
#[derive(Debug, Clone)]
pub struct SecurityState {
    pub status: Option<String>,
    pub vulnerabilities: Option<String>,
    pub permission_severity: Option<String>,
    pub job: Option<String>,
    pub worst_finding: Option<String>,
}
#[derive(Debug, Clone)]
pub struct DecideApproval {
    pub approval_id: ApprovalId,
    pub actor: DeveloperId,
    pub operator: bool,
    pub decision: ApprovalDecision,
    pub reason: Option<String>,
}

fn approval_columns() -> &'static str {
    "id,run_id,step_id,project_id,status,candidate,candidate_sha256,definition_version,project_policy_version,requested_by,requested_at,expires_at,decided_by,decided_role,decided_at,reason,consumed_at"
}
fn read_approval_for_step(
    db: &Connection,
    run: &str,
    step: &str,
) -> anyhow::Result<Option<ApprovalRequest>> {
    let id: Option<String> = db
        .query_row(
            "SELECT id FROM automation_approvals WHERE run_id=?1 AND step_id=?2",
            params![run, step],
            |r| r.get(0),
        )
        .optional()?;
    id.map(|id| read_approval(db, &id))
        .transpose()
        .map(Option::flatten)
}
fn read_approval(db: &Connection, id: &str) -> anyhow::Result<Option<ApprovalRequest>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        u32,
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = db
        .query_row(
            &format!(
                "SELECT {} FROM automation_approvals WHERE id=?1",
                approval_columns()
            ),
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                    r.get(16)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            id,
            run,
            step,
            project,
            status,
            candidate,
            digest,
            version,
            policy,
            requested_by,
            requested_at,
            expires_at,
            by,
            role,
            at,
            reason,
            consumed,
        )| {
            Ok(ApprovalRequest {
                id: id.parse()?,
                project_id: project.parse()?,
                run_id: run.parse()?,
                step_id: step,
                status: status
                    .parse()
                    .map_err(|e: &str| anyhow::anyhow!(e.to_owned()))?,
                candidate: serde_json::from_str(&candidate)?,
                candidate_sha256: digest,
                definition_version: AutomationVersion(version),
                project_policy_version: policy as u64,
                requested_by,
                requested_at: parse_time(&requested_at)?,
                expires_at: parse_time(&expires_at)?,
                decided_by: by.map(|v| v.parse()).transpose()?,
                decided_role: role
                    .map(|v| serde_json::from_value(Value::String(v)))
                    .transpose()?,
                decided_at: opt_time(at)?,
                reason,
                consumed_at: opt_time(consumed)?,
            })
        },
    )
    .transpose()
}
/// Role under which `actor` may see and decide `approval`. Returns `None` when they have no
/// standing at all (the caller reports "not found").
fn approver_role(
    db: &Connection,
    actor: DeveloperId,
    operator: bool,
    approval: &ApprovalRequest,
    spec: &WorkflowSpec,
) -> anyhow::Result<Option<ApproverRole>> {
    let owner: String = db.query_row(
        "SELECT owner FROM automation_approvals WHERE id=?1",
        [approval.id.to_string()],
        |r| r.get(0),
    )?;
    if owner == actor.to_string() {
        return Ok(Some(ApproverRole::ProjectOwner));
    }
    if spec
        .policy
        .release_approvers
        .iter()
        .any(|a| *a == actor.to_string())
    {
        return Ok(Some(ApproverRole::AuthorizedReleaseApprover));
    }
    if operator {
        return Ok(Some(ApproverRole::Operator));
    }
    Ok(None)
}

/// The kind of every step a spec contains, used when summarizing history.
pub fn step_kind_name(kind: StepKind) -> &'static str {
    kind.as_str()
}
