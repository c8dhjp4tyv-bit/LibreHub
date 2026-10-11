//! The durable workflow supervisor.
//!
//! Every tick re-derives progress from durable M1–M6 state (builds, publications, analysis,
//! attestations, approvals), so a restart at any instant resumes exactly where state says the
//! run is. Steps never perform an action without first recording or re-deriving whether it
//! already happened, and every side effect uses an idempotent M1–M6 admission.
use crate::{
    automation_store::{RunContext, StepPatch},
    platform_store::PlatformError,
    publication_store::AdmissionError,
    publishing::Publishing,
    store::Store,
};
use chrono::Utc;
use librehub_automation::{
    retry::{self, FailureKind, StepFailure},
    workflow::{Channel, SeverityGate, StepKind, StepParams, Unavailable, WorkflowSpec},
};
use librehub_common::*;
use librehub_source::SourceProvider;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::sync::CancellationToken;

/// A run that has not finished after this long is failed rather than left pending forever.
// Allow the maximum 720-hour approval window plus five days for build/security work.
const RUN_DEADLINE: chrono::Duration = chrono::Duration::days(35);

/// What a step reports after one poll.
#[derive(Debug)]
enum StepOutcome {
    Done(Value),
    Skipped(Value),
    Wait(AutomationRunStatus, Value),
    Fail(StepFailure),
}

#[derive(Clone)]
pub struct AutomationWorker {
    pub store: Store,
    pub provider: Arc<dyn SourceProvider>,
    pub publishing: Option<Publishing>,
    pub build_wake: Arc<Notify>,
    pub source_wake: Arc<Notify>,
    pub wake: Arc<Notify>,
    pub shutdown: CancellationToken,
    pub running: Arc<AtomicBool>,
    pub scheduler_enabled: bool,
    pub scheduler_running: Arc<AtomicBool>,
}

fn jitter() -> f64 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b) as f64 / (u32::MAX as f64 + 1.0)
}
fn failure_of(error: anyhow::Error) -> StepFailure {
    if let Some(e) = error.downcast_ref::<PlatformError>() {
        return StepFailure {
            kind: retry::classify(e.0),
            code: e.0,
            message: e.0.replace('_', " "),
        };
    }
    tracing::warn!(error=%error, "Automation step hit an unexpected storage error");
    StepFailure::transient(
        "temporarily_unavailable",
        "The operation could not be completed; it will be retried",
    )
}
fn admission_failure(error: anyhow::Error) -> StepFailure {
    if let Some(e) = error.downcast_ref::<AdmissionError>() {
        return match e {
            AdmissionError::SupplyChainDenied => StepFailure::permanent(
                "supply_chain_policy_denied",
                "Supply-chain policy denied publication",
            ),
            AdmissionError::Missing => {
                StepFailure::permanent("build_not_found", "Build does not exist")
            }
            AdmissionError::Ineligible => {
                StepFailure::permanent("build_not_publishable", "Build cannot be published")
            }
            AdmissionError::ApplicationOwned => StepFailure::permanent(
                "application_owned",
                "The application ID belongs to another developer",
            ),
            AdmissionError::Full => {
                StepFailure::transient("publish_queue_full", "The publication queue is full")
            }
            AdmissionError::TooLate => StepFailure::permanent(
                "publication_not_cancellable",
                "Publication cannot be cancelled",
            ),
        };
    }
    failure_of(error)
}

impl AutomationWorker {
    pub fn new(
        store: Store,
        provider: Arc<dyn SourceProvider>,
        publishing: Option<Publishing>,
        build_wake: Arc<Notify>,
        source_wake: Arc<Notify>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            store,
            provider,
            publishing,
            build_wake,
            source_wake,
            wake: Arc::new(Notify::new()),
            shutdown,
            running: Arc::new(AtomicBool::new(false)),
            scheduler_enabled: true,
            scheduler_running: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn ready(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::Release);
        self.scheduler_running
            .store(self.scheduler_enabled, Ordering::Release);
        // Failures are contained in this worker: the shared shutdown token is never cancelled here,
        // so the API and the other workers keep running (see docs/m8-verification.md).
        let result = self.run_inner().await;
        self.running.store(false, Ordering::Release);
        self.scheduler_running.store(false, Ordering::Release);
        result
    }
    async fn run_inner(&self) -> anyhow::Result<()> {
        let concurrency = self.store.automation_limits.step_concurrency.max(1);
        let mut failing = 0u32;
        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }
            match self.tick_once(concurrency).await {
                Ok(()) => failing = 0,
                Err(error) => {
                    let category = crate::outbound_worker::classify(&error);
                    if category == crate::outbound_worker::FailureCategory::StorageCorrupt {
                        // Stop admitting and advancing work until an operator restores the database.
                        tracing::error!(category = category.as_str(), error = %error, "Automation supervisor stopped: the control-plane database is unusable and needs operator action");
                        self.running.store(false, Ordering::Release);
                        self.shutdown.cancelled().await;
                        return Ok(());
                    }
                    failing = failing.saturating_add(1);
                    let delay = crate::outbound_worker::loop_backoff(failing);
                    tracing::warn!(category = category.as_str(), error = %error, retry_in_ms = delay.as_millis() as u64, "Automation supervisor tick failed; retrying");
                    tokio::select! {
                        _ = self.shutdown.cancelled() => {},
                        _ = tokio::time::sleep(delay) => {},
                    }
                    continue;
                }
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => {},
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(750)) => {},
            }
        }
    }
    /// One scheduling pass: schedules, outbox reactions, then every active run (bounded).
    pub async fn tick_once(&self, concurrency: usize) -> anyhow::Result<()> {
        if self.scheduler_enabled {
            for run in self.store.fire_due_schedules(Utc::now()).await? {
                tracing::info!(automation_run_id=%run, "Scheduled automation occurrence admitted");
            }
        }
        self.consume_outbox().await?;
        let ids = self
            .store
            .active_run_ids(self.store.automation_limits.active_runs_global)
            .await?;
        for chunk in ids.chunks(concurrency) {
            let mut tasks = JoinSet::new();
            for id in chunk {
                let this = self.clone();
                let id = *id;
                tasks.spawn(async move { this.advance(id).await });
            }
            while let Some(done) = tasks.join_next().await {
                // Every run's outcome is settled here, including a panic. The run stays active in the
                // store, so the next tick retries it; nothing in one run can end the supervisor.
                match done {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!(error=%e, "Automation run could not be advanced; retried next tick")
                    }
                    Err(e) => {
                        tracing::error!(error=%e, panicked=e.is_panic(), "Automation run task ended unexpectedly; retried next tick")
                    }
                }
            }
        }
        Ok(())
    }
    /// Reacts to durable events: archiving a project cancels its active runs.
    async fn consume_outbox(&self) -> anyhow::Result<()> {
        for event in self.store.outbox_batch("automation", 64).await? {
            if event.event_type == "project.archived" {
                let cancelled = self
                    .store
                    .request_cancel_project_runs(event.project_id, "project_archived")
                    .await?;
                tracing::info!(project_id=%event.project_id, cancelled, "Project archived; automation runs cancelled");
            }
            self.store.advance_outbox("automation", event.seq).await?;
        }
        Ok(())
    }

    async fn advance(&self, id: AutomationRunId) -> anyhow::Result<()> {
        let Some(ctx) = self.store.run_context(id).await? else {
            return Ok(());
        };
        if ctx.run.status.is_terminal() {
            return Ok(());
        }
        let span = tracing::info_span!("automation_run", project_id=%ctx.run.project_id, automation_id=%ctx.run.automation_id, automation_run_id=%id, source_event_id=?ctx.run.source_event_id, build_id=?ctx.run.build_id);
        let _guard = span.enter();
        if ctx.run.cancel_requested {
            return self.finish_cancel(&ctx).await;
        }
        if Utc::now() - ctx.run.created_at > RUN_DEADLINE {
            return self
                .fail_run(
                    &ctx,
                    StepFailure::permanent("run_timeout", "The run exceeded its deadline"),
                )
                .await;
        }
        // Disabled, archived or moderated-away projects admit no further work. Builds already
        // handed to M1 keep running; nothing is claimed to be undone.
        let project = self.store.project_state(ctx.run.project_id).await?;
        if project
            .as_ref()
            .is_none_or(|(p, dev)| p.status != ProjectStatus::Active || !dev)
        {
            return self
                .fail_run(
                    &ctx,
                    StepFailure::permanent("project_not_active", "The project is no longer active"),
                )
                .await;
        }
        if ctx.run.status == AutomationRunStatus::Queued {
            crate::fault::barrier(&self.store.data_dir, "trigger_admitted").await;
            self.store
                .run_transition(id, AutomationRunStatus::Running, None, None)
                .await?;
        }
        // Walk the DAG in order. Steps unlocked by an earlier step in this pass run immediately,
        // independent branches all make progress, and a permanent failure stops the pass.
        let mut satisfied: std::collections::HashSet<String> = ctx
            .run
            .steps
            .iter()
            .filter(|s| {
                matches!(
                    s.status,
                    AutomationStepStatus::Succeeded | AutomationStepStatus::Skipped
                )
            })
            .map(|s| s.id.clone())
            .collect();
        for step_id in ctx.spec.order() {
            let Some(step) = ctx.run.steps.iter().find(|s| s.id == step_id) else {
                continue;
            };
            if step.status == AutomationStepStatus::Failed {
                return Ok(());
            }
            if step.status.is_terminal() || !step.needs.iter().all(|n| satisfied.contains(n)) {
                continue;
            }
            if step.next_attempt_at.is_some_and(|t| t > Utc::now()) {
                // Backing off after a transient failure; revisit later.
                continue;
            }
            // Re-read the step: an earlier step in this pass may have changed run-level bindings.
            let Some(fresh) = self.store.run_context(id).await? else {
                return Ok(());
            };
            let Some(current) = fresh.run.steps.iter().find(|s| s.id == step_id) else {
                continue;
            };
            if fresh.run.cancel_requested || fresh.run.status.is_terminal() {
                return Ok(());
            }
            let outcome = self.execute(&fresh, current).await;
            let finished = matches!(outcome, StepOutcome::Done(_) | StepOutcome::Skipped(_));
            let fatal =
                matches!(&outcome, StepOutcome::Fail(f) if f.kind == FailureKind::Permanent);
            self.apply(&fresh, current, outcome).await?;
            if fatal {
                return Ok(());
            }
            if finished
                && fresh
                    .spec
                    .step(&step_id)
                    .is_some_and(|s| s.uses == StepKind::Build)
            {
                crate::fault::barrier(&self.store.data_dir, "after_build_complete").await;
            }
            if finished {
                satisfied.insert(step_id);
            }
        }
        self.maybe_complete(id).await
    }
    async fn maybe_complete(&self, id: AutomationRunId) -> anyhow::Result<()> {
        let Some(ctx) = self.store.run_context(id).await? else {
            return Ok(());
        };
        if ctx.run.status.is_terminal() {
            return Ok(());
        }
        if ctx.run.steps.iter().all(|s| {
            matches!(
                s.status,
                AutomationStepStatus::Succeeded | AutomationStepStatus::Skipped
            )
        }) {
            self.store
                .run_transition(id, AutomationRunStatus::Completed, None, None)
                .await?;
        }
        Ok(())
    }

    async fn fail_run(&self, ctx: &RunContext, failure: StepFailure) -> anyhow::Result<()> {
        for step in ctx.run.steps.iter().filter(|s| !s.status.is_terminal()) {
            if let Some(approval) = self
                .store
                .approval_for_step(ctx.run.id, step.id.clone())
                .await?
                && approval.status == ApprovalStatus::Requested
            {
                self.store
                    .set_approval_status(approval.id, ApprovalStatus::Cancelled, "run_failed")
                    .await?;
            }
            self.store
                .step_patch(
                    ctx.run.id,
                    step.id.clone(),
                    StepPatch {
                        status: Some(AutomationStepStatus::Skipped),
                        output: Some(json!({"reason":"run_failed"})),
                        ..Default::default()
                    },
                )
                .await
                .ok();
        }
        self.store
            .run_transition(
                ctx.run.id,
                AutomationRunStatus::Failed,
                ctx.run.current_step.clone(),
                Some(AutomationFailure {
                    code: failure.code.into(),
                    message: failure.message,
                    retryable: failure.kind == FailureKind::Transient,
                }),
            )
            .await
    }

    /// Persist a step outcome and the run status it implies.
    async fn apply(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
        outcome: StepOutcome,
    ) -> anyhow::Result<()> {
        let id = ctx.run.id;
        // A step must pass through Running before any other state.
        if step.status == AutomationStepStatus::Pending {
            self.store
                .step_patch(
                    id,
                    step.id.clone(),
                    StepPatch {
                        status: Some(AutomationStepStatus::Running),
                        ..Default::default()
                    },
                )
                .await?;
        }
        match outcome {
            StepOutcome::Done(output) => {
                self.store
                    .step_patch(
                        id,
                        step.id.clone(),
                        StepPatch {
                            status: Some(AutomationStepStatus::Succeeded),
                            output: Some(output),
                            next_attempt_at: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.store
                    .run_transition(
                        id,
                        AutomationRunStatus::Running,
                        Some(step.id.clone()),
                        None,
                    )
                    .await?;
            }
            StepOutcome::Skipped(output) => {
                self.store
                    .step_patch(
                        id,
                        step.id.clone(),
                        StepPatch {
                            status: Some(AutomationStepStatus::Skipped),
                            output: Some(output),
                            next_attempt_at: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.store
                    .run_transition(
                        id,
                        AutomationRunStatus::Running,
                        Some(step.id.clone()),
                        None,
                    )
                    .await?;
            }
            StepOutcome::Wait(status, output) => {
                self.store
                    .step_patch(
                        id,
                        step.id.clone(),
                        StepPatch {
                            status: Some(AutomationStepStatus::Waiting),
                            output: Some(output),
                            next_attempt_at: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.store
                    .run_transition(id, status, Some(step.id.clone()), None)
                    .await?;
            }
            StepOutcome::Fail(failure) if failure.kind == FailureKind::Transient => {
                let attempts = step.attempts + 1;
                if attempts >= retry::MAX_ATTEMPTS {
                    let exhausted = StepFailure::permanent(
                        "retries_exhausted",
                        format!("{} (retries exhausted)", failure.code),
                    );
                    return self.fail_step(ctx, step, exhausted).await;
                }
                let delay = retry::backoff(attempts, jitter());
                tracing::warn!(step_id=%step.id, code=failure.code, attempts, "Transient automation failure; will retry");
                self.store
                    .step_patch(
                        id,
                        step.id.clone(),
                        StepPatch {
                            status: Some(AutomationStepStatus::Waiting),
                            next_attempt_at: Some(Some(
                                Utc::now()
                                    + chrono::Duration::from_std(delay)
                                        .unwrap_or(chrono::Duration::minutes(15)),
                            )),
                            bump_attempt: true,
                            error: Some((failure.code.into(), failure.message)),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.store
                    .record_run_event(
                        id,
                        "step_retry",
                        json!({"step":step.id,"attempt":attempts,"code":failure.code}),
                    )
                    .await?;
            }
            StepOutcome::Fail(failure) => return self.fail_step(ctx, step, failure).await,
        }
        Ok(())
    }
    async fn fail_step(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
        failure: StepFailure,
    ) -> anyhow::Result<()> {
        tracing::warn!(step_id=%step.id, code=failure.code, "Automation step failed");
        self.store
            .step_patch(
                ctx.run.id,
                step.id.clone(),
                StepPatch {
                    status: Some(AutomationStepStatus::Failed),
                    error: Some((failure.code.into(), failure.message.clone())),
                    next_attempt_at: Some(None),
                    ..Default::default()
                },
            )
            .await?;
        // Dependents never run after a failed prerequisite.
        for other in ctx
            .run
            .steps
            .iter()
            .filter(|s| s.id != step.id && !s.status.is_terminal())
        {
            if let Some(approval) = self
                .store
                .approval_for_step(ctx.run.id, other.id.clone())
                .await?
                && approval.status == ApprovalStatus::Requested
            {
                self.store
                    .set_approval_status(approval.id, ApprovalStatus::Cancelled, "upstream_failed")
                    .await?;
            }
            self.store
                .step_patch(
                    ctx.run.id,
                    other.id.clone(),
                    StepPatch {
                        status: Some(AutomationStepStatus::Skipped),
                        output: Some(json!({"reason":"upstream_failed","step":step.id})),
                        ..Default::default()
                    },
                )
                .await
                .ok();
        }
        self.store
            .run_transition(
                ctx.run.id,
                AutomationRunStatus::Failed,
                Some(step.id.clone()),
                Some(AutomationFailure {
                    code: failure.code.into(),
                    message: failure.message,
                    retryable: false,
                }),
            )
            .await
    }

    async fn finish_cancel(&self, ctx: &RunContext) -> anyhow::Result<()> {
        let id = ctx.run.id;
        // Stop the work this run itself started, using the subsystems' own cancellation rules.
        let build_step = ctx.run.steps.iter().find(|s| {
            ctx.spec
                .step(&s.id)
                .is_some_and(|c| c.uses == StepKind::Build)
        });
        let created_build = build_step.is_some_and(|s| s.output["created"] == true);
        if created_build
            && let (Some(event), Some(build)) = (ctx.run.source_event_id, ctx.run.build_id)
        {
            if self.store.get(build).await?.is_none() {
                self.store.ignore_unstarted_source(event).await?;
            } else if self.store.cancel(build).await?.is_some() {
                self.build_wake.notify_one();
            }
        }
        for (channel, publication) in [
            ("beta", ctx.run.beta_publication_id),
            ("stable", ctx.run.stable_publication_id),
        ] {
            if let Some(publication) = publication
                && let Some(record) = self.store.publish_record(publication).await?
                && record.created_at >= ctx.run.created_at
            {
                match self.store.cancel_publication(publication).await {
                    Ok(_) => {}
                    Err(e) if e.downcast_ref::<AdmissionError>().is_some() => {
                        // Past M2's safe cancellation boundary: the release proceeds and is not rolled back.
                        self.store
                            .record_run_event(
                                id,
                                "publication_continues",
                                json!({"channel":channel,"publication_id":publication}),
                            )
                            .await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        for step in ctx.run.steps.iter().filter(|s| !s.status.is_terminal()) {
            if let Some(approval) = self.store.approval_for_step(id, step.id.clone()).await?
                && approval.status == ApprovalStatus::Requested
            {
                self.store
                    .set_approval_status(approval.id, ApprovalStatus::Cancelled, "run_cancelled")
                    .await?;
            }
            self.store
                .step_patch(
                    id,
                    step.id.clone(),
                    StepPatch {
                        status: Some(AutomationStepStatus::Cancelled),
                        ..Default::default()
                    },
                )
                .await
                .ok();
        }
        self.store
            .run_transition(
                id,
                AutomationRunStatus::Cancelled,
                ctx.run.current_step.clone(),
                None,
            )
            .await
    }

    // ------------------------------------------------------------------ steps

    async fn execute(&self, ctx: &RunContext, step: &AutomationStep) -> StepOutcome {
        let Some(spec_step) = ctx.spec.step(&step.id) else {
            return StepOutcome::Fail(StepFailure::permanent(
                "workflow_invalid",
                "Step is not part of the admitted workflow",
            ));
        };
        let Ok(params) = librehub_automation::workflow::step_params(spec_step) else {
            return StepOutcome::Fail(StepFailure::permanent(
                "workflow_invalid",
                "Step parameters are invalid",
            ));
        };
        let result = match params {
            StepParams::Build { reuse_existing } => self.build(ctx, step, reuse_existing).await,
            StepParams::VerifyProvenance => self.verify(ctx).await,
            StepParams::Publish { .. } => self.publish(ctx, step).await,
            StepParams::CheckSecurity {
                fail_on_severity,
                on_unavailable,
                timeout_seconds,
            } => {
                self.security(ctx, step, fail_on_severity, on_unavailable, timeout_seconds)
                    .await
            }
            StepParams::Approval {
                required,
                expires_in_hours,
            } => self.approval(ctx, step, required, expires_in_hours).await,
            StepParams::Promote { .. } => self.promote(ctx, step).await,
        };
        match result {
            Ok(outcome) => outcome,
            Err(failure) => StepOutcome::Fail(failure),
        }
    }

    async fn build(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
        reuse: bool,
    ) -> Result<StepOutcome, StepFailure> {
        let run = &ctx.run;
        let (project, _) = self
            .store
            .project_state(run.project_id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| StepFailure::permanent("project_not_active", "Project is gone"))?;
        // 1. Resolve an immutable commit (the diagram's "Resolve Immutable Git SHA").
        if run.source_commit.is_none() {
            let reference = run
                .source_ref
                .clone()
                .unwrap_or_else(|| project.settings.default_branch.clone());
            if !librehub_source::safe_ref(&reference) {
                return Err(StepFailure::permanent(
                    "invalid_source_ref",
                    "The source ref is not valid",
                ));
            }
            match self
                .provider
                .resolve_revision(&project.repository, &reference)
                .await
            {
                Ok(commit) => self
                    .store
                    .bind_run_commit(run.id, commit)
                    .await
                    .map_err(failure_of)?,
                Err(e) if e.retryable => {
                    return Err(StepFailure::transient(
                        "source_unavailable",
                        "The source provider is temporarily unavailable",
                    ));
                }
                Err(e) => {
                    return Err(StepFailure::permanent(
                        "source_ref_unresolvable",
                        format!("The source ref could not be resolved ({})", e.code),
                    ));
                }
            }
        }
        // 2. Admit (or reuse) exactly one M3 source event for this commit.
        crate::fault::barrier(&self.store.data_dir, "before_source_bind").await;
        let binding = self
            .store
            .bind_source_for_run(run.id, reuse)
            .await
            .map_err(failure_of)?;
        crate::fault::barrier(&self.store.data_dir, "after_build_bound").await;
        if binding.created {
            self.source_wake.notify_one();
        }
        let mut output = if step.output.is_object() {
            step.output.clone()
        } else {
            json!({})
        };
        if !binding.already_bound {
            output["created"] = json!(binding.created);
            output["reused"] = json!(binding.reused);
        }
        output["source_event_id"] = json!(binding.source_event_id);
        output["build_id"] = json!(binding.build_id);
        // 3. Observe the M3 event and M1 build.
        let event = self
            .store
            .source_event_public(binding.source_event_id)
            .await
            .map_err(failure_of)?;
        if let Some(event) = &event {
            if let Some(revision) = &event.revision {
                output["source_commit"] = json!(revision.commit);
            }
            match event.status {
                SourceEventStatus::Failed => {
                    let code = event
                        .error
                        .as_ref()
                        .map_or("unknown".to_owned(), |e| e.code.clone());
                    return Err(StepFailure::permanent(
                        "source_failed",
                        format!("Source processing failed ({code})"),
                    ));
                }
                SourceEventStatus::Ignored => {
                    return Err(StepFailure::permanent(
                        "source_ignored",
                        "The source event was ignored",
                    ));
                }
                _ => {}
            }
        }
        let Some(build) = self.store.get(binding.build_id).await.map_err(failure_of)? else {
            return Ok(StepOutcome::Wait(
                AutomationRunStatus::WaitingForBuild,
                output,
            ));
        };
        match build.status {
            BuildStatus::Succeeded => {
                let provenance = build.provenance.as_ref();
                output["app_id"] = json!(build.manifest.app_id);
                output["snapshot_sha256"] = json!(provenance.map(|p| p.snapshot.sha256.clone()));
                output["build_status"] = json!("succeeded");
                Ok(StepOutcome::Done(output))
            }
            BuildStatus::Failed => Err(StepFailure::permanent("build_failed", "The build failed")),
            BuildStatus::Cancelled => Err(StepFailure::permanent(
                "build_cancelled",
                "The build was cancelled",
            )),
            _ => {
                output["build_status"] = serde_json::to_value(build.status).unwrap_or(Value::Null);
                Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForBuild,
                    output,
                ))
            }
        }
    }

    async fn verify(&self, ctx: &RunContext) -> Result<StepOutcome, StepFailure> {
        let build = ctx.run.build_id.ok_or_else(|| {
            StepFailure::permanent("build_missing", "No build is bound to the run")
        })?;
        let required = ctx.spec.policy.require_valid_build_attestation
            || ctx.spec.policy.require_allowed_builder;
        if self.store.attestor.is_none() {
            return if required {
                Err(StepFailure::permanent(
                    "attestation_unavailable",
                    "Build attestation is required but no attestor is configured",
                ))
            } else {
                Ok(StepOutcome::Skipped(
                    json!({"attestation":"not_configured"}),
                ))
            };
        }
        let (exists, job) = self
            .store
            .attestation_state("build", build.to_string())
            .await
            .map_err(failure_of)?;
        if !exists {
            return if job.as_deref() == Some("failed") {
                Err(StepFailure::permanent(
                    "attestation_failed",
                    "Build provenance could not be created or verified",
                ))
            } else {
                Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForBuild,
                    json!({"attestation":"pending"}),
                ))
            };
        }
        if ctx.spec.policy.require_allowed_builder {
            let decision = self.store.check_supply_policy(build).await.map_err(|_| {
                StepFailure::transient(
                    "temporarily_unavailable",
                    "Supply-chain policy could not be evaluated",
                )
            })?;
            if !decision.violations.is_empty() {
                return Err(StepFailure::permanent(
                    "builder_not_allowed",
                    "The build environment is not allowed by policy",
                ));
            }
        }
        Ok(StepOutcome::Done(
            json!({"attestation":"verified","build_id":build}),
        ))
    }

    /// Re-check everything that could have changed since admission, before any side effect.
    async fn preflight(
        &self,
        ctx: &RunContext,
        channel: Channel,
    ) -> Result<(BuildRecord, Value), StepFailure> {
        let run = &ctx.run;
        let (project, developer_active) = self
            .store
            .project_state(run.project_id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| StepFailure::permanent("project_not_active", "Project is gone"))?;
        if project.owner_developer_id != ctx.owner {
            return Err(StepFailure::permanent(
                "project_not_found",
                "Project ownership changed",
            ));
        }
        if project.status != ProjectStatus::Active || !developer_active {
            return Err(StepFailure::permanent(
                "project_not_active",
                "The project is no longer active",
            ));
        }
        let (enabled, _current, min_valid) = self
            .store
            .automation_head(run.project_id, run.automation_id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| {
                StepFailure::permanent("automation_not_found", "The automation no longer exists")
            })?;
        if !enabled {
            return Err(StepFailure::permanent(
                "automation_disabled",
                "The automation was disabled",
            ));
        }
        if run.definition_version.0 < min_valid {
            return Err(StepFailure::permanent(
                "stale_policy",
                "The automation policy changed after this run was admitted",
            ));
        }
        let build_id = run.build_id.ok_or_else(|| {
            StepFailure::permanent("build_missing", "No build is bound to the run")
        })?;
        let build = self
            .store
            .get(build_id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| StepFailure::permanent("build_missing", "The build no longer exists"))?;
        if build.status != BuildStatus::Succeeded {
            return Err(StepFailure::permanent(
                "build_not_successful",
                "The build did not succeed",
            ));
        }
        if self
            .store
            .build_project(build_id)
            .await
            .map_err(failure_of)?
            != Some(run.project_id)
        {
            return Err(StepFailure::permanent(
                "build_project_mismatch",
                "The build belongs to a different project",
            ));
        }
        let commit = build.provenance.as_ref().map(|p| p.revision.commit.clone());
        if commit.is_none() || commit != run.source_commit {
            return Err(StepFailure::permanent(
                "source_commit_mismatch",
                "The build does not match the run's pinned source commit",
            ));
        }
        let policy = &ctx.spec.policy;
        if policy.require_valid_build_attestation || policy.require_allowed_builder {
            if self.store.attestor.is_none() {
                return Err(StepFailure::permanent(
                    "attestation_unavailable",
                    "Build attestation is required but no attestor is configured",
                ));
            }
            let (exists, _) = self
                .store
                .attestation_state("build", build_id.to_string())
                .await
                .map_err(failure_of)?;
            if !exists {
                return Err(StepFailure::permanent(
                    "attestation_missing",
                    "No verified build attestation exists",
                ));
            }
        }
        // M6: the same policy M2 enforces, evaluated up front so a denial is explicit and attributable.
        if self.store.attestor.is_some() || self.store.supply_policy == SupplyChainPolicy::Enforce {
            let decision = self
                .store
                .check_supply_policy(build_id)
                .await
                .map_err(|_| {
                    StepFailure::transient(
                        "temporarily_unavailable",
                        "Supply-chain policy could not be evaluated",
                    )
                })?;
            if !decision.allowed
                || (policy.require_allowed_builder && !decision.violations.is_empty())
            {
                return Err(StepFailure::permanent(
                    "supply_chain_policy_denied",
                    "Supply-chain policy denied publication",
                ));
            }
        }
        // M5: automation cannot publish an application an operator has restricted or removed.
        if policy.require_no_blocking_moderation
            && let Some(reason) = self
                .store
                .moderation_blocks(build.manifest.app_id.clone())
                .await
                .map_err(failure_of)?
        {
            return Err(StepFailure::permanent(
                "moderation_blocked",
                format!("The application is under moderation ({reason})"),
            ));
        }
        let _ = channel;
        Ok((build.clone(), json!({"app_id":build.manifest.app_id})))
    }

    async fn publication_wait(
        &self,
        id: PublishId,
        build: BuildId,
    ) -> Result<Result<PublishRecord, PublishRecord>, StepFailure> {
        let record = self
            .store
            .publish_record(id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| {
                StepFailure::permanent("publication_missing", "The publication record vanished")
            })?;
        if record.build_id != build {
            return Err(StepFailure::permanent(
                "publication_build_mismatch",
                "The publication belongs to another build",
            ));
        }
        Ok(match record.status {
            PublishStatus::Succeeded => Ok(record),
            _ => Err(record),
        })
    }
    fn publication_output(record: &PublishRecord) -> Value {
        json!({
            "publication_id": record.id, "channel": record.channel, "publication_status": record.status,
            "flatpak_ref": record.result.as_ref().map(|r| r.published_ref.ref_name.to_string()),
            "ostree_commit": record.result.as_ref().map(|r| r.published_ref.commit.clone()),
            "attempts": record.attempts,
        })
    }

    async fn publish(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
    ) -> Result<StepOutcome, StepFailure> {
        let publishing = self.publishing.as_ref().ok_or_else(|| {
            StepFailure::permanent(
                "publishing_disabled",
                "Repository publishing is not configured",
            )
        })?;
        let build_id = ctx.run.build_id.ok_or_else(|| {
            StepFailure::permanent("build_missing", "No build is bound to the run")
        })?;
        let publication = match ctx.run.beta_publication_id {
            Some(id) => id,
            None => {
                self.preflight(ctx, Channel::Beta).await?;
                crate::fault::barrier(&self.store.data_dir, "before_beta_publication").await;
                let record = self
                    .store
                    .enqueue_publish(build_id, RepositoryChannel::Beta)
                    .await
                    .map_err(admission_failure)?;
                self.store
                    .bind_publication(ctx.run.id, RepositoryChannel::Beta, record.id)
                    .await
                    .map_err(failure_of)?;
                crate::fault::barrier(&self.store.data_dir, "after_beta_publication").await;
                publishing.wake.notify_one();
                record.id
            }
        };
        let _ = step;
        match self.publication_wait(publication, build_id).await? {
            Ok(record) => Ok(StepOutcome::Done(Self::publication_output(&record))),
            Err(record) => match record.status {
                PublishStatus::Failed | PublishStatus::Cancelled => Err(StepFailure::permanent(
                    "publication_failed",
                    "The beta publication did not succeed",
                )),
                _ => Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForPublication,
                    Self::publication_output(&record),
                )),
            },
        }
    }

    async fn security(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
        gate: SeverityGate,
        unavailable: Unavailable,
        timeout_seconds: u64,
    ) -> Result<StepOutcome, StepFailure> {
        let publication = ctx.run.beta_publication_id.ok_or_else(|| {
            StepFailure::permanent(
                "publication_missing",
                "No beta publication is bound to the run",
            )
        })?;
        if ctx.spec.policy.require_no_blocking_moderation {
            let build = ctx.run.build_id.ok_or_else(|| {
                StepFailure::permanent("build_missing", "No build is bound to the run")
            })?;
            if let Some(build) = self.store.get(build).await.map_err(failure_of)?
                && let Some(reason) = self
                    .store
                    .moderation_blocks(build.manifest.app_id)
                    .await
                    .map_err(failure_of)?
            {
                return Err(StepFailure::permanent(
                    "moderation_blocked",
                    format!("The application is under moderation ({reason})"),
                ));
            }
        }
        let state = self
            .store
            .security_state(publication)
            .await
            .map_err(failure_of)?;
        let rank = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        let gate_rank = match gate {
            SeverityGate::Never => 99,
            SeverityGate::Critical => 4,
            SeverityGate::High => 3,
            SeverityGate::Medium => 2,
            SeverityGate::Low => 1,
        };
        let summary = json!({"analysis":state.status,"vulnerabilities":state.vulnerabilities,"permission_severity":state.permission_severity,"worst_finding":state.worst_finding});
        // Never turn "no answer" into "clean".
        let outage = |reason: &'static str| -> Result<StepOutcome, StepFailure> {
            let waited = step
                .started_at
                .is_some_and(|t| (Utc::now() - t).num_seconds() > timeout_seconds as i64);
            if unavailable == Unavailable::Fail || waited {
                return Err(StepFailure::permanent(
                    "security_analysis_unavailable",
                    format!("Security analysis is unavailable ({reason})"),
                ));
            }
            Ok(StepOutcome::Wait(
                AutomationRunStatus::WaitingForSecurity,
                json!({"analysis":"unavailable","reason":reason}),
            ))
        };
        match (state.status.as_deref(), state.vulnerabilities.as_deref()) {
            (None, _) | (Some("pending" | "analyzing"), _) => {
                if state.job.as_deref() == Some("failed") {
                    return outage("analysis_failed");
                }
                let waited = step.started_at.is_some_and(|t| {
                    (Utc::now() - t).num_seconds() > (timeout_seconds as i64).saturating_mul(4)
                });
                if waited {
                    return Err(StepFailure::permanent(
                        "security_analysis_timeout",
                        "Security analysis did not finish in time",
                    ));
                }
                Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForSecurity,
                    json!({"analysis":"pending"}),
                ))
            }
            (Some("failed" | "unavailable"), _) => outage("analysis_failed"),
            (Some("ready"), Some("unavailable")) => outage("vulnerability_provider_unavailable"),
            (Some("ready"), Some("vulnerable")) => {
                if state
                    .worst_finding
                    .as_deref()
                    .is_some_and(|w| rank(w) >= gate_rank)
                {
                    Err(StepFailure::permanent(
                        "vulnerability_gate",
                        format!(
                            "Findings at or above the configured severity were reported ({})",
                            state.worst_finding.unwrap_or_default()
                        ),
                    ))
                } else {
                    Ok(StepOutcome::Done(summary))
                }
            }
            (Some("ready"), _) => Ok(StepOutcome::Done(summary)),
            _ => outage("unknown_state"),
        }
    }

    async fn candidate(&self, ctx: &RunContext) -> Result<ReleaseCandidate, StepFailure> {
        let run = &ctx.run;
        let build_id = run.build_id.ok_or_else(|| {
            StepFailure::permanent("build_missing", "No build is bound to the run")
        })?;
        let build = self
            .store
            .get(build_id)
            .await
            .map_err(failure_of)?
            .ok_or_else(|| StepFailure::permanent("build_missing", "The build no longer exists"))?;
        let provenance = build.provenance.clone().ok_or_else(|| {
            StepFailure::permanent(
                "immutable_source_unavailable",
                "The build has no source provenance",
            )
        })?;
        let beta = match run.beta_publication_id {
            Some(id) => self.store.publish_record(id).await.map_err(failure_of)?,
            None => None,
        };
        Ok(ReleaseCandidate {
            project_id: run.project_id,
            automation_id: run.automation_id,
            run_id: run.id,
            definition_version: run.definition_version,
            build_id,
            source_commit: provenance.revision.commit,
            snapshot_sha256: provenance.snapshot.sha256,
            app_id: build.manifest.app_id,
            beta_publication_id: beta.as_ref().map(|b| b.id),
            beta_ostree_commit: beta.and_then(|b| b.result.map(|r| r.published_ref.commit)),
            target_channel: "stable".into(),
        })
    }

    async fn approval(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
        required: bool,
        hours: u64,
    ) -> Result<StepOutcome, StepFailure> {
        if !required {
            return Ok(StepOutcome::Skipped(json!({"approval":"not_required"})));
        }
        let candidate = self.candidate(ctx).await?;
        let requested_by = match ctx.run.trigger {
            AutomationTrigger::Ci => format!(
                "ci:{}",
                ctx.run.trigger_detail["repository_id"]
                    .as_str()
                    .unwrap_or("unknown")
            ),
            other => other.as_str().to_owned(),
        };
        let approval = match self
            .store
            .approval_for_step(ctx.run.id, step.id.clone())
            .await
            .map_err(failure_of)?
        {
            Some(existing) => existing,
            None => {
                // Nothing may be requested for a run whose policy has been superseded.
                self.preflight(ctx, Channel::Stable).await?;
                let requested = self
                    .store
                    .request_approval(
                        ctx.run.id,
                        step.id.clone(),
                        candidate.clone(),
                        hours,
                        requested_by,
                    )
                    .await
                    .map_err(failure_of)?;
                crate::fault::barrier(&self.store.data_dir, "awaiting_approval").await;
                requested
            }
        };
        let summary = json!({"approval_id":approval.id,"approval_status":approval.status,"expires_at":approval.expires_at});
        match approval.status {
            ApprovalStatus::Requested => {
                if approval.expires_at <= Utc::now() {
                    self.store
                        .set_approval_status(approval.id, ApprovalStatus::Expired, "expired")
                        .await
                        .map_err(failure_of)?;
                    return Err(StepFailure::permanent(
                        "approval_expired",
                        "The approval request expired",
                    ));
                }
                Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForApproval,
                    summary,
                ))
            }
            ApprovalStatus::Approved => {
                if !approval_matches(&approval, &candidate, ctx) {
                    self.store
                        .set_approval_status(approval.id, ApprovalStatus::Cancelled, "stale")
                        .await
                        .ok();
                    return Err(StepFailure::permanent(
                        "approval_stale",
                        "The release candidate changed after it was approved",
                    ));
                }
                Ok(StepOutcome::Done(summary))
            }
            ApprovalStatus::Rejected => Err(StepFailure::permanent(
                "approval_rejected",
                "The release was rejected",
            )),
            ApprovalStatus::Expired => Err(StepFailure::permanent(
                "approval_expired",
                "The approval request expired",
            )),
            ApprovalStatus::Cancelled => Err(StepFailure::permanent(
                "approval_cancelled",
                "The approval request was cancelled",
            )),
        }
    }

    async fn promote(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
    ) -> Result<StepOutcome, StepFailure> {
        let publishing = self.publishing.as_ref().ok_or_else(|| {
            StepFailure::permanent(
                "publishing_disabled",
                "Repository publishing is not configured",
            )
        })?;
        let build_id = ctx.run.build_id.ok_or_else(|| {
            StepFailure::permanent("build_missing", "No build is bound to the run")
        })?;
        let publication = match ctx.run.stable_publication_id {
            Some(id) => id,
            None => {
                self.preflight(ctx, Channel::Stable).await?;
                self.authorize_promotion(ctx, step).await?;
                crate::fault::barrier(&self.store.data_dir, "before_stable_publication").await;
                let record = self
                    .store
                    .enqueue_publish(build_id, RepositoryChannel::Stable)
                    .await
                    .map_err(admission_failure)?;
                self.store
                    .bind_publication(ctx.run.id, RepositoryChannel::Stable, record.id)
                    .await
                    .map_err(failure_of)?;
                publishing.wake.notify_one();
                record.id
            }
        };
        match self.publication_wait(publication, build_id).await? {
            Ok(record) => {
                let mut output = Self::publication_output(&record);
                // The stable release gets its own M6 attestation; beta evidence is never reused.
                if self.store.attestor.is_some() {
                    let (exists, job) = self
                        .store
                        .attestation_state("release", publication.to_string())
                        .await
                        .map_err(failure_of)?;
                    if exists {
                        output["attestation_status"] = json!("verified");
                    } else if job.as_deref() == Some("failed") {
                        output["attestation_status"] = json!("failed");
                        return Err(StepFailure::permanent(
                            "release_attestation_failed",
                            "The stable release was published but its attestation could not be verified; the publication is not rolled back",
                        ));
                    } else {
                        output["attestation_status"] = json!("pending");
                        return Ok(StepOutcome::Wait(
                            AutomationRunStatus::WaitingForPublication,
                            output,
                        ));
                    }
                } else {
                    output["attestation_status"] = json!("not_configured");
                }
                Ok(StepOutcome::Done(output))
            }
            Err(record) => match record.status {
                PublishStatus::Failed | PublishStatus::Cancelled => Err(StepFailure::permanent(
                    "publication_failed",
                    "The stable publication did not succeed",
                )),
                _ => Ok(StepOutcome::Wait(
                    AutomationRunStatus::WaitingForPublication,
                    Self::publication_output(&record),
                )),
            },
        }
    }

    /// All gates between "a candidate exists" and "stable publication may be admitted".
    async fn authorize_promotion(
        &self,
        ctx: &RunContext,
        step: &AutomationStep,
    ) -> Result<(), StepFailure> {
        let policy = &ctx.spec.policy;
        if policy.require_successful_beta_publication {
            let beta = ctx.run.beta_publication_id.ok_or_else(|| {
                StepFailure::permanent(
                    "beta_not_published",
                    "Beta publication is required before promotion",
                )
            })?;
            let record = self.store.publish_record(beta).await.map_err(failure_of)?;
            if record.is_none_or(|r| {
                r.status != PublishStatus::Succeeded || Some(r.build_id) != ctx.run.build_id
            }) {
                return Err(StepFailure::permanent(
                    "beta_not_published",
                    "A successful beta publication of this build is required",
                ));
            }
        }
        if policy.require_security_analysis_complete {
            let beta = ctx.run.beta_publication_id.ok_or_else(|| {
                StepFailure::permanent(
                    "security_analysis_incomplete",
                    "Security analysis is required",
                )
            })?;
            let state = self.store.security_state(beta).await.map_err(failure_of)?;
            if state.status.as_deref() != Some("ready")
                || state.vulnerabilities.as_deref() == Some("unavailable")
            {
                return Err(StepFailure::permanent(
                    "security_analysis_incomplete",
                    "Security analysis has not completed",
                ));
            }
        }
        let approval_step = ctx
            .spec
            .ancestors(&step.id)
            .into_iter()
            .filter_map(|a| ctx.spec.step(&a).map(|s| (a, s.uses)))
            .find(|(_, kind)| *kind == StepKind::Approval)
            .map(|(id, _)| id);
        let approval = match &approval_step {
            Some(approval_step) => self
                .store
                .approval_for_step(ctx.run.id, approval_step.clone())
                .await
                .map_err(failure_of)?,
            None => None,
        };
        match approval {
            Some(approval) => {
                if approval.status != ApprovalStatus::Approved {
                    return Err(StepFailure::permanent(
                        "approval_required",
                        "An approved release is required",
                    ));
                }
                let candidate = self.candidate(ctx).await?;
                if !approval_matches(&approval, &candidate, ctx) {
                    return Err(StepFailure::permanent(
                        "approval_stale",
                        "The release candidate changed after it was approved",
                    ));
                }
                // Single use. Resuming the same step after a crash finds it already consumed.
                self.store
                    .consume_approval(approval.id, ctx.run.id)
                    .await
                    .map_err(failure_of)?;
            }
            None => {
                // A federated CI identity may never be the sole authority behind a stable release.
                if ctx.run.trigger == AutomationTrigger::Ci || policy.require_manual_approval {
                    return Err(StepFailure::permanent(
                        "approval_required",
                        "Stable promotion requires an approved release",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn approval_matches(
    approval: &ApprovalRequest,
    candidate: &ReleaseCandidate,
    ctx: &RunContext,
) -> bool {
    let live = serde_json::to_vec(candidate)
        .map(|b| {
            Sha256::digest(b)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        })
        .unwrap_or_default();
    approval.candidate_sha256 == live
        && approval.definition_version == ctx.run.definition_version
        && approval.run_id == ctx.run.id
        && approval.project_id == ctx.run.project_id
}

/// Used by tests and the CLI to render workflows without a database.
pub fn describe_steps(spec: &WorkflowSpec) -> Vec<(String, &'static str)> {
    spec.order()
        .into_iter()
        .filter_map(|id| spec.step(&id).map(|s| (id.clone(), s.uses.as_str())))
        .collect()
}
