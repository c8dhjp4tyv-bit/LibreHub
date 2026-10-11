//! Durable outbound webhook delivery: outbox fan-out plus a bounded, retrying sender.
//!
//! Destinations are untrusted. Every attempt validates the URL, resolves it itself, requires
//! all answers to be public and connects only to those pinned addresses (no redirects, no
//! proxy, hard deadlines, bounded bodies).
//!
//! Failure isolation: a delivery attempt is the unit of failure. A task error, panic or
//! cancellation is recorded with a stable category and the attempt is made due again (or
//! terminal once its budget is spent); every other delivery keeps running. Storage errors in
//! the dispatch loop back off and retry. Only corrupt storage degrades this worker, and the
//! process stays up so that other services and operators can still act.
use crate::{
    auth::decrypt_secret_aad,
    integration_store::{DeliveryOutcome, DueDelivery, FinishResult},
    store::Store,
};
use async_trait::async_trait;
use chrono::Utc;
use librehub_automation::{
    retry,
    webhook::{
        self, Destination, DestinationError, DestinationPolicy, Outcome, is_public_ip,
        parse_destination,
    },
};
use librehub_common::DeliveryId;
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub const MAX_ATTEMPTS: u32 = 8;
/// A claimed attempt must finish within this window or be recovered by another task.
pub const LEASE: Duration = Duration::from_secs(120);
/// Recording a result is retried briefly for transient SQLite contention, then left to the lease.
const RESULT_ATTEMPTS: u32 = 3;

#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}
pub struct SystemResolver;
#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .take(16)
            .collect())
    }
}
/// Deterministic resolver for tests, including DNS-rebinding scenarios.
#[derive(Default)]
pub struct StaticResolver {
    pub answers: std::sync::Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
    pub calls: std::sync::Mutex<HashMap<String, usize>>,
}
impl StaticResolver {
    /// Each call to `resolve` consumes the next answer set (the last repeats).
    pub fn set(&self, host: &str, sequence: Vec<Vec<IpAddr>>) {
        self.answers.lock().unwrap().insert(host.into(), sequence);
        self.calls.lock().unwrap().remove(host);
    }
}
#[async_trait]
impl Resolver for StaticResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let n = {
            let mut calls = self.calls.lock().unwrap();
            let n = calls.entry(host.into()).or_default();
            *n += 1;
            *n - 1
        };
        let answers = self.answers.lock().unwrap();
        let sets = answers
            .get(host)
            .ok_or_else(|| std::io::Error::other("NXDOMAIN"))?;
        let set = &sets[n.min(sets.len() - 1)];
        Ok(set.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }
}

/// Resolve with the given resolver and require every address to be public.
pub async fn check_destination(
    raw: &str,
    policy: DestinationPolicy,
    resolver: &dyn Resolver,
) -> Result<(Destination, Vec<SocketAddr>), DestinationError> {
    let destination = parse_destination(raw, policy)?;
    let addresses = if let Some(ip) = destination.literal {
        vec![SocketAddr::new(ip, destination.port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(3),
            resolver.resolve(&destination.host, destination.port),
        )
        .await
        .map_err(|_| DestinationError::Unresolvable)?
        .map_err(|_| DestinationError::Unresolvable)?
    };
    if addresses.is_empty() {
        return Err(DestinationError::Unresolvable);
    }
    if addresses.iter().any(|a| !is_public_ip(a.ip(), policy)) {
        return Err(DestinationError::NonPublicAddress);
    }
    Ok((destination, addresses))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    Response {
        status: u16,
        retry_after: Option<u64>,
    },
    Timeout,
    Connect,
}
#[async_trait]
pub trait Transport: Send + Sync {
    async fn post(
        &self,
        destination: &Destination,
        pinned: &[SocketAddr],
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> TransportResult;
}

pub struct ReqwestTransport {
    extra_root: Option<reqwest::Certificate>,
}
impl ReqwestTransport {
    /// `ca_pem` adds an operator-provided trust anchor (private receivers, test fixtures).
    pub fn new(ca_pem: Option<&[u8]>) -> anyhow::Result<Self> {
        Ok(Self {
            extra_root: ca_pem.map(reqwest::Certificate::from_pem).transpose()?,
        })
    }
}
#[async_trait]
impl Transport for ReqwestTransport {
    async fn post(
        &self,
        destination: &Destination,
        pinned: &[SocketAddr],
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> TransportResult {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent("LibreHub-Webhooks/1");
        if let Some(root) = &self.extra_root {
            builder = builder.add_root_certificate(root.clone());
        }
        if destination.literal.is_none() {
            builder = builder.resolve_to_addrs(&destination.host, pinned);
        }
        let Ok(client) = builder.build() else {
            return TransportResult::Connect;
        };
        let mut request = client.post(destination.url.clone()).body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        match request.send().await {
            Ok(mut response) => {
                let status = response.status().as_u16();
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                // Drain a bounded amount so the connection ends cleanly; never keep the body.
                let mut read = 0;
                while let Ok(Some(chunk)) = response.chunk().await {
                    read += chunk.len();
                    if read > webhook::MAX_RESPONSE_BYTES {
                        break;
                    }
                }
                TransportResult::Response {
                    status,
                    retry_after,
                }
            }
            Err(e) if e.is_timeout() => TransportResult::Timeout,
            Err(_) => TransportResult::Connect,
        }
    }
}

/// Stable, low-cardinality failure categories. They are logged, counted and stored with the
/// delivery, so they never carry destination, payload or secret text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCategory {
    /// A delivery task panicked.
    TaskPanic,
    /// A delivery task was cancelled before it finished.
    TaskCancelled,
    /// SQLite reported busy or locked: transient contention.
    StorageBusy,
    /// The disk is full: transient until an operator frees space.
    StorageFull,
    /// SQLite reported corruption or an unreadable database: operator action is required.
    StorageCorrupt,
    /// Any other SQLite failure.
    Storage,
    /// A non-database error inside the worker.
    Internal,
}
impl FailureCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TaskPanic => "task_panic",
            Self::TaskCancelled => "task_cancelled",
            Self::StorageBusy => "storage_busy",
            Self::StorageFull => "storage_full",
            Self::StorageCorrupt => "storage_corrupt",
            Self::Storage => "storage",
            Self::Internal => "internal",
        }
    }
}
/// Classify a failure by its SQLite cause, which survives `anyhow` context wrapping.
pub fn classify(error: &anyhow::Error) -> FailureCategory {
    use rusqlite::{Error, ErrorCode};
    match error.downcast_ref::<Error>() {
        Some(Error::SqliteFailure(failure, _)) => match failure.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => FailureCategory::StorageBusy,
            ErrorCode::DiskFull => FailureCategory::StorageFull,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => FailureCategory::StorageCorrupt,
            _ => FailureCategory::Storage,
        },
        Some(_) => FailureCategory::Storage,
        None => FailureCategory::Internal,
    }
}

/// Operator-visible state of the outbound worker. It never touches the database, so it stays
/// answerable while storage is struggling.
#[derive(Default)]
pub struct WorkerHealth {
    running: AtomicBool,
    degraded: Mutex<Option<&'static str>>,
    failures: Mutex<BTreeMap<&'static str, u64>>,
}
impl WorkerHealth {
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    /// The reason this worker stopped delivering, when it cannot safely continue.
    pub fn degraded(&self) -> Option<&'static str> {
        *self.degraded.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Failure counts by stable category.
    pub fn failures(&self) -> Vec<(&'static str, u64)> {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(category, count)| (*category, *count))
            .collect()
    }
    fn record(&self, category: FailureCategory) {
        *self
            .failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(category.as_str())
            .or_default() += 1;
    }
    fn degrade(&self, reason: &'static str) {
        *self.degraded.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
    }
}

/// Backoff for a failed dispatch step: 500 ms, doubling, capped at 30 s. A busy database is
/// retried at this pace; it neither spins the worker nor ends it.
fn loop_backoff(failures: u32) -> Duration {
    let millis = 250u64.saturating_mul(1u64 << failures.min(10));
    Duration::from_millis(millis.min(30_000))
}

#[derive(Clone)]
pub struct OutboundWorker {
    pub store: Store,
    pub key: [u8; 32],
    pub transport: Arc<dyn Transport>,
    pub resolver: Arc<dyn Resolver>,
    pub policy: DestinationPolicy,
    pub shutdown: CancellationToken,
    pub wake: Arc<Notify>,
    pub health: Arc<WorkerHealth>,
    pub concurrency: usize,
    pub max_attempts: u32,
    pub backoff_base: Duration,
    /// How long a claimed attempt may stay unfinished before another task recovers it.
    pub lease: Duration,
}
fn jitter() -> f64 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b) as f64 / (u32::MAX as f64 + 1.0)
}

impl OutboundWorker {
    pub fn new(
        store: Store,
        key: [u8; 32],
        transport: Arc<dyn Transport>,
        resolver: Arc<dyn Resolver>,
        policy: DestinationPolicy,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            store,
            key,
            transport,
            resolver,
            policy,
            shutdown,
            wake: Arc::new(Notify::new()),
            health: Arc::new(WorkerHealth::default()),
            concurrency: 4,
            max_attempts: MAX_ATTEMPTS,
            backoff_base: retry::BASE_DELAY,
            lease: LEASE,
        }
    }
    /// Running and not degraded.
    pub fn ready(&self) -> bool {
        self.health.running() && self.health.degraded().is_none()
    }
    /// Runs until shutdown and resolves `Ok` then. Failures are contained inside: nothing here
    /// cancels the shared shutdown token or ends the process.
    pub async fn run(self) -> anyhow::Result<()> {
        self.health.running.store(true, Ordering::Release);
        self.run_loop().await;
        self.health.running.store(false, Ordering::Release);
        Ok(())
    }
    async fn run_loop(&self) {
        let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
        let mut inflight: HashMap<tokio::task::Id, (DeliveryId, u32)> = HashMap::new();
        let mut recovered = false;
        let mut next_prune = Instant::now();
        let mut failing = 0u32;
        loop {
            // Every finished task is settled explicitly, so no task result can end this loop.
            while let Some(joined) = tasks.try_join_next_with_id() {
                self.settle(joined, &mut inflight).await;
            }
            if self.shutdown.is_cancelled() {
                // Bounded: every attempt has connect, read and total deadlines.
                while let Some(joined) = tasks.join_next_with_id().await {
                    self.settle(joined, &mut inflight).await;
                }
                return;
            }
            match self
                .step(&mut tasks, &mut inflight, &mut recovered, &mut next_prune)
                .await
            {
                Ok(busy) => {
                    failing = 0;
                    if !busy {
                        self.idle().await;
                    }
                }
                Err(error) => {
                    let category = classify(&error);
                    self.health.record(category);
                    if category == FailureCategory::StorageCorrupt {
                        tracing::error!(category = category.as_str(), error = %error, "Outbound webhook delivery stopped: the control-plane database is unusable and needs operator action");
                        self.health.degrade(category.as_str());
                        while let Some(joined) = tasks.join_next_with_id().await {
                            self.settle(joined, &mut inflight).await;
                        }
                        self.shutdown.cancelled().await;
                        return;
                    }
                    failing = failing.saturating_add(1);
                    let delay = loop_backoff(failing);
                    tracing::warn!(category = category.as_str(), error = %error, retry_in_ms = delay.as_millis() as u64, "Outbound webhook dispatch step failed; retrying");
                    tokio::select! {
                        _ = self.shutdown.cancelled() => {},
                        _ = tokio::time::sleep(delay) => {},
                    }
                }
            }
        }
    }
    async fn idle(&self) {
        tokio::select! {
            _ = self.shutdown.cancelled() => {},
            _ = self.wake.notified() => {},
            _ = tokio::time::sleep(Duration::from_millis(500)) => {},
        }
    }
    /// One dispatch pass: recovery, outbox admission, lease reclamation, claims and retention.
    /// Returns whether more work may be immediately available.
    async fn step(
        &self,
        tasks: &mut JoinSet<anyhow::Result<()>>,
        inflight: &mut HashMap<tokio::task::Id, (DeliveryId, u32)>,
        recovered: &mut bool,
        next_prune: &mut Instant,
    ) -> anyhow::Result<bool> {
        if !*recovered {
            // Anything that was mid-delivery when the process died is retried: at-least-once.
            self.store.recover_deliveries(self.max_attempts).await?;
            *recovered = true;
        }
        // Attempts abandoned by a panicked, cancelled or unrecorded task become due again.
        self.store
            .reclaim_expired_deliveries(self.max_attempts, self.backoff_base)
            .await?;
        // Outbox -> delivery rows (each event atomically with the cursor).
        let events = self.store.outbox_batch("webhooks", 64).await?;
        let busy = !events.is_empty();
        for event in events {
            self.store
                .fan_out(event, self.store.automation_limits.max_chain_depth)
                .await?;
            crate::fault::barrier(&self.store.data_dir, "after_event_admission").await;
        }
        let free = self.concurrency.saturating_sub(tasks.len());
        if free > 0 {
            for delivery in self.store.claim_deliveries(free, self.lease).await? {
                let (id, attempt) = (delivery.id, delivery.attempt);
                let this = self.clone();
                let handle = tasks.spawn(async move { this.deliver(delivery).await });
                inflight.insert(handle.id(), (id, attempt));
            }
        }
        if Instant::now() >= *next_prune {
            // Retention is best effort: a failed prune must not hold up delivery.
            *next_prune = match self.store.prune_outbox().await {
                Ok(_) => Instant::now() + Duration::from_secs(3600),
                Err(error) => {
                    self.health.record(classify(&error));
                    tracing::warn!(category = classify(&error).as_str(), error = %error, "Outbox retention failed; it will be retried");
                    Instant::now() + Duration::from_secs(60)
                }
            };
        }
        Ok(busy)
    }
    /// Settle one finished delivery task. Every outcome is handled: success, a returned error,
    /// a panic and a cancellation. A failed attempt is recovered with its identity intact.
    async fn settle(
        &self,
        joined: Result<(tokio::task::Id, anyhow::Result<()>), tokio::task::JoinError>,
        inflight: &mut HashMap<tokio::task::Id, (DeliveryId, u32)>,
    ) {
        let (task, category, detail) = match joined {
            Ok((task, Ok(()))) => {
                inflight.remove(&task);
                return;
            }
            Ok((task, Err(error))) => (task, classify(&error), format!("{error:#}")),
            Err(error) if error.is_panic() => (
                error.id(),
                FailureCategory::TaskPanic,
                "delivery task panicked".to_owned(),
            ),
            Err(error) => (
                error.id(),
                FailureCategory::TaskCancelled,
                format!("delivery task ended early: {error}"),
            ),
        };
        self.health.record(category);
        let Some((delivery, attempt)) = inflight.remove(&task) else {
            tracing::error!(
                category = category.as_str(),
                "An unknown outbound delivery task finished"
            );
            return;
        };
        tracing::error!(delivery_id = %delivery, attempt, category = category.as_str(), error = %detail, "Outbound webhook delivery task failed; recovering the attempt");
        let delay = retry::backoff_with(self.backoff_base, attempt, jitter());
        match self
            .store
            .interrupt_delivery(
                delivery,
                attempt,
                category.as_str(),
                self.max_attempts,
                delay,
            )
            .await
        {
            Ok(Some(status)) => {
                tracing::warn!(delivery_id = %delivery, attempt, status = status.as_str(), "Interrupted outbound webhook delivery recovered");
            }
            Ok(None) => {
                tracing::info!(delivery_id = %delivery, attempt, "Interrupted attempt was already superseded");
            }
            Err(error) => {
                // The row stays `delivering`; its lease makes it due once it expires.
                tracing::warn!(delivery_id = %delivery, attempt, category = classify(&error).as_str(), error = %error, "Interrupted outbound webhook delivery left for lease recovery");
            }
        }
    }

    /// One delivery attempt. The row is already marked `delivering` (attempt counted).
    pub async fn deliver(&self, delivery: DueDelivery) -> anyhow::Result<()> {
        let started = Utc::now();
        let clock = Instant::now();
        tracing::info!(delivery_id=%delivery.id, project_id=%delivery.project_id, event_id=%delivery.event_id, attempt=delivery.attempt, "Delivering outbound webhook");
        crate::fault::barrier(&self.store.data_dir, "during_delivery").await;
        let (outcome, status) = self.attempt(&delivery).await;
        let duration_ms = clock.elapsed().as_millis() as u64;
        match self
            .record_result(&delivery, started, duration_ms, status, outcome)
            .await?
        {
            FinishResult::Recorded(delivered) => {
                tracing::info!(delivery_id=%delivery.id, status=delivered.as_str(), "Outbound webhook attempt finished");
            }
            FinishResult::Superseded => {
                tracing::warn!(delivery_id=%delivery.id, attempt=delivery.attempt, "Outbound webhook result superseded by a newer attempt");
            }
        }
        Ok(())
    }
    /// Recording a result retries briefly on transient contention. A result that still cannot
    /// be written leaves the row `delivering`, and the lease then makes it due again.
    async fn record_result(
        &self,
        delivery: &DueDelivery,
        started: chrono::DateTime<Utc>,
        duration_ms: u64,
        status: Option<u16>,
        outcome: DeliveryOutcome,
    ) -> anyhow::Result<FinishResult> {
        let mut tries = 0;
        loop {
            tries += 1;
            match self
                .store
                .finish_delivery(
                    delivery.clone(),
                    started,
                    duration_ms,
                    status,
                    outcome.clone(),
                    self.max_attempts,
                )
                .await
            {
                Ok(result) => return Ok(result),
                Err(error)
                    if tries < RESULT_ATTEMPTS
                        && classify(&error) == FailureCategory::StorageBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(50 << tries)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    async fn attempt(&self, delivery: &DueDelivery) -> (DeliveryOutcome, Option<u16>) {
        let retry = |reason: &'static str, hint: Option<Duration>| {
            let computed = retry::backoff_with(self.backoff_base, delivery.attempt, jitter());
            DeliveryOutcome::Retry {
                reason,
                delay: hint.map_or(computed, |h| h.max(computed)),
            }
        };
        // Revalidate every attempt: DNS may have changed since the subscription was created.
        let (destination, pinned) =
            match check_destination(&delivery.url, self.policy, self.resolver.as_ref()).await {
                Ok(v) => v,
                Err(DestinationError::Unresolvable) => {
                    return (retry("destination_unresolvable", None), None);
                }
                Err(e) => return (DeliveryOutcome::Permanent { reason: e.code() }, None),
            };
        let secret = match decrypt_secret_aad(
            &self.key,
            &delivery.webhook_id.to_string(),
            &delivery.cipher,
        ) {
            Ok(secret) => secret,
            Err(_) => {
                return (
                    DeliveryOutcome::Permanent {
                        reason: "secret_unavailable",
                    },
                    None,
                );
            }
        };
        let timestamp = Utc::now().timestamp();
        let signature = webhook::signature(
            secret.0.as_bytes(),
            timestamp,
            &delivery.id.to_string(),
            &delivery.payload,
        );
        let headers = vec![
            ("Content-Type".into(), "application/json".into()),
            (webhook::SIGNATURE_HEADER.into(), signature),
            (webhook::TIMESTAMP_HEADER.into(), timestamp.to_string()),
            (webhook::DELIVERY_HEADER.into(), delivery.id.to_string()),
            (webhook::EVENT_HEADER.into(), delivery.event_type.clone()),
            (
                webhook::EVENT_ID_HEADER.into(),
                delivery.event_id.to_string(),
            ),
        ];
        match self
            .transport
            .post(&destination, &pinned, headers, delivery.payload.clone())
            .await
        {
            TransportResult::Response {
                status,
                retry_after,
            } => match webhook::classify_status(status, retry_after) {
                Outcome::Delivered => (DeliveryOutcome::Delivered, Some(status)),
                Outcome::Retry {
                    reason,
                    retry_after,
                } => (retry(reason, retry_after), Some(status)),
                Outcome::Permanent { reason } => {
                    (DeliveryOutcome::Permanent { reason }, Some(status))
                }
            },
            TransportResult::Timeout => (retry("timeout", None), None),
            TransportResult::Connect => (retry("connect_error", None), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite(code: rusqlite::ErrorCode) -> anyhow::Error {
        anyhow::Error::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code,
                extended_code: 0,
            },
            None,
        ))
        .context("Database task failed")
    }

    #[test]
    fn storage_failures_are_classified_by_their_sqlite_cause_through_context() {
        use rusqlite::ErrorCode::*;
        assert_eq!(
            classify(&sqlite(DatabaseBusy)),
            FailureCategory::StorageBusy
        );
        assert_eq!(
            classify(&sqlite(DatabaseLocked)),
            FailureCategory::StorageBusy
        );
        assert_eq!(classify(&sqlite(DiskFull)), FailureCategory::StorageFull);
        assert_eq!(
            classify(&sqlite(DatabaseCorrupt)),
            FailureCategory::StorageCorrupt
        );
        assert_eq!(
            classify(&sqlite(NotADatabase)),
            FailureCategory::StorageCorrupt
        );
        assert_eq!(
            classify(&sqlite(ConstraintViolation)),
            FailureCategory::Storage
        );
        assert_eq!(
            classify(&anyhow::anyhow!("serde said no")),
            FailureCategory::Internal
        );
    }

    #[test]
    fn loop_backoff_is_bounded_and_never_spins() {
        assert_eq!(loop_backoff(1), Duration::from_millis(500));
        assert!(loop_backoff(2) > loop_backoff(1));
        assert_eq!(loop_backoff(u32::MAX), Duration::from_secs(30));
    }
}
