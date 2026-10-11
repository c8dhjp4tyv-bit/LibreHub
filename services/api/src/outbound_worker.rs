//! Durable outbound webhook delivery: outbox fan-out plus a bounded, retrying sender.
//!
//! Destinations are untrusted. Every attempt validates the URL, resolves it itself, requires
//! all answers to be public and connects only to those pinned addresses (no redirects, no
//! proxy, hard deadlines, bounded bodies).
use crate::{
    auth::decrypt_secret_aad,
    integration_store::{DeliveryOutcome, DueDelivery},
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
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub const MAX_ATTEMPTS: u32 = 8;

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

#[derive(Clone)]
pub struct OutboundWorker {
    pub store: Store,
    pub key: [u8; 32],
    pub transport: Arc<dyn Transport>,
    pub resolver: Arc<dyn Resolver>,
    pub policy: DestinationPolicy,
    pub shutdown: CancellationToken,
    pub wake: Arc<Notify>,
    pub running: Arc<AtomicBool>,
    pub concurrency: usize,
    pub max_attempts: u32,
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
            running: Arc::new(AtomicBool::new(false)),
            concurrency: 4,
            max_attempts: MAX_ATTEMPTS,
        }
    }
    pub fn ready(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    pub async fn run(self) -> anyhow::Result<()> {
        self.running.store(true, Ordering::Release);
        let result = self.run_inner().await;
        self.running.store(false, Ordering::Release);
        if result.is_err() {
            self.shutdown.cancel();
        }
        result
    }
    async fn run_inner(&self) -> anyhow::Result<()> {
        // Anything that was mid-delivery when the process died is retried: at-least-once.
        self.store.recover_deliveries().await?;
        let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
        let mut last_prune = Instant::now();
        loop {
            if self.shutdown.is_cancelled() {
                while let Some(done) = tasks.join_next().await {
                    done??;
                }
                return Ok(());
            }
            // Outbox -> delivery rows (each event atomically with the cursor).
            let events = self.store.outbox_batch("webhooks", 64).await?;
            let busy = !events.is_empty();
            for event in events {
                self.store
                    .fan_out(event, self.store.automation_limits.max_chain_depth)
                    .await?;
            }
            while let Some(done) = tasks.try_join_next() {
                done??;
            }
            let free = self.concurrency.saturating_sub(tasks.len());
            if free > 0 {
                for delivery in self.store.claim_deliveries(free).await? {
                    let this = self.clone();
                    tasks.spawn(async move { this.deliver(delivery).await });
                }
            }
            if last_prune.elapsed() > Duration::from_secs(3600) {
                self.store.prune_outbox().await?;
                last_prune = Instant::now();
            }
            if !busy {
                tokio::select! {
                    _ = self.shutdown.cancelled() => {},
                    _ = self.wake.notified() => {},
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                }
            }
        }
    }

    /// One delivery attempt. The row is already marked `delivering` (attempt counted).
    pub async fn deliver(&self, delivery: DueDelivery) -> anyhow::Result<()> {
        let started = Utc::now();
        let clock = Instant::now();
        tracing::info!(delivery_id=%delivery.id, project_id=%delivery.project_id, event_id=%delivery.event_id, attempt=delivery.attempt, "Delivering outbound webhook");
        let (outcome, status) = self.attempt(&delivery).await;
        let delivered = self
            .store
            .finish_delivery(
                delivery.clone(),
                started,
                clock.elapsed().as_millis() as u64,
                status,
                outcome,
                self.max_attempts,
            )
            .await?;
        tracing::info!(delivery_id=%delivery.id, status=delivered.as_str(), "Outbound webhook attempt finished");
        Ok(())
    }
    async fn attempt(&self, delivery: &DueDelivery) -> (DeliveryOutcome, Option<u16>) {
        let retry = |reason: &'static str, hint: Option<Duration>| {
            let computed = retry::backoff(delivery.attempt, jitter());
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
