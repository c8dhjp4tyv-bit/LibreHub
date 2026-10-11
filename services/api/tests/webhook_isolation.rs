//! M7 regression (isolated webhook failures). One failing delivery attempt must not stop other
//! deliveries, the API, or the shared shutdown token. A failed attempt is recorded with a stable
//! category and recovered with its delivery and event identity intact. Every fault here is a real
//! failure: a SQLite trigger, a panicking transport, a lock held by another connection, or an
//! attempt that outlives its lease.
mod common;
use axum::http::StatusCode;
use common::*;
use librehub_api::outbound_worker::{OutboundWorker, Transport, TransportResult};
use librehub_automation::webhook::{self, Destination};
use librehub_common::*;
use rusqlite::OptionalExtension;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};

const HOST: &str = "hooks.example.com";

/// What the receiver does for one attempt against a hook.
#[derive(Clone)]
enum Plan {
    Accept,
    Panic,
    /// Holds the attempt until the test releases it, then accepts it.
    Stall(Arc<Notify>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    path: String,
    delivery: String,
    event: String,
}

/// Chooses the plan for an attempt from the hook path and its attempt number.
type PlanFn = dyn Fn(&str, u32) -> Plan + Send + Sync;

/// Records every attempt's identity and applies a per-attempt plan.
struct Receiver {
    plan: Box<PlanFn>,
    /// Runs once, just before the first attempt is recorded.
    before: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    attempts: Mutex<HashMap<String, u32>>,
    seen: Mutex<Vec<Seen>>,
}
impl Receiver {
    fn new(plan: impl Fn(&str, u32) -> Plan + Send + Sync + 'static) -> Self {
        Self {
            plan: Box::new(plan),
            before: Mutex::new(None),
            attempts: Mutex::new(HashMap::new()),
            seen: Mutex::new(vec![]),
        }
    }
    fn identities(&self, path: &str) -> Vec<(String, String)> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .map(|s| (s.delivery.clone(), s.event.clone()))
            .collect()
    }
}
#[async_trait::async_trait]
impl Transport for Receiver {
    async fn post(
        &self,
        destination: &Destination,
        _pinned: &[SocketAddr],
        headers: Vec<(String, String)>,
        _body: Vec<u8>,
    ) -> TransportResult {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        };
        let path = destination.url.path().to_owned();
        let nth = {
            let mut attempts = self.attempts.lock().unwrap();
            let count = attempts.entry(path.clone()).or_default();
            *count += 1;
            *count
        };
        if let Some(before) = self.before.lock().unwrap().take() {
            before();
        }
        self.seen.lock().unwrap().push(Seen {
            path: path.clone(),
            delivery: header(webhook::DELIVERY_HEADER),
            event: header(webhook::EVENT_ID_HEADER),
        });
        match (self.plan)(&path, nth) {
            Plan::Accept => {}
            Plan::Panic => panic!("synthetic delivery panic"),
            Plan::Stall(release) => release.notified().await,
        }
        TransportResult::Response {
            status: 204,
            retry_after: None,
        }
    }
}

/// A project with two hooks on the same event: every event is two deliveries, `/first` and
/// `/second`, that succeed independently of each other.
async fn project_with_two_hooks() -> (Env, ProjectId) {
    let env = Env::at(tempfile::tempdir().unwrap(), false).await;
    env.resolver
        .set(HOST, vec![vec!["93.184.216.34".parse().unwrap()]]);
    let project = env.project().await;
    for path in ["first", "second"] {
        let (status, body) = env
            .call(
                "POST",
                &format!("/api/v1/projects/{project}/integrations/webhooks"),
                Some(&env.token),
                Some(json!({"url": format!("https://{HOST}/{path}"), "event_types": ["automation.started"]})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let automation = env
        .create_automation(
            project,
            json!({"name":"A","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]}),
        )
        .await;
    let (status, body) = env
        .trigger(project, automation, json!({"idempotency_key":"e"}))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    (env, project)
}

/// The real outbound worker with fast retries and a short lease, sharing the environment's
/// shutdown token exactly as production does.
fn worker(env: &Env, receiver: Arc<Receiver>) -> OutboundWorker {
    let mut worker = env.outbound.clone();
    worker.transport = receiver;
    worker.backoff_base = Duration::from_millis(10);
    worker.lease = Duration::from_millis(400);
    worker.max_attempts = 4;
    worker
}

/// `(status, attempts, last_error)` for the delivery to the hook whose path is `path`. Before the
/// worker admits the event there is no row yet, reported as `missing`.
fn status_of(env: &Env, path: &str) -> (String, u32, Option<String>) {
    env.db()
        .query_row(
            "SELECT d.status,d.attempts,d.last_error FROM integration_deliveries d JOIN webhook_subscriptions w ON w.id=d.webhook_id WHERE w.url LIKE ?1",
            [format!("%/{path}")],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .unwrap()
        .unwrap_or(("missing".into(), 0, None))
}
fn delivery_id(env: &Env, path: &str) -> String {
    env.db()
        .query_row(
            "SELECT d.id FROM integration_deliveries d JOIN webhook_subscriptions w ON w.id=d.webhook_id WHERE w.url LIKE ?1",
            [format!("%/{path}")],
            |r| r.get(0),
        )
        .unwrap()
}
fn attempt_rows(env: &Env, path: &str, outcome: &str, error: Option<&str>) -> i64 {
    env.db()
        .query_row(
            "SELECT count(*) FROM integration_attempts a JOIN integration_deliveries d ON d.id=a.delivery_id JOIN webhook_subscriptions w ON w.id=d.webhook_id WHERE w.url LIKE ?1 AND a.outcome=?2 AND (?3 IS NULL OR a.error=?3)",
            rusqlite::params![format!("%/{path}"), outcome, error],
            |r| r.get(0),
        )
        .unwrap()
}
fn deliveries_total(env: &Env) -> i64 {
    env.db()
        .query_row("SELECT count(*) FROM integration_deliveries", [], |r| {
            r.get(0)
        })
        .unwrap()
}
fn failures(worker: &OutboundWorker, category: &str) -> u64 {
    worker
        .health
        .failures()
        .iter()
        .find(|(name, _)| *name == category)
        .map_or(0, |(_, count)| *count)
}
async fn stop(env: Env, task: JoinHandle<anyhow::Result<()>>) {
    env.shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the outbound worker drains within its deadline")
        .unwrap()
        .unwrap();
}
async fn api_responds(env: &Env, project: ProjectId) {
    let (status, body) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_failed_result_write_is_isolated_and_retried_with_the_same_identity() {
    let (env, project) = project_with_two_hooks().await;
    // A real SQLite failure scoped to one hook: its result rows cannot be written.
    env.db()
        .execute_batch(
            "CREATE TRIGGER fail_result BEFORE INSERT ON integration_attempts WHEN NEW.delivery_id IN (SELECT d.id FROM integration_deliveries d JOIN webhook_subscriptions w ON w.id=d.webhook_id WHERE w.url LIKE '%/first') BEGIN SELECT RAISE(ABORT,'synthetic storage fault'); END;",
        )
        .unwrap();
    let receiver = Arc::new(Receiver::new(|_, _| Plan::Accept));
    let worker = worker(&env, receiver.clone());
    let task = tokio::spawn(worker.clone().run());
    wait_until(|| status_of(&env, "second").0 == "delivered").await;
    wait_until(|| status_of(&env, "first").2.as_deref() == Some("storage")).await;
    // While one result cannot be recorded, the API answers and nothing else is shut down.
    api_responds(&env, project).await;
    assert!(worker.ready(), "the worker stays operational");
    assert!(
        !env.shutdown.is_cancelled(),
        "one delivery failure must not cancel shutdown"
    );
    assert!(!task.is_finished());
    // Storage recovers: the same delivery is retried and its result is recorded.
    env.db().execute_batch("DROP TRIGGER fail_result;").unwrap();
    wait_until(|| status_of(&env, "first").0 == "delivered").await;
    assert!(
        status_of(&env, "first").1 >= 2,
        "the failed attempt was counted"
    );
    let identities = receiver.identities("/first");
    assert!(identities.len() >= 2);
    assert!(
        identities.iter().all(|identity| identity == &identities[0]),
        "retries keep one identity"
    );
    assert_eq!(
        identities[0].0,
        delivery_id(&env, "first"),
        "the delivery identity is the stored one"
    );
    assert_eq!(
        deliveries_total(&env),
        2,
        "recovery created no new delivery"
    );
    assert!(failures(&worker, "storage") >= 1);
    stop(env, task).await;
}

#[tokio::test]
async fn a_panicking_delivery_is_isolated_recorded_and_retried_with_the_same_identity() {
    let (env, project) = project_with_two_hooks().await;
    let receiver = Arc::new(Receiver::new(|path, nth| {
        if path == "/first" && nth == 1 {
            Plan::Panic
        } else {
            Plan::Accept
        }
    }));
    let worker = worker(&env, receiver.clone());
    let task = tokio::spawn(worker.clone().run());
    wait_until(|| {
        status_of(&env, "first").0 == "delivered" && status_of(&env, "second").0 == "delivered"
    })
    .await;
    assert!(
        !env.shutdown.is_cancelled(),
        "a panic must not cancel shutdown"
    );
    assert!(!task.is_finished());
    assert!(worker.ready());
    assert_eq!(failures(&worker, "task_panic"), 1);
    assert_eq!(
        attempt_rows(&env, "first", "interrupted", Some("task_panic")),
        1
    );
    assert_eq!(status_of(&env, "first").1, 2);
    let identities = receiver.identities("/first");
    assert_eq!(identities.len(), 2);
    assert_eq!(
        identities[0], identities[1],
        "the retry keeps the delivery and event identity"
    );
    api_responds(&env, project).await;
    stop(env, task).await;
}

#[tokio::test]
async fn repeated_failure_reaches_dead_letter_with_an_audit_record() {
    let (env, _project) = project_with_two_hooks().await;
    let receiver = Arc::new(Receiver::new(|path, _| {
        if path == "/first" {
            Plan::Panic
        } else {
            Plan::Accept
        }
    }));
    let mut worker = worker(&env, receiver);
    worker.max_attempts = 3;
    let task = tokio::spawn(worker.clone().run());
    wait_until(|| status_of(&env, "first").0 == "dead_letter").await;
    assert_eq!(
        status_of(&env, "first"),
        ("dead_letter".into(), 3, Some("task_panic".into()))
    );
    assert_eq!(
        status_of(&env, "second").0,
        "delivered",
        "other deliveries are unaffected"
    );
    assert_eq!(failures(&worker, "task_panic"), 3);
    let audited: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM integration_audit_events WHERE action='webhook.delivery_failed' AND target_id=?1",
            [delivery_id(&env, "first")],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audited, 1, "the terminal failure is audited once");
    assert!(!env.shutdown.is_cancelled());
    stop(env, task).await;
}

#[tokio::test]
async fn busy_storage_pauses_delivery_without_losing_or_duplicating_it() {
    let (env, _project) = project_with_two_hooks().await;
    env.store
        .set_busy_timeout(Duration::from_millis(20))
        .await
        .unwrap();
    let database = env.root.path().join("builds.sqlite3");
    let receiver = Arc::new(Receiver::new(|_, _| Plan::Accept));
    // While the first attempt is in flight, another connection holds the write lock for a while,
    // the way an operator's sqlite3 session or a backup would.
    *receiver.before.lock().unwrap() = Some(Box::new(move || {
        let lock = rusqlite::Connection::open(&database).unwrap();
        lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1200));
            lock.execute_batch("COMMIT").unwrap();
        });
    }));
    let worker = worker(&env, receiver.clone());
    let task = tokio::spawn(worker.clone().run());
    wait_until(|| {
        status_of(&env, "first").0 == "delivered" && status_of(&env, "second").0 == "delivered"
    })
    .await;
    assert!(
        failures(&worker, "storage_busy") >= 1,
        "contention was observed and classified"
    );
    assert_eq!(
        deliveries_total(&env),
        2,
        "no delivery was lost or duplicated"
    );
    assert!(!env.shutdown.is_cancelled());
    assert!(
        !task.is_finished(),
        "transient contention never ends the worker"
    );
    stop(env, task).await;
}

#[tokio::test]
async fn an_attempt_stalled_past_its_lease_is_recovered_and_its_late_result_is_discarded() {
    let (env, _project) = project_with_two_hooks().await;
    let release = Arc::new(Notify::new());
    let stall = release.clone();
    let receiver = Arc::new(Receiver::new(move |path, nth| {
        if path == "/first" && nth == 1 {
            Plan::Stall(stall.clone())
        } else {
            Plan::Accept
        }
    }));
    let task = tokio::spawn(worker(&env, receiver.clone()).run());
    // The lease lapses while the first attempt is still in flight: the delivery is recovered.
    wait_until(|| status_of(&env, "first") == ("delivered".into(), 2, None)).await;
    assert_eq!(
        attempt_rows(&env, "first", "interrupted", Some("lease_expired")),
        1
    );
    // The stalled attempt now completes. Its result is stale and must not overwrite the newer one.
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(status_of(&env, "first"), ("delivered".into(), 2, None));
    assert_eq!(
        attempt_rows(&env, "first", "delivered", None),
        1,
        "exactly one winning result"
    );
    assert_eq!(
        receiver.identities("/first").len(),
        2,
        "both attempts were sent with one identity"
    );
    assert!(
        receiver
            .identities("/first")
            .iter()
            .all(|i| i == &receiver.identities("/first")[0])
    );
    stop(env, task).await;
}
