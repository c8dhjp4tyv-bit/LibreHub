use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use librehub_api::{
    http::{ApiState, router},
    store::{MAX_LOG_BYTES, Store},
    worker::Supervisor,
};
use librehub_builder::{BuildExecutor, BuildJob, ExecutorError, LogSink};
use librehub_common::*;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
const MAX_PENDING_BUILDS: usize = 64;

#[derive(Clone)]
struct Worker {
    inner: Supervisor,
    store: Store,
    executor: Arc<Fake>,
}
impl Worker {
    fn new(store: Store, executor: Arc<Fake>) -> Self {
        Self {
            inner: Supervisor::new(store.clone()),
            store,
            executor,
        }
    }
    async fn run(self, token: CancellationToken) -> anyhow::Result<()> {
        let mut inner = self.inner;
        inner.shutdown = token;
        inner.run(self.executor).await
    }
    async fn recover(&self) -> anyhow::Result<()> {
        self.inner.recover(self.executor.as_ref()).await
    }
    async fn cancel(&self, id: BuildId) -> anyhow::Result<Option<BuildRecord>> {
        self.store.cancel(id).await
    }
}

const MANIFEST: &str = include_str!("../../../examples/org.librehub.Hello.json");

#[derive(Clone, Copy)]
enum Mode {
    Success,
    FailFirst,
    Wait,
    SuccessAfterCancel,
}
struct Fake {
    mode: Mode,
    started: AtomicUsize,
    stopped: AtomicBool,
    cleaned: AtomicUsize,
}
impl Fake {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            started: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            cleaned: AtomicUsize::new(0),
        })
    }
}
#[async_trait]
impl BuildExecutor for Fake {
    async fn execute(
        &self,
        job: BuildJob,
        logs: Arc<dyn LogSink>,
        cancel: CancellationToken,
    ) -> Result<BuildResult, ExecutorError> {
        let call = self.started.fetch_add(1, Ordering::SeqCst);
        for stream in [LogStream::Stdout, LogStream::Stderr] {
            logs.append(BuildLogEntry {
                sequence: 0,
                timestamp: Utc::now(),
                stream,
                message: "fake build output".into(),
            })
            .await?;
        }
        if matches!(self.mode, Mode::Wait | Mode::SuccessAfterCancel) {
            cancel.cancelled().await;
            self.stopped.store(true, Ordering::SeqCst);
            if matches!(self.mode, Mode::Wait) {
                return Err(ExecutorError::Cancelled);
            }
        }
        if matches!(self.mode, Mode::FailFirst) && call == 0 {
            return Err(ExecutorError::Exit(Some(7)));
        }
        let relative = format!("builds/{}/artifacts/application.flatpak", job.id);
        let output = job.data_dir.join(&relative);
        tokio::fs::create_dir_all(output.parent().unwrap())
            .await
            .map_err(anyhow::Error::from)?;
        tokio::fs::write(&output, b"fake artifact")
            .await
            .map_err(anyhow::Error::from)?;
        Ok(BuildResult {
            exit_code: Some(0),
            artifacts: vec![Artifact {
                path: relative,
                size_bytes: 13,
                sha256: "fake-test-hash".into(),
            }],
        })
    }
    async fn cleanup(&self, _: BuildId) -> anyhow::Result<()> {
        self.cleaned.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
async fn harness(dir: &Path, mode: Mode) -> (Router, Worker, Arc<Fake>) {
    let store = Store::open(dir).unwrap();
    let fake = Fake::new(mode);
    let worker = Worker::new(store, fake.clone());
    let app = router(ApiState {
        supervisor: worker.inner.clone(),
        architecture: Architecture::native(),
    });
    (app, worker, fake)
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    content_type: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", content_type)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn submit(app: &Router) -> BuildId {
    let (status, body) = request(app, "POST", "/api/v1/builds", MANIFEST, "application/json").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "queued");
    body["id"].as_str().unwrap().parse().unwrap()
}
async fn wait_status(store: &Store, id: BuildId, expected: BuildStatus) -> BuildRecord {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let record = store.get(id).await.unwrap().unwrap();
            if record.status == expected {
                return record;
            }
            assert!(
                !record.status.is_terminal(),
                "Unexpected status: {:?}",
                record.status
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Build did not reach expected status")
}
fn run(
    worker: &Worker,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let worker = worker.clone();
    (
        shutdown,
        tokio::spawn(async move { worker.run(token).await }),
    )
}
async fn stop(token: CancellationToken, task: tokio::task::JoinHandle<anyhow::Result<()>>) {
    token.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn creates_looks_up_and_persists_builds() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, _) = harness(dir.path(), Mode::Success).await;
    let id = submit(&app).await;
    let (status, record) = request(
        &app,
        "GET",
        &format!("/api/v1/builds/{id}"),
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(record["manifest"]["app_id"], "org.librehub.Hello");
    drop(worker);
    drop(app);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store.get(id).await.unwrap().unwrap().status,
        BuildStatus::Queued
    );
    assert_eq!(store.manifest(id).await.unwrap().command, "hello");
}
#[tokio::test]
async fn unknown_and_invalid_ids_and_routes_are_structured() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = harness(dir.path(), Mode::Success).await;
    for suffix in ["", "/logs", "/cancel"] {
        let method = if suffix == "/cancel" { "POST" } else { "GET" };
        let (status, body) = request(
            &app,
            method,
            &format!("/api/v1/builds/{}{suffix}", BuildId::new()),
            "",
            "application/json",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "build_not_found");
    }
    let (status, _) = request(
        &app,
        "GET",
        "/api/v1/builds/invalid",
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = request(&app, "GET", "/missing", "", "application/json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(&app, "DELETE", "/api/v1/builds", "", "application/json").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
#[tokio::test]
async fn validation_media_types_and_size_limits() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = harness(dir.path(), Mode::Success).await;
    for body in ["{}", &MANIFEST.replace("org.librehub.Hello", "bad")] {
        let (status, result) =
            request(&app, "POST", "/api/v1/builds", body, "application/json").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(result["valid"], false);
        assert!(!result["errors"].as_array().unwrap().is_empty());
    }
    let (status, _) = request(&app, "POST", "/api/v1/builds", MANIFEST, "text/plain").await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/builds",
        &"x".repeat(2 * 1024 * 1024 + 1),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let yaml = include_str!("../../../examples/org.librehub.Hello.yaml");
    let (status, _) = request(&app, "POST", "/api/v1/builds", yaml, "application/yaml").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let envelope =
        json!({"manifest":yaml,"format":"yaml","architecture":Architecture::native()}).to_string();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/builds",
            &envelope,
            "application/json"
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    let other = if Architecture::native() == Architecture::X86_64 {
        "aarch64"
    } else {
        "x86_64"
    };
    let envelope = json!({"manifest": MANIFEST, "architecture":other}).to_string();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/builds",
            &envelope,
            "application/json"
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
#[tokio::test]
async fn worker_preserves_artifacts_logs_and_terminal_results() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, _) = harness(dir.path(), Mode::Success).await;
    let id = submit(&app).await;
    let (token, task) = run(&worker);
    let record = wait_status(&worker.store, id, BuildStatus::Succeeded).await;
    stop(token, task).await;
    assert!(record.started_at.is_some() && record.finished_at.is_some());
    let artifact = &record.result.unwrap().artifacts[0];
    assert_eq!(
        tokio::fs::read(dir.path().join(&artifact.path))
            .await
            .unwrap(),
        b"fake artifact"
    );
    let (status, logs) = request(
        &app,
        "GET",
        &format!("/api/v1/builds/{id}/logs?limit=2"),
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(logs.as_array().unwrap().len(), 2);
    let after = logs[1]["sequence"].as_u64().unwrap();
    let (_, more) = request(
        &app,
        "GET",
        &format!("/api/v1/builds/{id}/logs?after={after}"),
        "",
        "application/json",
    )
    .await;
    assert!(more[0]["sequence"].as_u64().unwrap() > after);
    let (status, record) = request(
        &app,
        "POST",
        &format!("/api/v1/builds/{id}/cancel"),
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(record["status"], "succeeded");
    drop(app);
    drop(worker);
    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        reopened.get(id).await.unwrap().unwrap().status,
        BuildStatus::Succeeded
    );
    assert!(
        reopened
            .logs(id, 0, 100)
            .await
            .unwrap()
            .iter()
            .any(|l| matches!(l.stream, LogStream::Stderr))
    );
}
#[tokio::test]
async fn cancellation_stops_active_executor() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, fake) = harness(dir.path(), Mode::Wait).await;
    let id = submit(&app).await;
    let (token, task) = run(&worker);
    wait_status(&worker.store, id, BuildStatus::Building).await;
    let (status, record) = request(
        &app,
        "POST",
        &format!("/api/v1/builds/{id}/cancel"),
        "",
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(record["cancellation_requested"], true);
    wait_status(&worker.store, id, BuildStatus::Cancelled).await;
    assert!(fake.stopped.load(Ordering::SeqCst));
    stop(token, task).await;
}
#[tokio::test]
async fn queued_cancellation_never_executes_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, fake) = harness(dir.path(), Mode::Success).await;
    let id = submit(&app).await;
    for _ in 0..2 {
        let (status, record) = request(
            &app,
            "POST",
            &format!("/api/v1/builds/{id}/cancel"),
            "",
            "application/json",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(record["status"], "cancelled");
    }
    let (token, task) = run(&worker);
    tokio::time::sleep(Duration::from_millis(30)).await;
    stop(token, task).await;
    assert_eq!(fake.started.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn cancellation_wins_over_late_success_and_removes_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, _) = harness(dir.path(), Mode::SuccessAfterCancel).await;
    let id = submit(&app).await;
    let (token, task) = run(&worker);
    wait_status(&worker.store, id, BuildStatus::Building).await;
    worker.cancel(id).await.unwrap();
    let record = wait_status(&worker.store, id, BuildStatus::Cancelled).await;
    stop(token, task).await;
    assert!(record.result.is_none());
    assert!(!dir.path().join(format!("builds/{id}/artifacts")).exists());
}
#[tokio::test]
async fn builder_failure_does_not_stop_subsequent_builds() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, _) = harness(dir.path(), Mode::FailFirst).await;
    let first = submit(&app).await;
    let second = submit(&app).await;
    let (token, task) = run(&worker);
    let failed = wait_status(&worker.store, first, BuildStatus::Failed).await;
    assert_eq!(failed.error.unwrap().code, "build_failed");
    assert_eq!(failed.result.unwrap().exit_code, Some(7));
    wait_status(&worker.store, second, BuildStatus::Succeeded).await;
    assert_eq!(
        request(&app, "GET", "/health", "", "application/json")
            .await
            .0,
        StatusCode::OK
    );
    stop(token, task).await;
}
#[tokio::test]
async fn restart_recovers_active_builds_and_keeps_queue() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, fake) = harness(dir.path(), Mode::Success).await;
    let active = submit(&app).await;
    let queued = submit(&app).await;
    worker
        .store
        .transition(active, BuildStatus::Validating, None, None)
        .await
        .unwrap();
    worker
        .store
        .transition(active, BuildStatus::Building, None, None)
        .await
        .unwrap();
    worker.recover().await.unwrap();
    assert_eq!(fake.cleaned.load(Ordering::SeqCst), 1);
    let failed = worker.store.get(active).await.unwrap().unwrap();
    assert_eq!(failed.status, BuildStatus::Failed);
    assert_eq!(failed.error.unwrap().code, "worker_restarted");
    assert_eq!(
        worker.store.pending().await.unwrap().first().copied(),
        Some(queued)
    );
    assert!(
        worker
            .store
            .transition(active, BuildStatus::Building, None, None)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn shutdown_cancels_the_active_job_and_preserves_queued_job() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, fake) = harness(dir.path(), Mode::Wait).await;
    let active = submit(&app).await;
    let queued = submit(&app).await;
    let (token, task) = run(&worker);
    wait_status(&worker.store, active, BuildStatus::Building).await;
    stop(token, task).await;
    assert_eq!(
        worker.store.get(active).await.unwrap().unwrap().status,
        BuildStatus::Cancelled
    );
    assert_eq!(
        worker.store.get(queued).await.unwrap().unwrap().status,
        BuildStatus::Queued
    );
    assert!(fake.stopped.load(Ordering::SeqCst));
}
#[tokio::test]
async fn persistent_logs_and_queue_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let (app, worker, _) = harness(dir.path(), Mode::Success).await;
    let id = submit(&app).await;
    for _ in 0..(MAX_LOG_BYTES / 8192 + 2) {
        worker
            .store
            .append(
                id,
                BuildLogEntry {
                    sequence: 0,
                    timestamp: Utc::now(),
                    stream: LogStream::Stdout,
                    message: "x".repeat(8192),
                },
            )
            .await
            .unwrap();
    }
    assert!(worker.store.get(id).await.unwrap().unwrap().logs_truncated);
    let logs = worker.store.logs(id, 0, 1000).await.unwrap();
    assert!(logs.iter().map(|l| l.message.len() + 128).sum::<usize>() <= MAX_LOG_BYTES);
    assert!(
        worker
            .store
            .logs(id, u64::MAX, 1000)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/builds/{id}/logs?limit=1001"),
            "",
            "application/json"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for _ in 1..MAX_PENDING_BUILDS {
        submit(&app).await;
    }
    let (status, body) =
        request(&app, "POST", "/api/v1/builds", MANIFEST, "application/json").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "queue_full");
}
