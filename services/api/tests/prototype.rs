use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use librehub_api::{
    ApiState, router,
    store::{MAX_LOG_BYTES, Store},
    worker::Supervisor,
};
use librehub_builder::*;
use librehub_common::*;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const MANIFEST: &str = include_str!("../../../examples/org.librehub.Hello.json");
struct Fixture {
    _dir: tempfile::TempDir,
    supervisor: Supervisor,
    app: Router,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = Supervisor::new(Store::open(dir.path()).unwrap());
        let app = router(ApiState {
            supervisor: supervisor.clone(),
            architecture: Architecture::native(),
        });
        Self {
            _dir: dir,
            supervisor,
            app,
        }
    }
    async fn submit(&self) -> BuildId {
        let (status, body) = call(&self.app, "POST", "/api/v1/builds", MANIFEST).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "queued");
        serde_json::from_value(body["id"].clone()).unwrap()
    }
}
async fn call(app: &Router, method: &str, path: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn creation_lookup_logs_and_unknown_ids() {
    let f = Fixture::new();
    let id = f.submit().await;
    let (status, body) = call(&f.app, "GET", &format!("/api/v1/builds/{id}"), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["manifest"]["app_id"], "org.librehub.Hello");
    for suffix in ["", "/logs", "/cancel"] {
        let method = if suffix == "/cancel" { "POST" } else { "GET" };
        assert_eq!(
            call(
                &f.app,
                method,
                &format!("/api/v1/builds/{}{suffix}", BuildId::new()),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(&f.app, "GET", "/api/v1/builds/not-a-uuid", "").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &f.app,
            "GET",
            &format!("/api/v1/builds/{id}/logs?limit=501"),
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn malformed_missing_fields_envelope_yaml_and_body_limit() {
    let f = Fixture::new();
    assert_eq!(
        call(&f.app, "POST", "/api/v1/builds", "{").await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, errors) = call(&f.app, "POST", "/api/v1/builds", "{}").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(errors["valid"], false);
    assert_eq!(errors["errors"].as_array().unwrap().len(), 6);
    let yaml = include_str!("../../../examples/org.librehub.Hello.yaml");
    let envelope = json!({"manifest":yaml, "format":"yaml"});
    assert_eq!(
        call(&f.app, "POST", "/api/v1/builds", &envelope.to_string())
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/builds")
        .header("content-type", "application/yaml")
        .body(Body::from(yaml))
        .unwrap();
    assert_eq!(
        f.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        call(
            &f.app,
            "POST",
            "/api/v1/builds",
            &"a".repeat(2 * 1024 * 1024 + 1)
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(f.supervisor.store.pending().await.unwrap().len(), 2);
}

#[derive(Clone, Copy)]
enum Mode {
    Success,
    Failure,
    Wait,
    Panic,
}
struct Fake {
    mode: Mode,
    started: AtomicBool,
    terminated: AtomicBool,
    cleaned: AtomicUsize,
}
impl Fake {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            started: AtomicBool::new(false),
            terminated: AtomicBool::new(false),
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
        self.started.store(true, Ordering::SeqCst);
        logs.append(BuildLogEntry {
            sequence: 0,
            timestamp: Utc::now(),
            stream: LogStream::Stderr,
            message: "compiler output".into(),
        })
        .await
        .unwrap();
        match self.mode {
            Mode::Success => {
                let path = format!("builds/{}/artifacts/application.flatpak", job.id);
                let full = job.data_dir.join(&path);
                tokio::fs::create_dir_all(full.parent().unwrap())
                    .await
                    .unwrap();
                tokio::fs::write(&full, b"fake bundle").await.unwrap();
                Ok(BuildResult {
                    exit_code: Some(0),
                    artifacts: vec![Artifact {
                        path,
                        size_bytes: 11,
                        sha256: "test".into(),
                    }],
                })
            }
            Mode::Failure => Err(ExecutorError::Exit(Some(42))),
            Mode::Wait => {
                cancel.cancelled().await;
                // Cancellation is recorded only after actual termination completes.
                tokio::time::sleep(Duration::from_millis(30)).await;
                self.terminated.store(true, Ordering::SeqCst);
                Err(ExecutorError::Cancelled)
            }
            Mode::Panic => panic!("test executor panic"),
        }
    }
    async fn cleanup(&self, _id: BuildId) -> anyhow::Result<()> {
        self.cleaned.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
async fn until_terminal(store: &Store, id: BuildId) -> BuildRecord {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let record = store.get(id).await.unwrap().unwrap();
            if record.status.is_terminal() {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
async fn until_started(executor: &Fake) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !executor.started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn successful_artifact_and_failure_and_panic_do_not_crash_worker() {
    for (mode, expected, code) in [
        (Mode::Success, BuildStatus::Succeeded, None),
        (Mode::Failure, BuildStatus::Failed, Some("build_failed")),
        (Mode::Panic, BuildStatus::Failed, Some("executor_error")),
    ] {
        let f = Fixture::new();
        let id = f.submit().await;
        let executor = Fake::new(mode);
        let worker = tokio::spawn(f.supervisor.clone().run(executor.clone()));
        let record = until_terminal(&f.supervisor.store, id).await;
        assert_eq!(record.status, expected);
        assert_eq!(record.error.as_ref().map(|e| e.code.as_str()), code);
        assert!(record.started_at.is_some() && record.finished_at.is_some());
        if expected == BuildStatus::Succeeded {
            let result = record.result.unwrap();
            assert!(
                f.supervisor
                    .store
                    .data_dir
                    .join(&result.artifacts[0].path)
                    .exists()
            );
        }
        let (_, logs) = call(
            &f.app,
            "GET",
            &format!("/api/v1/builds/{id}/logs?after=1&limit=1"),
            "",
        )
        .await;
        assert_eq!(logs[0]["stream"], "stderr");
        assert_eq!(logs[0]["sequence"], 2);
        // A subsequent job proves failures/panics do not kill queue consumption.
        let second = f.submit().await;
        assert_eq!(
            until_terminal(&f.supervisor.store, second).await.status,
            expected
        );
        f.supervisor.shutdown.cancel();
        worker.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn queued_and_running_cancellation_terminate_execution() {
    let f = Fixture::new();
    let queued = f.submit().await;
    let (_, body) = call(
        &f.app,
        "POST",
        &format!("/api/v1/builds/{queued}/cancel"),
        "",
    )
    .await;
    assert_eq!(body["status"], "cancelled");
    let id = f.submit().await;
    let executor = Fake::new(Mode::Wait);
    let worker = tokio::spawn(f.supervisor.clone().run(executor.clone()));
    until_started(&executor).await;
    let (status, body) = call(&f.app, "POST", &format!("/api/v1/builds/{id}/cancel"), "").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["cancellation_requested"], true);
    assert_eq!(
        until_terminal(&f.supervisor.store, id).await.status,
        BuildStatus::Cancelled
    );
    assert!(executor.terminated.load(Ordering::SeqCst));
    assert_eq!(
        call(&f.app, "POST", &format!("/api/v1/builds/{id}/cancel"), "")
            .await
            .0,
        StatusCode::OK
    );
    f.supervisor.shutdown.cancel();
    worker.await.unwrap().unwrap();
}
#[tokio::test]
async fn graceful_shutdown_stops_active_executor_and_preserves_queued_jobs() {
    let f = Fixture::new();
    let id = f.submit().await;
    let queued = f.submit().await;
    let executor = Fake::new(Mode::Wait);
    let worker = tokio::spawn(f.supervisor.clone().run(executor.clone()));
    until_started(&executor).await;
    f.supervisor.shutdown.cancel();
    worker.await.unwrap().unwrap();
    assert!(executor.terminated.load(Ordering::SeqCst));
    assert_eq!(
        f.supervisor.store.get(id).await.unwrap().unwrap().status,
        BuildStatus::Cancelled
    );
    assert_eq!(
        f.supervisor
            .store
            .get(queued)
            .await
            .unwrap()
            .unwrap()
            .status,
        BuildStatus::Queued
    );
}
#[tokio::test]
async fn persistence_recovery_and_single_owner_lock() {
    let dir = tempfile::tempdir().unwrap();
    let id;
    let queued;
    {
        let store = Store::open(dir.path()).unwrap();
        assert!(Store::open(dir.path()).is_err());
        let manifest = librehub_validator::validate(MANIFEST, ManifestFormat::Json).unwrap();
        id = store
            .insert(manifest.clone(), Architecture::native())
            .await
            .unwrap()
            .id;
        queued = store
            .insert(manifest, Architecture::native())
            .await
            .unwrap()
            .id;
        assert!(
            store
                .transition(id, BuildStatus::Succeeded, None, None)
                .await
                .is_err()
        );
        store
            .transition(id, BuildStatus::Validating, None, None)
            .await
            .unwrap();
        store
            .transition(id, BuildStatus::Building, None, None)
            .await
            .unwrap();
        store
            .append(
                id,
                BuildLogEntry {
                    sequence: 0,
                    timestamp: Utc::now(),
                    stream: LogStream::Stdout,
                    message: "persist me".into(),
                },
            )
            .await
            .unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    let supervisor = Supervisor::new(store.clone());
    let executor = Fake::new(Mode::Success);
    supervisor.recover(executor.as_ref()).await.unwrap();
    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.status, BuildStatus::Failed);
    assert_eq!(record.error.unwrap().code, "worker_restarted");
    assert_eq!(executor.cleaned.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.logs(id, 0, 10).await.unwrap()[0].message,
        "persist me"
    );
    let worker = tokio::spawn(supervisor.clone().run(executor));
    assert_eq!(
        until_terminal(&store, queued).await.status,
        BuildStatus::Succeeded
    );
    supervisor.shutdown.cancel();
    worker.await.unwrap().unwrap();
}
#[tokio::test]
async fn bounded_logs_and_queue_and_cancellation_race() {
    let f = Fixture::new();
    let id = f.submit().await;
    // At least 8 MiB of attempted output: persisted JSON must stay within the quota.
    for _ in 0..1100 {
        f.supervisor
            .store
            .append(
                id,
                BuildLogEntry {
                    sequence: 0,
                    timestamp: Utc::now(),
                    stream: LogStream::Stdout,
                    message: "x".repeat(9000),
                },
            )
            .await
            .unwrap();
    }
    let record = f.supervisor.store.get(id).await.unwrap().unwrap();
    assert!(record.logs_truncated);
    let mut after = 0;
    let mut bytes = 0;
    loop {
        let page = f.supervisor.store.logs(id, after, 500).await.unwrap();
        if page.is_empty() {
            break;
        }
        for entry in page {
            after = entry.sequence;
            bytes += serde_json::to_string(&entry).unwrap().len();
        }
    }
    assert!(bytes <= MAX_LOG_BYTES);
    for _ in 1..64 {
        f.submit().await;
    }
    assert_eq!(
        call(&f.app, "POST", "/api/v1/builds", MANIFEST).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    f.supervisor
        .store
        .transition(id, BuildStatus::Validating, None, None)
        .await
        .unwrap();
    f.supervisor
        .store
        .transition(id, BuildStatus::Building, None, None)
        .await
        .unwrap();
    f.supervisor.store.cancel(id).await.unwrap();
    let record = f
        .supervisor
        .store
        .transition(
            id,
            BuildStatus::Succeeded,
            Some(BuildResult {
                exit_code: Some(0),
                artifacts: vec![],
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(record.status, BuildStatus::Cancelled);
    assert!(record.result.is_none());
}

struct CleanupFailure;
#[async_trait]
impl BuildExecutor for CleanupFailure {
    async fn execute(
        &self,
        _: BuildJob,
        _: Arc<dyn LogSink>,
        _: CancellationToken,
    ) -> Result<BuildResult, ExecutorError> {
        Err(ExecutorError::Cleanup(anyhow::anyhow!(
            "container daemon unavailable"
        )))
    }
    async fn cleanup(&self, _: BuildId) -> anyhow::Result<()> {
        anyhow::bail!("container daemon unavailable")
    }
}
#[tokio::test]
async fn cleanup_failure_stops_queue_and_blocks_recovery_until_container_is_removed() {
    let f = Fixture::new();
    let id = f.submit().await;
    let queued = f.submit().await;
    assert!(
        f.supervisor
            .clone()
            .run(Arc::new(CleanupFailure))
            .await
            .is_err()
    );
    let record = f.supervisor.store.get(id).await.unwrap().unwrap();
    assert_eq!(record.status, BuildStatus::Failed);
    assert_eq!(record.error.unwrap().code, "container_cleanup_failed");
    assert_eq!(
        f.supervisor
            .store
            .get(queued)
            .await
            .unwrap()
            .unwrap()
            .status,
        BuildStatus::Queued
    );
    assert!(f.supervisor.recover(&CleanupFailure).await.is_err());
    let recovered = Fake::new(Mode::Success);
    f.supervisor.recover(recovered.as_ref()).await.unwrap();
    assert_eq!(recovered.cleaned.load(Ordering::SeqCst), 1);
}
