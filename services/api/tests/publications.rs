use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use librehub_api::{
    ApiState, publishing::Publishing, router_with_publisher, store::Store, worker::Supervisor,
};
use librehub_common::*;
use librehub_publisher::{
    PublishError, PublishJob, PublishJournal, Publisher, repository::RepositoryConfig,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;

struct Fake {
    calls: AtomicUsize,
    failure: bool,
    admission_error: Option<PublishError>,
}
#[async_trait]
impl Publisher for Fake {
    async fn eligible(
        &self,
        build: BuildRecord,
        _: FlatpakManifest,
        _: PathBuf,
    ) -> Result<(), PublishError> {
        if build.status != BuildStatus::Succeeded {
            return Err(PublishError::Ineligible);
        }
        if let Some(error) = &self.admission_error {
            return Err(error.clone());
        }
        Ok(())
    }
    async fn publish(
        &self,
        job: PublishJob,
        journal: &dyn PublishJournal,
    ) -> Result<PublishResult, PublishError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failure {
            return Err(PublishError::Commit);
        }
        let mut record = job.record;
        for state in [
            PublishStatus::Uploading,
            PublishStatus::Committing,
            PublishStatus::Publishing,
        ] {
            if record.status.can_transition_to(state) {
                record.status = state;
                journal.save(record.clone()).await?;
            }
        }
        Ok(PublishResult {
            published_ref: PublishedRef {
                ref_name: RepositoryRef::new(&record.app_id, record.architecture, "master")
                    .unwrap(),
                commit: "a".repeat(64),
                source_commit: "b".repeat(64),
                repository_url: "http://localhost/repo/stable/".into(),
            },
            signing: repository().signing(),
        })
    }
    async fn ready(&self) -> bool {
        true
    }
    async fn repository_ready(&self) -> bool {
        true
    }
}
fn repository() -> RepositoryConfig {
    RepositoryConfig {
        public_base_url: "http://localhost:8090".into(),
        public_key: b"public".to_vec(),
        fingerprint: "A".repeat(40),
        runtime_repo_url: "https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
    }
}
fn manifest() -> FlatpakManifest {
    librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap()
}
async fn succeeded(store: &Store) -> BuildId {
    let id = store
        .insert(manifest(), Architecture::native())
        .await
        .unwrap()
        .id;
    store
        .transition(id, BuildStatus::Validating, None, None)
        .await
        .unwrap();
    store
        .transition(id, BuildStatus::Building, None, None)
        .await
        .unwrap();
    store
        .transition(
            id,
            BuildStatus::Succeeded,
            Some(BuildResult {
                exit_code: Some(0),
                artifacts: vec![Artifact {
                    path: format!("builds/{id}/artifacts/application.flatpak"),
                    size_bytes: 5,
                    sha256: "a".repeat(64),
                }],
            }),
            None,
        )
        .await
        .unwrap();
    id
}
async fn call(app: &Router, method: &str, url: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(url)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}
#[tokio::test]
async fn api_publish_lookup_cancel_and_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let supervisor = Supervisor::new(store.clone());
    let service = Publishing::new(
        store.clone(),
        Arc::new(Fake {
            calls: AtomicUsize::new(0),
            failure: false,
            admission_error: None,
        }),
        repository(),
        1,
        supervisor.shutdown.clone(),
    )
    .unwrap();
    let app = router_with_publisher(
        ApiState {
            supervisor,
            architecture: Architecture::native(),
        },
        Some(service),
    );
    assert_eq!(
        call(&app, "GET", "/ready", json!({})).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/api/v1/builds/{}/publish", BuildId::new()),
            json!({"channel":"stable"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let id = succeeded(&store).await;
    let url = format!("/api/v1/builds/{id}/publish");
    for body in [
        json!({"channel":"../stable"}),
        json!({"channel":"stable","path":"/etc"}),
    ] {
        assert_eq!(
            call(&app, "POST", &url, body).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let (status, record) = call(&app, "POST", &url, json!({"channel":"stable"})).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(record["status"], "queued");
    let (_, duplicate) = call(&app, "POST", &url, json!({"channel":"stable"})).await;
    assert_eq!(record["id"], duplicate["id"]);
    let lookup = format!("/api/v1/publishes/{}", record["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "GET", &lookup, json!({})).await.1["build_id"],
        id.to_string()
    );
    assert_eq!(
        call(&app, "POST", &format!("{lookup}/cancel"), json!({}))
            .await
            .1["status"],
        "cancelled"
    );
    assert_eq!(
        call(&app, "POST", &format!("{lookup}/cancel"), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    for status in [BuildStatus::Failed, BuildStatus::Cancelled] {
        let id = store
            .insert(manifest(), Architecture::native())
            .await
            .unwrap()
            .id;
        store.transition(id, status, None, None).await.unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/api/v1/builds/{id}/publish"),
                json!({"channel":"beta"})
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }
}
#[tokio::test]
async fn duplicate_race_and_cancellation_claim_are_transactional() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let build = succeeded(&store).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let s = store.clone();
        tasks.spawn(async move {
            s.enqueue_publish(build, RepositoryChannel::Stable)
                .await
                .unwrap()
                .id
        });
    }
    let mut ids = std::collections::HashSet::new();
    while let Some(id) = tasks.join_next().await {
        ids.insert(id.unwrap());
    }
    assert_eq!(ids.len(), 1);
    let id = *ids.iter().next().unwrap();
    store.claim_publication(id).await.unwrap().unwrap();
    assert!(store.cancel_publication(id).await.is_err());
    let mut record = store.publish_record(id).await.unwrap().unwrap();
    record.status = PublishStatus::Succeeded;
    assert!(store.save_publication(record).await.is_err());
    assert_eq!(store.publications(build).await.unwrap().len(), 1);
}
#[tokio::test]
async fn recovery_success_failure_and_terminal_lookup() {
    for failure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = Store::open(dir.path()).unwrap();
            let build = succeeded(&store).await;
            id = store
                .enqueue_publish(build, RepositoryChannel::Beta)
                .await
                .unwrap()
                .id;
            let mut record = store.claim_publication(id).await.unwrap().unwrap();
            record.status = PublishStatus::Uploading;
            record.flat_manager_build_id = Some(7);
            store.save_publication(record.clone()).await.unwrap();
            record.status = PublishStatus::Committing;
            record.needs_attention = true;
            record.error = Some(PublishError::Timeout.failure());
            store.save_publication(record).await.unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        let supervisor = Supervisor::new(store.clone());
        let publisher = Arc::new(Fake {
            calls: AtomicUsize::new(0),
            failure,
            admission_error: None,
        });
        let service = Publishing::new(
            store.clone(),
            publisher.clone(),
            repository(),
            2,
            supervisor.shutdown.clone(),
        )
        .unwrap();
        let app = router_with_publisher(
            ApiState {
                supervisor: supervisor.clone(),
                architecture: Architecture::native(),
            },
            Some(service.clone()),
        );
        let task = tokio::spawn(service.run());
        let record = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let r = store.publish_record(id).await.unwrap().unwrap();
                if r.status.is_terminal() {
                    break r;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            record.status,
            if failure {
                PublishStatus::Failed
            } else {
                PublishStatus::Succeeded
            }
        );
        assert_eq!(record.flat_manager_build_id, Some(7));
        assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            call(&app, "GET", &format!("/api/v1/publishes/{id}"), json!({}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/ready", json!({})).await.0,
            StatusCode::OK
        );
        supervisor.shutdown.cancel();
        task.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn m1_database_migration_preserves_builds() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let build = succeeded(&store).await;
    drop(store);
    let db = rusqlite::Connection::open(dir.path().join("builds.sqlite3")).unwrap();
    db.execute_batch("DROP TABLE publishes; DROP TABLE schema_migrations;")
        .unwrap();
    drop(db);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store.get(build).await.unwrap().unwrap().status,
        BuildStatus::Succeeded
    );
    let id = store
        .enqueue_publish(build, RepositoryChannel::Stable)
        .await
        .unwrap()
        .id;
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store.publish_record(id).await.unwrap().unwrap().status,
        PublishStatus::Queued
    );
}

#[tokio::test]
async fn real_publisher_admission_rejects_modified_artifact_without_leaking_paths() {
    use librehub_publisher::{FlatManagerPublisher, flat_manager::FlatManagerClient};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let build = succeeded(&store).await;
    let path = store
        .data_dir
        .join(format!("builds/{build}/artifacts/application.flatpak"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"hello").unwrap(); // Recorded checksum deliberately differs.
    let client = FlatManagerClient::new(
        "http://127.0.0.1:1",
        "private-token".into(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    let publisher = FlatManagerPublisher::new(
        client,
        repository(),
        Architecture::native(),
        Duration::from_secs(10),
    )
    .unwrap();
    let supervisor = Supervisor::new(store.clone());
    let service = Publishing::new(
        store.clone(),
        Arc::new(publisher),
        repository(),
        1,
        supervisor.shutdown.clone(),
    )
    .unwrap();
    let app = router_with_publisher(
        ApiState {
            supervisor,
            architecture: Architecture::native(),
        },
        Some(service),
    );
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/v1/builds/{build}/publish"),
        json!({"channel":"stable"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "artifact_integrity_failed");
    assert!(!body.to_string().contains("private-token"));
    assert!(!body.to_string().contains(dir.path().to_str().unwrap()));
    assert!(store.publications(build).await.unwrap().is_empty());
}

#[tokio::test]
async fn admission_distinguishes_unavailable_infrastructure_from_build_conflicts() {
    for (error, expected) in [
        (PublishError::Timeout, StatusCode::SERVICE_UNAVAILABLE),
        (PublishError::Storage, StatusCode::SERVICE_UNAVAILABLE),
        (PublishError::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
        (PublishError::PartialUpload, StatusCode::SERVICE_UNAVAILABLE),
        (PublishError::Verification, StatusCode::SERVICE_UNAVAILABLE),
        (PublishError::Integrity, StatusCode::CONFLICT),
        (PublishError::Metadata, StatusCode::CONFLICT),
        (PublishError::Architecture, StatusCode::CONFLICT),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let build = succeeded(&store).await;
        let supervisor = Supervisor::new(store.clone());
        let publisher = Arc::new(Fake {
            calls: AtomicUsize::new(0),
            failure: false,
            admission_error: Some(error.clone()),
        });
        let service = Publishing::new(
            store.clone(),
            publisher.clone(),
            repository(),
            1,
            supervisor.shutdown.clone(),
        )
        .unwrap();
        let app = router_with_publisher(
            ApiState {
                supervisor,
                architecture: Architecture::native(),
            },
            Some(service),
        );
        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/builds/{build}/publish"),
            json!({"channel":"stable"}),
        )
        .await;
        assert_eq!(status, expected, "{error:?}");
        assert_eq!(body["code"], error.code());
        assert_eq!(body["message"], error.to_string());
        assert!(store.publications(build).await.unwrap().is_empty());
        assert_eq!(publisher.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn publication_queue_is_bounded_and_cannot_accept_failed_builds() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    for _ in 0..64 {
        let id = succeeded(&store).await;
        store
            .enqueue_publish(id, RepositoryChannel::Stable)
            .await
            .unwrap();
    }
    let extra = succeeded(&store).await;
    assert!(
        store
            .enqueue_publish(extra, RepositoryChannel::Beta)
            .await
            .is_err()
    );
    for state in [BuildStatus::Failed, BuildStatus::Cancelled] {
        let id = store
            .insert(manifest(), Architecture::native())
            .await
            .unwrap()
            .id;
        store.transition(id, state, None, None).await.unwrap();
        assert!(
            store
                .enqueue_publish(id, RepositoryChannel::Stable)
                .await
                .is_err()
        );
    }
}
