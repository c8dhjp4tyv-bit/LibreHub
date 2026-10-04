use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use librehub_api::{
    ApiState,
    auth::{self, Secret},
    platform::{Platform, verify_signature},
    platform_store::{Admission, SourceAdmission},
    source_worker::SourceWorker,
    store::Store,
    worker::Supervisor,
};
use librehub_common::*;
use librehub_source::{FetchedSource, PreparedSource, SourceError, SourceProvider};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;
const MANIFEST: &str = include_str!("../../../examples/org.librehub.Hello.json");
struct Provider {
    resolutions: AtomicUsize,
    fetches: AtomicUsize,
    fail: bool,
}
#[async_trait]
impl SourceProvider for Provider {
    async fn resolve_revision(&self, _: &ProjectSource, _: &str) -> Result<String, SourceError> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok("a".repeat(40))
    }
    async fn fetch_source(
        &self,
        _: &ProjectSource,
        _: &str,
        _: &std::path::Path,
    ) -> Result<FetchedSource, SourceError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(SourceError::new("manifest_invalid"));
        }
        let mut files = BTreeMap::new();
        files.insert(
            "org.librehub.Hello.json".into(),
            MANIFEST.as_bytes().to_vec(),
        );
        Ok(FetchedSource {
            workspace: tempfile::tempdir().unwrap(),
            files,
            executable: Default::default(),
        })
    }
    fn discover_manifest(
        &self,
        fetched: &FetchedSource,
        path: Option<&str>,
    ) -> Result<PreparedSource, SourceError> {
        librehub_source::GitSource::default().discover_manifest(fetched, path)
    }
}
struct Harness {
    root: tempfile::TempDir,
    store: Store,
    app: Router,
    worker: SourceWorker,
    provider: Arc<Provider>,
    owner: DeveloperId,
    token: String,
    other_token: String,
}
impl Harness {
    async fn new(fail: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        let owner = store.create_developer("A".into()).await.unwrap().id;
        let other = store.create_developer("B".into()).await.unwrap().id;
        let token = store
            .issue_token(owner, "A".into(), Scope::developer_defaults())
            .await
            .unwrap()
            .token
            .0;
        let other_token = store
            .issue_token(other, "B".into(), Scope::developer_defaults())
            .await
            .unwrap()
            .token
            .0;
        let supervisor = Supervisor::new(store.clone());
        let provider = Arc::new(Provider {
            resolutions: AtomicUsize::new(0),
            fetches: AtomicUsize::new(0),
            fail,
        });
        let worker = SourceWorker::new(supervisor.clone(), provider.clone(), None);
        worker.recover().await.unwrap();
        let key = auth::encryption_key(root.path()).unwrap();
        let app = librehub_api::platform::router(
            ApiState {
                supervisor,
                architecture: Architecture::native(),
            },
            None,
            Platform {
                worker: worker.clone(),
                key,
            },
        );
        Self {
            root,
            store,
            app,
            worker,
            provider,
            owner,
            token,
            other_token,
        }
    }
    async fn project(&self) -> (ProjectId, String) {
        let (status,value)=request(&self.app,"POST","/api/v1/projects",Some(&self.token),Some(json!({"slug":"hello","display_name":"Hello","repository":{"provider":"github","url":"https://github.com/example/hello"},"auto_build":true,"build_tags":true}))).await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        (
            value["project"]["id"].as_str().unwrap().parse().unwrap(),
            value["webhook_secret"].as_str().unwrap().into(),
        )
    }
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"))
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn signature(secret: &str, bytes: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(bytes);
    format!("sha256={:x}", mac.finalize().into_bytes())
}
async fn webhook(
    app: &Router,
    id: ProjectId,
    secret: &str,
    delivery: uuid::Uuid,
    kind: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let body = payload.to_string();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/webhooks/github/{id}"))
        .header("x-github-delivery", delivery.to_string())
        .header("x-github-event", kind)
        .header("x-hub-signature-256", signature(secret, body.as_bytes()))
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, value)
}
fn push(branch: &str) -> Value {
    json!({"ref":format!("refs/heads/{branch}"),"after":"b".repeat(40),"deleted":false,"repository":{"clone_url":"https://github.com/example/hello.git"}})
}
#[tokio::test]
async fn tokens_are_hashed_redacted_scoped_revocable_and_returned_once() {
    let h = Harness::new(false).await;
    let (status, issued) = request(
        &h.app,
        "POST",
        "/api/v1/tokens",
        Some(&h.token),
        Some(json!({"name":"read only","scopes":["projects:read"]})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let raw = issued["token"].as_str().unwrap();
    let db = rusqlite::Connection::open(h.root.path().join("builds.sqlite3")).unwrap();
    let (hash, record): (Vec<u8>, String) = db
        .query_row(
            "SELECT hash,record FROM api_tokens WHERE id=?1",
            [issued["id"].as_str().unwrap()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(hash.len(), 32);
    assert!(!record.contains(raw));
    assert!(!format!("{:?}", Secret(raw.into())).contains(raw));
    let (_, listed) = request(&h.app, "GET", "/api/v1/tokens", Some(&h.token), None).await;
    assert!(!listed.to_string().contains(raw));
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t.get("token").is_none())
    );
    assert_eq!(
        request(
            &h.app,
            "POST",
            "/api/v1/projects",
            Some(raw),
            Some(json!({}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(
        h.store
            .authenticate(Secret(raw.into()))
            .await
            .unwrap()
            .is_some()
    );
    let mut wrong = raw.to_owned();
    wrong.pop();
    wrong.push('x');
    assert!(h.store.authenticate(Secret(wrong)).await.unwrap().is_none());
    assert_eq!(
        request(
            &h.app,
            "DELETE",
            &format!("/api/v1/tokens/{}", issued["id"].as_str().unwrap()),
            Some(&h.token),
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&h.app, "GET", "/api/v1/projects", Some(raw), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn tokens_cannot_escalate_or_revoke_another_developer() {
    let h = Harness::new(false).await;
    let scoped = h
        .store
        .issue_token(h.owner, "limited".into(), vec![Scope::TokensWrite])
        .await
        .unwrap();
    for scope in ["projects:write", "operator"] {
        assert_eq!(
            request(
                &h.app,
                "POST",
                "/api/v1/tokens",
                Some(&scoped.token.0),
                Some(json!({"name":"escalate","scopes":[scope]}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(
            &h.app,
            "DELETE",
            &format!("/api/v1/tokens/{}", scoped.record.id),
            Some(&h.other_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn auth_is_mandatory_on_all_old_build_and_publish_routes() {
    let h = Harness::new(false).await;
    for (method, path) in [
        ("POST", "/api/v1/builds".into()),
        ("GET", format!("/api/v1/builds/{}", BuildId::new())),
        ("POST", format!("/api/v1/builds/{}/publish", BuildId::new())),
        ("GET", format!("/api/v1/publishes/{}", PublishId::new())),
    ] {
        let (status, body) = request(&h.app, method, &path, None, Some(json!({}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "authentication_required");
    }
}
#[tokio::test]
async fn authorization_header_is_removed_before_downstream_handling() {
    let h = Harness::new(false).await;
    let app = Router::new()
        .route(
            "/api/v1/probe",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                Json(json!({"authorization":headers.get("authorization").is_some()}))
            }),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            h.store.clone(),
            auth::middleware,
        ));
    let (status, body) = request(&app, "GET", "/api/v1/probe", Some(&h.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authorization"], false);
}
use axum::Json;
#[tokio::test]
async fn ownership_isolation_covers_metadata_mutation_build_secret_audit_and_publish() {
    let h = Harness::new(false).await;
    let (id, _) = h.project().await;
    for (method, path, body) in [
        ("GET", format!("/api/v1/projects/{id}"), None),
        (
            "PATCH",
            format!("/api/v1/projects/{id}"),
            Some(json!({"display_name":"stolen"})),
        ),
        ("DELETE", format!("/api/v1/projects/{id}"), None),
        (
            "POST",
            format!("/api/v1/projects/{id}/builds"),
            Some(json!({"ref":"main"})),
        ),
        (
            "POST",
            format!("/api/v1/projects/{id}/webhook-secret/rotate"),
            None,
        ),
        ("GET", format!("/api/v1/projects/{id}/audit"), None),
        ("GET", format!("/api/v1/projects/{id}/builds"), None),
    ] {
        assert_eq!(
            request(&h.app, method, &path, Some(&h.other_token), body)
                .await
                .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let (_, trigger) = request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        Some(json!({"ref":"main"})),
    )
    .await;
    let event = h.store.pending_source().await.unwrap().unwrap();
    h.worker.process(event).await.unwrap();
    let build = trigger["build_id"].as_str().unwrap();
    for (method, path) in [
        ("GET", format!("/api/v1/builds/{build}")),
        ("GET", format!("/api/v1/builds/{build}/logs")),
        ("POST", format!("/api/v1/builds/{build}/cancel")),
        ("POST", format!("/api/v1/builds/{build}/publish")),
        ("GET", format!("/api/v1/builds/{build}/publishes")),
    ] {
        assert_eq!(
            request(
                &h.app,
                method,
                &path,
                Some(&h.other_token),
                Some(json!({"channel":"beta"}))
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let (_, audits) = request(&h.app, "GET", "/api/v1/audit", Some(&h.other_token), None).await;
    assert!(
        audits
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["project_id"] != id.to_string())
    );
}
#[test]
fn github_hmac_accepts_only_correct_signature_and_never_panics_on_unicode() {
    let secret = Secret("secret".into());
    let body = b"{\"ref\":\"main\"}";
    let sig = signature(&secret.0, body);
    assert!(verify_signature(&secret, body, Some(&sig)));
    assert!(!verify_signature(&secret, b"changed", Some(&sig)));
    assert!(!verify_signature(&secret, body, None));
    assert!(!verify_signature(
        &secret,
        body,
        Some(&format!("sha256={}", "é".repeat(32)))
    ));
}
#[tokio::test]
async fn webhook_signature_is_checked_before_payload_parsing() {
    let h = Harness::new(false).await;
    let (id, secret) = h.project().await;
    let raw = b"invalid-json";
    for sig in [None, Some(signature("wrong", raw))] {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/webhooks/github/{id}"));
        if let Some(sig) = sig {
            req = req.header("x-hub-signature-256", sig)
        }
        let res = h
            .app
            .clone()
            .oneshot(req.body(Body::from(raw.as_slice())).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(!secret.is_empty());
}
#[tokio::test]
async fn webhook_duplicates_are_transactional_even_when_concurrent() {
    let h = Harness::new(false).await;
    let (id, secret) = h.project().await;
    let delivery = uuid::Uuid::new_v4();
    let (a, b) = tokio::join!(
        webhook(&h.app, id, &secret, delivery, "push", push("main")),
        webhook(&h.app, id, &secret, delivery, "push", push("main"))
    );
    assert!(a.0.is_success() && b.0.is_success());
    assert!([&a.1, &b.1].iter().any(|v| v["status"] == "duplicate"));
    let events = h.store.project_events(id, 100, 0).await.unwrap();
    assert_eq!(events.len(), 1);
    h.worker.process(events[0].clone()).await.unwrap();
    assert_eq!(h.store.pending().await.unwrap().len(), 1);
    let (_, dup) = webhook(&h.app, id, &secret, delivery, "push", push("main")).await;
    assert_eq!(dup["status"], "duplicate");
    assert_eq!(h.store.pending().await.unwrap().len(), 1);
}
#[tokio::test]
async fn webhook_branch_tag_disabled_and_unsupported_event_policies() {
    let h = Harness::new(false).await;
    let (id, secret) = h.project().await;
    for (kind, payload) in [("push", push("feature")), ("ping", json!({"zen":"test"}))] {
        assert_eq!(
            webhook(&h.app, id, &secret, uuid::Uuid::new_v4(), kind, payload)
                .await
                .1["status"],
            "ignored"
        );
    }
    let payload = json!({"ref":"v1.0","ref_type":"tag","repository":{"clone_url":"https://github.com/example/hello.git"}});
    assert_eq!(
        webhook(&h.app, id, &secret, uuid::Uuid::new_v4(), "create", payload)
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (_, project) = request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"status":"disabled"})),
    )
    .await;
    assert_eq!(project["status"], "disabled");
    assert_eq!(
        webhook(
            &h.app,
            id,
            &secret,
            uuid::Uuid::new_v4(),
            "push",
            push("main")
        )
        .await
        .1["status"],
        "ignored"
    );
    assert_eq!(h.store.project_events(id, 100, 0).await.unwrap().len(), 1);
}
#[tokio::test]
async fn secret_rotation_invalidates_old_signatures_and_ciphertext_is_bound_to_project() {
    let h = Harness::new(false).await;
    let (id, old) = h.project().await;
    let (_, value) = request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/webhook-secret/rotate"),
        Some(&h.token),
        None,
    )
    .await;
    let new = value["webhook_secret"].as_str().unwrap();
    assert_ne!(new, old);
    assert_eq!(
        webhook(&h.app, id, &old, uuid::Uuid::new_v4(), "push", push("main"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        webhook(&h.app, id, new, uuid::Uuid::new_v4(), "push", push("main"))
            .await
            .0,
        StatusCode::ACCEPTED
    );
    let (_, cipher) = h.store.webhook_connection(id).await.unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&cipher).contains(new));
    let key = auth::encryption_key(h.root.path()).unwrap();
    assert!(auth::decrypt_secret(&key, ProjectId::new(), &cipher).is_err());
}
#[tokio::test]
async fn restart_at_source_stages_retains_revision_and_handoff_is_at_most_once() {
    for stage in [
        SourceEventStatus::Queued,
        SourceEventStatus::Fetching,
        SourceEventStatus::Handoff,
    ] {
        let h = Harness::new(false).await;
        let (id, _) = h.project().await;
        let admitted = h
            .store
            .admit_source(
                SourceAdmission {
                    project_id: id,
                    owner: Some(h.owner),
                    trigger: TriggerType::Manual,
                    source_ref: "main".into(),
                    commit: Some("b".repeat(40)),
                    webhook: None,
                },
                false,
            )
            .await
            .unwrap();
        let Admission::Created(event) = admitted else {
            panic!()
        };
        let mut event = *event;
        event.status = stage;
        h.store.save_source(event.clone()).await.unwrap();
        let restarted = SourceWorker::new(h.worker.supervisor.clone(), h.provider.clone(), None);
        restarted.recover().await.unwrap();
        restarted
            .process(h.store.pending_source().await.unwrap().unwrap())
            .await
            .unwrap();
        assert_eq!(h.provider.resolutions.load(Ordering::SeqCst), 0);
        let build = h.store.get(event.build_id).await.unwrap().unwrap();
        assert_eq!(
            build.provenance.as_ref().unwrap().revision.commit,
            "b".repeat(40)
        );
        let manifest = h.store.manifest(event.build_id).await.unwrap();
        h.store
            .handoff_source(
                event.id,
                manifest,
                build.provenance.unwrap(),
                Architecture::native(),
            )
            .await
            .unwrap();
        assert_eq!(h.store.pending().await.unwrap().len(), 1);
        assert!(h.store.pending_source().await.unwrap().is_none());
    }
}
#[tokio::test]
async fn source_failures_are_visible_in_bounded_project_history() {
    let h = Harness::new(true).await;
    let (id, _) = h.project().await;
    request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        Some(json!({"ref":"main"})),
    )
    .await;
    h.worker
        .process(h.store.pending_source().await.unwrap().unwrap())
        .await
        .unwrap();
    let (status, history) = request(
        &h.app,
        "GET",
        &format!("/api/v1/projects/{id}/builds?limit=1"),
        Some(&h.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history[0]["source_status"], "failed");
    assert_eq!(history[0]["error"]["code"], "manifest_invalid");
    assert_eq!(
        request(
            &h.app,
            "GET",
            "/api/v1/projects?limit=10000",
            Some(&h.token),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn archival_retains_history_and_stops_new_triggers() {
    let h = Harness::new(false).await;
    let (id, secret) = h.project().await;
    request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        Some(json!({"ref":"main"})),
    )
    .await;
    let event = h.store.pending_source().await.unwrap().unwrap();
    request(
        &h.app,
        "DELETE",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        None,
    )
    .await;
    h.worker.process(event).await.unwrap();
    assert!(h.store.pending().await.unwrap().is_empty());
    assert_eq!(
        request(
            &h.app,
            "POST",
            &format!("/api/v1/projects/{id}/builds"),
            Some(&h.token),
            Some(json!({"ref":"main"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        webhook(
            &h.app,
            id,
            &secret,
            uuid::Uuid::new_v4(),
            "push",
            push("main")
        )
        .await
        .1["status"],
        "ignored"
    );
    let (_, history) = request(
        &h.app,
        "GET",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        None,
    )
    .await;
    assert_eq!(history.as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn policy_changes_suppress_stale_auto_publish() {
    let h = Harness::new(false).await;
    let (id, _) = h.project().await;
    request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"auto_publish_channel":"beta"})),
    )
    .await;
    request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        Some(json!({"ref":"main"})),
    )
    .await;
    let event = h.store.pending_source().await.unwrap().unwrap();
    assert!(h.store.auto_policy_valid(event.clone()).await.unwrap());
    request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"auto_publish_channel":"none"})),
    )
    .await;
    assert!(!h.store.auto_policy_valid(event.clone()).await.unwrap());
    assert!(
        h.store
            .enqueue_auto_publish(event.id, RepositoryChannel::Beta)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn additive_migration_preserves_m2_records_and_old_json_without_provenance() {
    let root = tempfile::tempdir().unwrap();
    let id = BuildId::new();
    let record = json!({"id":id,"status":"queued","architecture":"x86_64","created_at":"2026-10-03T00:00:00Z","updated_at":"2026-10-03T00:00:00Z","started_at":null,"finished_at":null,"manifest":{"app_id":"org.librehub.Hello","runtime":"org.freedesktop.Platform","runtime_version":"25.08","sdk":"org.freedesktop.Sdk"},"result":null,"error":null,"cancellation_requested":false,"logs_truncated":false});
    {
        let db = rusqlite::Connection::open(root.path().join("builds.sqlite3")).unwrap();
        db.execute_batch("CREATE TABLE builds(id TEXT PRIMARY KEY,status TEXT NOT NULL,record TEXT NOT NULL,manifest TEXT NOT NULL,log_bytes INTEGER NOT NULL DEFAULT 0,log_count INTEGER NOT NULL DEFAULT 0,cleanup_pending INTEGER NOT NULL DEFAULT 0);CREATE TABLE logs(build_id TEXT NOT NULL REFERENCES builds(id),sequence INTEGER NOT NULL,entry TEXT NOT NULL,PRIMARY KEY(build_id,sequence));").unwrap();
        db.execute_batch(include_str!("../migrations/002_publications.sql"))
            .unwrap();
        db.execute(
            "INSERT INTO builds(id,status,record,manifest) VALUES(?1,'queued',?2,?3)",
            rusqlite::params![id.to_string(), record.to_string(), MANIFEST],
        )
        .unwrap();
    }
    let store = Store::open(root.path()).unwrap();
    let stored = store.get(id).await.unwrap().unwrap();
    assert_eq!(stored.id, id);
    assert!(stored.provenance.is_none());
    assert!(store.publications(id).await.unwrap().is_empty());
    drop(store);
    let store = Store::open(root.path()).unwrap();
    assert_eq!(store.pending().await.unwrap(), vec![id]);
    let db = rusqlite::Connection::open(root.path().join("builds.sqlite3")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM schema_migrations WHERE version IN(2,3)",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
}
async fn automatic_publication_fixture() -> (Harness, ProjectId, SourceEvent) {
    let h = Harness::new(false).await;
    let (id, _) = h.project().await;
    request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"auto_publish_channel":"beta"})),
    )
    .await;
    request(
        &h.app,
        "POST",
        &format!("/api/v1/projects/{id}/builds"),
        Some(&h.token),
        Some(json!({"ref":"main"})),
    )
    .await;
    let event = h.store.pending_source().await.unwrap().unwrap();
    h.worker.process(event.clone()).await.unwrap();
    let build = event.build_id;
    h.store
        .transition(build, BuildStatus::Validating, None, None)
        .await
        .unwrap();
    h.store
        .transition(build, BuildStatus::Building, None, None)
        .await
        .unwrap();
    h.store
        .transition(
            build,
            BuildStatus::Succeeded,
            Some(BuildResult {
                exit_code: Some(0),
                artifacts: vec![Artifact {
                    path: format!("builds/{build}/artifacts/application.flatpak"),
                    size_bytes: 1,
                    sha256: "a".repeat(64),
                }],
            }),
            None,
        )
        .await
        .unwrap();
    (h, id, event)
}

#[tokio::test]
async fn queued_automatic_publication_is_cancelled_after_policy_change() {
    let (h, id, event) = automatic_publication_fixture().await;
    let manual = h
        .store
        .enqueue_publish(event.build_id, RepositoryChannel::Stable)
        .await
        .unwrap();
    let publication = h
        .store
        .enqueue_auto_publish(event.id, RepositoryChannel::Beta)
        .await
        .unwrap()
        .unwrap();
    request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"auto_publish_channel":"none"})),
    )
    .await;
    assert!(
        h.store
            .claim_publication(publication.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.store
            .publish_record(publication.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        PublishStatus::Cancelled
    );
    assert_eq!(
        h.store
            .claim_publication(manual.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        PublishStatus::Preparing
    );
}

#[tokio::test]
async fn automatic_admission_does_not_adopt_existing_manual_publication() {
    let (h, id, event) = automatic_publication_fixture().await;
    let manual = h
        .store
        .enqueue_publish(event.build_id, RepositoryChannel::Beta)
        .await
        .unwrap();
    let automatic = h
        .store
        .enqueue_auto_publish(event.id, RepositoryChannel::Beta)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(automatic.id, manual.id);
    assert!(
        h.store
            .enqueue_auto_publish(event.id, RepositoryChannel::Beta)
            .await
            .unwrap()
            .is_none()
    );
    let db = rusqlite::Connection::open(h.root.path().join("builds.sqlite3")).unwrap();
    let associated: Option<String> = db
        .query_row(
            "SELECT auto_publish_id FROM source_events WHERE id=?1",
            [event.id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(associated.is_none());
    request(
        &h.app,
        "PATCH",
        &format!("/api/v1/projects/{id}"),
        Some(&h.token),
        Some(json!({"auto_publish_channel":"none"})),
    )
    .await;
    assert_eq!(
        h.store
            .claim_publication(manual.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        PublishStatus::Preparing
    );
}
#[tokio::test]
async fn invalid_slug_repository_paths_and_webhook_size_are_rejected() {
    let h = Harness::new(false).await;
    for (slug, url) in [
        ("../escape", "https://github.com/example/hello"),
        ("safe", "file:///etc/passwd"),
        ("safe", "https://127.0.0.1/private"),
    ] {
        assert_eq!(request(&h.app,"POST","/api/v1/projects",Some(&h.token),Some(json!({"slug":slug,"display_name":"test","repository":{"provider":"git","url":url}}))).await.0,StatusCode::BAD_REQUEST);
    }
    let (id, _) = h.project().await;
    let res = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/webhooks/github/{id}"))
                .body(Body::from(vec![b'x'; 256 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn developer_cannot_publish_over_another_developers_application_id() {
    let h = Harness::new(false).await;
    let other = h
        .store
        .authenticate(Secret(h.other_token.clone()))
        .await
        .unwrap()
        .unwrap()
        .developer_id;
    let manifest = librehub_validator::validate(MANIFEST, ManifestFormat::Json).unwrap();
    let mut ids = Vec::new();
    for owner in [h.owner, other] {
        let build = h
            .store
            .insert_owned(manifest.clone(), Architecture::native(), Some(owner))
            .await
            .unwrap();
        let id = build.id;
        h.store
            .transition(id, BuildStatus::Validating, None, None)
            .await
            .unwrap();
        h.store
            .transition(id, BuildStatus::Building, None, None)
            .await
            .unwrap();
        h.store
            .transition(
                id,
                BuildStatus::Succeeded,
                Some(BuildResult {
                    exit_code: Some(0),
                    artifacts: vec![Artifact {
                        path: format!("builds/{id}/artifacts/application.flatpak"),
                        size_bytes: 1,
                        sha256: "a".repeat(64),
                    }],
                }),
                None,
            )
            .await
            .unwrap();
        ids.push(id);
    }
    h.store
        .enqueue_publish(ids[0], RepositoryChannel::Beta)
        .await
        .unwrap();
    let error = h
        .store
        .enqueue_publish(ids[1], RepositoryChannel::Stable)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("another developer"));
}

#[tokio::test]
async fn invalid_token_names_and_token_quota_are_client_errors() {
    let h = Harness::new(false).await;
    for name in ["", " \t\n", "\u{2003}"] {
        let (status, body) = request(
            &h.app,
            "POST",
            "/api/v1/tokens",
            Some(&h.token),
            Some(json!({"name":name,"scopes":["projects:read"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "invalid_request");
        let error = h
            .store
            .issue_token(h.owner, name.into(), vec![Scope::ProjectsRead])
            .await
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<librehub_api::platform_store::PlatformError>()
                .unwrap()
                .0,
            "invalid_request"
        );
    }
    for _ in 1..32 {
        h.store
            .issue_token(h.owner, "quota".into(), vec![Scope::ProjectsRead])
            .await
            .unwrap();
    }
    let (status, body) = request(
        &h.app,
        "POST",
        "/api/v1/tokens",
        Some(&h.token),
        Some(json!({"name":"overflow","scopes":["projects:read"]})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "token_limit_exceeded");
    let token = h.store.tokens(h.owner, 1, 0).await.unwrap()[0].id;
    h.store.revoke_token(h.owner, token).await.unwrap();
    assert_eq!(
        request(
            &h.app,
            "POST",
            "/api/v1/tokens",
            Some(&h.token),
            Some(json!({"name":"replacement","scopes":["projects:read"]}))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let db = rusqlite::Connection::open(h.root.path().join("builds.sqlite3")).unwrap();
    db.execute(
        "UPDATE developers SET status='disabled' WHERE id=?1",
        [h.owner.to_string()],
    )
    .unwrap();
    let error = h
        .store
        .issue_token(h.owner, "disabled".into(), vec![Scope::ProjectsRead])
        .await
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<librehub_api::platform_store::PlatformError>()
            .unwrap()
            .0,
        "developer_disabled"
    );
}

#[tokio::test]
async fn existing_m3_database_gains_automatic_publication_id_on_reopen() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let owner = store.create_developer("preserved".into()).await.unwrap().id;
    drop(store);
    let db = rusqlite::Connection::open(root.path().join("builds.sqlite3")).unwrap();
    db.execute_batch("ALTER TABLE source_events DROP COLUMN auto_publish_id;")
        .unwrap();
    drop(Store::open(root.path()).unwrap());
    let store = Store::open(root.path()).unwrap();
    store
        .issue_token(owner, "after migration".into(), vec![Scope::ProjectsRead])
        .await
        .unwrap();
    db.prepare("SELECT auto_publish_id FROM source_events")
        .unwrap();
}

// Stop after one admission pass so pending/retry state can be inspected deterministically.
struct AdmissionPublisher(tokio_util::sync::CancellationToken);
#[async_trait]
impl librehub_publisher::Publisher for AdmissionPublisher {
    async fn eligible(
        &self,
        _: BuildRecord,
        _: FlatpakManifest,
        _: std::path::PathBuf,
    ) -> Result<(), librehub_publisher::PublishError> {
        self.0.cancel();
        Ok(())
    }
    async fn publish(
        &self,
        _: librehub_publisher::PublishJob,
        _: &dyn librehub_publisher::PublishJournal,
    ) -> Result<PublishResult, librehub_publisher::PublishError> {
        unreachable!("Only admission is exercised")
    }
    async fn ready(&self) -> bool {
        true
    }
    async fn repository_ready(&self) -> bool {
        true
    }
}

async fn run_automatic_admission(h: &Harness) -> anyhow::Result<()> {
    let supervisor = Supervisor::new(h.store.clone());
    let publishing = librehub_api::publishing::Publishing::new(
        h.store.clone(),
        Arc::new(AdmissionPublisher(supervisor.shutdown.clone())),
        librehub_publisher::repository::RepositoryConfig {
            public_base_url: "http://localhost:8090".into(),
            public_key: b"public".to_vec(),
            fingerprint: "A".repeat(40),
            runtime_repo_url: "https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
        },
        1,
        supervisor.shutdown.clone(),
    )
    .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        SourceWorker::new(supervisor, h.provider.clone(), Some(publishing)).run(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn automatic_admission_retries_only_full_and_propagates_storage_errors() {
    for case in ["owned", "ineligible", "full", "storage"] {
        let (h, _, event) = automatic_publication_fixture().await;
        let db = rusqlite::Connection::open(h.root.path().join("builds.sqlite3")).unwrap();
        match case {
            "owned" => {
                let other = h
                    .store
                    .authenticate(Secret(h.other_token.clone()))
                    .await
                    .unwrap()
                    .unwrap();
                db.execute("INSERT INTO application_owners(app_id,developer_id) VALUES('org.librehub.Hello',?1)", [other.developer_id.to_string()]).unwrap();
            }
            "ineligible" => {
                db.execute("UPDATE builds SET record=json_set(record,'$.result.artifacts',json('[]')) WHERE id=?1", [event.build_id.to_string()]).unwrap();
            }
            "full" => {
                // Distinct synthetic builds/publications fill the durable queue.
                let record = h
                    .store
                    .enqueue_publish(event.build_id, RepositoryChannel::Stable)
                    .await
                    .unwrap();
                for _ in 1..64 {
                    let build = BuildId::new();
                    db.execute("INSERT INTO builds(id,status,record,manifest) SELECT ?1,status,record,manifest FROM builds WHERE id=?2", rusqlite::params![build.to_string(), event.build_id.to_string()]).unwrap();
                    let mut queued = record.clone();
                    queued.id = PublishId::new();
                    queued.build_id = build;
                    db.execute("INSERT INTO publishes(id,build_id,channel,status,record) VALUES(?1,?2,'stable','queued',?3)", rusqlite::params![queued.id.to_string(), build.to_string(), serde_json::to_string(&queued).unwrap()]).unwrap();
                }
            }
            "storage" => {
                db.execute_batch("CREATE TRIGGER reject_publication BEFORE INSERT ON publishes BEGIN SELECT RAISE(ABORT,'storage failure'); END;").unwrap();
            }
            _ => unreachable!(),
        }
        let result = run_automatic_admission(&h).await;
        assert_eq!(result.is_err(), case == "storage", "{case}: {result:?}");
        let state: String = db
            .query_row(
                "SELECT auto_publish_state FROM source_events WHERE id=?1",
                [event.id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            state,
            if matches!(case, "full" | "storage") {
                "pending"
            } else {
                "failed"
            },
            "{case}"
        );
        assert_eq!(
            h.store.auto_publish_candidates().await.unwrap().len(),
            usize::from(matches!(case, "full" | "storage"))
        );
        if case == "full" {
            db.execute("UPDATE publishes SET status='cancelled'", [])
                .unwrap();
            run_automatic_admission(&h).await.unwrap();
            let state: String = db
                .query_row(
                    "SELECT auto_publish_state FROM source_events WHERE id=?1",
                    [event.id.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(state, "queued");
        }
    }
}
