//! Shared in-process M7 harness: real stores, supervisors and HTTP router; fake Git, builder
//! output and publisher. Everything between those edges is production code.
#![allow(dead_code)]
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use librehub_api::{
    ApiState, auth,
    automation_http::{self, AutomationHttp},
    automation_worker::AutomationWorker,
    integration_http::{self, IntegrationHttp},
    oidc_verifier::{JwksFetcher, OidcVerifier},
    outbound_worker::{OutboundWorker, StaticResolver, Transport, TransportResult},
    platform::Platform,
    publishing::Publishing,
    source_worker::SourceWorker,
    store::Store,
    worker::Supervisor,
};
use librehub_automation::{
    oidc::{GithubIdentityPolicy, JwkSet, OidcConfig, testing},
    webhook::{Destination, DestinationPolicy},
};
use librehub_common::*;
use librehub_publisher::{
    PublishError, PublishJob, PublishJournal, Publisher, repository::RepositoryConfig,
};
use librehub_source::{FetchedSource, PreparedSource, SourceError, SourceProvider};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

pub const MANIFEST: &str = include_str!("../../../../examples/org.librehub.Hello.json");
pub const NOW_OFFSET: i64 = 0;

pub struct Provider {
    pub commits: Mutex<BTreeMap<String, String>>,
    pub fetches: AtomicUsize,
    pub resolutions: AtomicUsize,
    pub fail_resolution: Mutex<Option<SourceError>>,
}
impl Provider {
    pub fn commit(c: char) -> String {
        c.to_string().repeat(40)
    }
}
#[async_trait]
impl SourceProvider for Provider {
    async fn resolve_revision(
        &self,
        _: &ProjectSource,
        source_ref: &str,
    ) -> Result<String, SourceError> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = self.fail_resolution.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(self
            .commits
            .lock()
            .unwrap()
            .get(source_ref)
            .cloned()
            .unwrap_or_else(|| Self::commit('a')))
    }
    async fn fetch_source(
        &self,
        _: &ProjectSource,
        _: &str,
        _: &std::path::Path,
    ) -> Result<FetchedSource, SourceError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
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

pub struct FakePublisher {
    pub calls: AtomicUsize,
    pub by_channel: Mutex<Vec<String>>,
    pub fail: Mutex<bool>,
}
#[async_trait]
impl Publisher for FakePublisher {
    async fn eligible(
        &self,
        build: BuildRecord,
        _: FlatpakManifest,
        _: PathBuf,
    ) -> Result<(), PublishError> {
        if build.status != BuildStatus::Succeeded {
            return Err(PublishError::Ineligible);
        }
        Ok(())
    }
    async fn publish(
        &self,
        job: PublishJob,
        journal: &dyn PublishJournal,
    ) -> Result<PublishResult, PublishError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.by_channel
            .lock()
            .unwrap()
            .push(job.record.channel.to_string());
        if *self.fail.lock().unwrap() {
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
                commit: if record.channel == RepositoryChannel::Stable {
                    "c".repeat(64)
                } else {
                    "a".repeat(64)
                },
                source_commit: "b".repeat(64),
                repository_url: format!("http://localhost/repo/{}/", record.channel),
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
pub fn repository() -> RepositoryConfig {
    RepositoryConfig {
        public_base_url: "http://localhost:8090".into(),
        public_key: b"public".to_vec(),
        fingerprint: "A".repeat(40),
        runtime_repo_url: "https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
    }
}

pub struct StaticJwks(pub Mutex<JwkSet>);
#[async_trait]
impl JwksFetcher for StaticJwks {
    async fn fetch(&self) -> anyhow::Result<JwkSet> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Clone, Debug)]
pub struct Recorded {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub pinned: Vec<SocketAddr>,
}
pub struct FakeTransport {
    pub requests: Mutex<Vec<Recorded>>,
    pub script: Mutex<Vec<TransportResult>>,
    pub observer: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}
#[async_trait]
impl Transport for FakeTransport {
    async fn post(
        &self,
        destination: &Destination,
        pinned: &[SocketAddr],
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> TransportResult {
        if let Some(observer) = self.observer.lock().unwrap().as_ref() {
            observer();
        }
        self.requests.lock().unwrap().push(Recorded {
            url: destination.url.to_string(),
            headers,
            body,
            pinned: pinned.to_vec(),
        });
        let mut script = self.script.lock().unwrap();
        if script.len() > 1 {
            script.remove(0)
        } else {
            script
                .first()
                .cloned()
                .unwrap_or(TransportResult::Response {
                    status: 200,
                    retry_after: None,
                })
        }
    }
}

pub struct Env {
    pub root: tempfile::TempDir,
    pub store: Store,
    pub supervisor: Supervisor,
    pub app: Router,
    pub source: SourceWorker,
    pub provider: Arc<Provider>,
    pub publisher: Arc<FakePublisher>,
    pub publishing: Publishing,
    pub automation: AutomationWorker,
    pub outbound: OutboundWorker,
    pub transport: Arc<FakeTransport>,
    pub resolver: Arc<StaticResolver>,
    pub jwks: Arc<StaticJwks>,
    pub owner: DeveloperId,
    pub token: String,
    pub other: DeveloperId,
    pub other_token: String,
    pub shutdown: CancellationToken,
    pub tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    pub key: [u8; 32],
}

pub const AUDIENCE: &str = "librehub-test";

impl Env {
    pub async fn new() -> Self {
        Self::at(tempfile::tempdir().unwrap(), true).await
    }
    /// `spawn_workers=false` leaves every loop to be stepped manually.
    pub async fn at(root: tempfile::TempDir, spawn_workers: bool) -> Self {
        let store = Store::open(root.path()).unwrap();
        Self::build(root, store, spawn_workers, None).await
    }
    pub async fn build(
        root: tempfile::TempDir,
        store: Store,
        spawn_workers: bool,
        ids: Option<(DeveloperId, String, DeveloperId, String)>,
    ) -> Self {
        let (owner, token, other, other_token) = match ids {
            Some(ids) => ids,
            None => {
                let owner = store.create_developer("Owner".into()).await.unwrap().id;
                let other = store.create_developer("Other".into()).await.unwrap().id;
                let token = store
                    .issue_token(owner, "owner".into(), Scope::developer_defaults())
                    .await
                    .unwrap()
                    .token
                    .0;
                let other_token = store
                    .issue_token(other, "other".into(), Scope::developer_defaults())
                    .await
                    .unwrap()
                    .token
                    .0;
                (owner, token, other, other_token)
            }
        };
        let supervisor = Supervisor::new(store.clone());
        let shutdown = supervisor.shutdown.clone();
        let provider = Arc::new(Provider {
            commits: Mutex::new(BTreeMap::new()),
            fetches: AtomicUsize::new(0),
            resolutions: AtomicUsize::new(0),
            fail_resolution: Mutex::new(None),
        });
        let publisher = Arc::new(FakePublisher {
            calls: AtomicUsize::new(0),
            by_channel: Mutex::new(vec![]),
            fail: Mutex::new(false),
        });
        let publishing = Publishing::new(
            store.clone(),
            publisher.clone(),
            repository(),
            1,
            shutdown.clone(),
        )
        .unwrap();
        let source = SourceWorker::new(
            supervisor.clone(),
            provider.clone(),
            Some(publishing.clone()),
        );
        source.recover().await.unwrap();
        let key = auth::encryption_key(&store.data_dir).unwrap();
        let platform = librehub_api::platform::router(
            ApiState {
                supervisor: supervisor.clone(),
                architecture: Architecture::native(),
            },
            Some(publishing.clone()),
            Platform {
                worker: source.clone(),
                key,
            },
        );
        let automation = AutomationWorker::new(
            store.clone(),
            provider.clone(),
            Some(publishing.clone()),
            supervisor.wake.clone(),
            source.wake.clone(),
            shutdown.clone(),
        );
        let transport = Arc::new(FakeTransport {
            requests: Mutex::new(vec![]),
            script: Mutex::new(vec![]),
            observer: Mutex::new(None),
        });
        let resolver = Arc::new(StaticResolver::default());
        let outbound = OutboundWorker::new(
            store.clone(),
            key,
            transport.clone(),
            resolver.clone(),
            DestinationPolicy::default(),
            shutdown.clone(),
        );
        let jwks = Arc::new(StaticJwks(Mutex::new(JwkSet::default())));
        let verifier = Arc::new(OidcVerifier::new(
            OidcConfig::github(AUDIENCE),
            jwks.clone(),
        ));
        let state = IntegrationHttp {
            store: store.clone(),
            key,
            verifier: Some(verifier),
            policy: DestinationPolicy::default(),
            resolver: resolver.clone(),
        };
        let guard = |r: Router| {
            r.route_layer(axum::middleware::from_fn_with_state(
                store.clone(),
                auth::middleware,
            ))
        };
        let app = platform
            .merge(guard(automation_http::router(AutomationHttp {
                store: store.clone(),
                wake: automation.wake.clone(),
            })))
            .merge(guard(integration_http::private_router(state.clone())))
            .merge(integration_http::public_router(state));
        let mut env = Self {
            root,
            store,
            supervisor,
            app,
            source,
            provider,
            publisher,
            publishing,
            automation,
            outbound,
            transport,
            resolver,
            jwks,
            owner,
            token,
            other,
            other_token,
            shutdown,
            tasks: vec![],
            key,
        };
        if spawn_workers {
            env.spawn_workers();
        }
        env
    }
    pub fn spawn_workers(&mut self) {
        self.tasks.push(tokio::spawn(self.source.clone().run()));
        self.tasks.push(tokio::spawn(self.publishing.clone().run()));
        self.tasks.push(tokio::spawn(self.automation.clone().run()));
        self.tasks.push(tokio::spawn(self.outbound.clone().run()));
    }
    pub async fn stop(&mut self) {
        self.shutdown.cancel();
        for task in self.tasks.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
    }
    pub fn db(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.root.path().join("builds.sqlite3")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }

    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.app, method, path, token, body).await
    }
    pub async fn project(&self) -> ProjectId {
        let (status, value) = self
            .call("POST", "/api/v1/projects", Some(&self.token), Some(json!({"slug":"hello","display_name":"Hello","repository":{"provider":"github","url":"https://github.com/example/hello"},"auto_build":true,"build_tags":true})))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        value["project"]["id"].as_str().unwrap().parse().unwrap()
    }
    pub async fn automation_with(&self, project: ProjectId, spec: Value) -> (StatusCode, Value) {
        self.call(
            "POST",
            &format!("/api/v1/projects/{project}/automations"),
            Some(&self.token),
            Some(json!({"spec": spec})),
        )
        .await
    }
    pub async fn create_automation(&self, project: ProjectId, spec: Value) -> AutomationId {
        let (status, value) = self.automation_with(project, spec).await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        value["id"].as_str().unwrap().parse().unwrap()
    }
    pub async fn trigger(
        &self,
        project: ProjectId,
        automation: AutomationId,
        body: Value,
    ) -> (StatusCode, Value) {
        self.call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/{automation}/run"),
            Some(&self.token),
            Some(body),
        )
        .await
    }
    pub async fn run_view(&self, project: ProjectId, run: &str) -> Value {
        let (status, value) = self
            .call(
                "GET",
                &format!("/api/v1/projects/{project}/automations/runs/{run}"),
                Some(&self.token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }
    pub async fn wait_run(&self, project: ProjectId, run: &str, want: &[&str]) -> Value {
        for _ in 0..400 {
            let view = self.run_view(project, run).await;
            if want.contains(&view["status"].as_str().unwrap()) {
                return view;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "run never reached {want:?}: {}",
            self.run_view(project, run).await
        );
    }
    pub fn step<'a>(run: &'a Value, id: &str) -> &'a Value {
        run["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .unwrap()
    }
    /// Play the M1 executor: run the queued build to success.
    pub async fn succeed_build(&self, build: BuildId) {
        for _ in 0..200 {
            if self.store.get(build).await.unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        for to in [BuildStatus::Validating, BuildStatus::Building] {
            self.store.transition(build, to, None, None).await.unwrap();
        }
        self.store
            .transition(
                build,
                BuildStatus::Succeeded,
                Some(BuildResult {
                    environment: None,
                    exit_code: Some(0),
                    artifacts: vec![Artifact {
                        path: format!("builds/{build}/artifacts/application.flatpak"),
                        size_bytes: 5,
                        sha256: "a".repeat(64),
                    }],
                }),
                None,
            )
            .await
            .unwrap();
    }
    pub async fn fail_build(&self, build: BuildId) {
        for _ in 0..200 {
            if self.store.get(build).await.unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        for to in [BuildStatus::Validating, BuildStatus::Building] {
            self.store.transition(build, to, None, None).await.unwrap();
        }
        self.store
            .transition(
                build,
                BuildStatus::Failed,
                None,
                Some(BuildError {
                    code: "build_failed".into(),
                    message: "failed".into(),
                }),
            )
            .await
            .unwrap();
    }
    /// Play the M5 analysis worker.
    pub fn analysis(&self, publication: &str, vulnerabilities: &str, finding: Option<&str>) {
        let db = self.db();
        let app: String = db
            .query_row(
                "SELECT json_extract(record,'$.app_id') FROM publishes WHERE id=?1",
                [publication],
                |r| r.get(0),
            )
            .unwrap();
        let channel: String = db
            .query_row(
                "SELECT channel FROM publishes WHERE id=?1",
                [publication],
                |r| r.get(0),
            )
            .unwrap();
        db.execute("INSERT OR REPLACE INTO security_jobs(publication_id,state,updated_at) VALUES(?1,'ready','now')", [publication]).unwrap();
        db.execute(
            "INSERT OR REPLACE INTO release_security(publication_id,app_id,channel,status,sbom_format,sbom_path,sbom_component_count,sbom_sha256,vulnerabilities_status,permissions_extracted_at,permission_severity,created_at,updated_at) VALUES(?1,?2,?3,'ready','spdx-2.3-json','',1,'',?4,'now','none','now','now')",
            rusqlite::params![publication, app, channel, vulnerabilities],
        )
        .unwrap();
        if let Some(severity) = finding {
            db.execute(
                "INSERT INTO vulnerability_findings(id,publication_id,vulnerability_id,component_name,component_version,severity,summary,source_provider,checked_at) VALUES(?1,?2,'CVE-1','lib','1',?3,'x','test','now')",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), publication, severity],
            )
            .unwrap();
        }
    }
}
pub async fn call(
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
        builder = builder.header("authorization", format!("Bearer {token}"));
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

pub fn release_pipeline() -> Value {
    json!({
        "name": "Release Pipeline",
        "triggers": [{"type":"push","branches":["main"]},{"type":"tag","patterns":["v*"]},{"type":"manual"},{"type":"ci"}],
        "steps": [
            {"id":"build","uses":"librehub/build"},
            {"id":"verify","uses":"librehub/verify-provenance","needs":["build"]},
            {"id":"publish-beta","uses":"librehub/publish","needs":["verify"],"with":{"channel":"beta"}},
            {"id":"security","uses":"librehub/check-security","needs":["publish-beta"]},
            {"id":"approval","uses":"librehub/approval","needs":["security"],"with":{"required":true}},
            {"id":"publish-stable","uses":"librehub/promote","needs":["approval"],"with":{"channel":"stable"}}
        ],
        "policy": {"require_security_analysis_complete": true}
    })
}
pub fn github_policy() -> GithubIdentityPolicy {
    GithubIdentityPolicy {
        provider: "github".into(),
        repository_id: "1296269".into(),
        repository_owner_id: "583231".into(),
        repository: Some("octo/hello".into()),
        allowed_refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
        allowed_workflows: vec!["octo/hello/.github/workflows/release.yml@*".into()],
        allowed_environments: vec![],
        allowed_event_types: vec!["push".into(), "workflow_dispatch".into()],
        allowed_permissions: vec![
            Scope::BuildsRead,
            Scope::AutomationsRun,
            Scope::AutomationsRead,
            Scope::ProjectsRead,
        ],
        token_ttl_seconds: 600,
    }
}
pub fn sign_github_token(claims: Value) -> String {
    let pair = testing::key_pair(testing::SIGNING_KEY);
    testing::sign(&pair, testing::header("k1"), claims)
}
pub fn install_signing_key(env: &Env) {
    let pair = testing::key_pair(testing::SIGNING_KEY);
    *env.jwks.0.lock().unwrap() = testing::jwks(vec![testing::jwk(&pair, "k1")]);
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn github_claims() -> Value {
    let mut c = testing::github_claims(now(), AUDIENCE);
    c["jti"] = json!(uuid::Uuid::new_v4().to_string());
    c
}
pub async fn wait_until<F: FnMut() -> bool>(mut f: F) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition was not reached in time");
}

pub struct Candidate {
    pub run: String,
    pub build: BuildId,
    pub beta: String,
    pub approval: String,
}
/// Drive a release pipeline run to the point where a human decision is required.
pub async fn to_approval(
    env: &Env,
    project: ProjectId,
    automation: AutomationId,
    key: &str,
    commit: &str,
) -> Candidate {
    let (status, started) = env
        .trigger(
            project,
            automation,
            json!({"idempotency_key":key,"commit":commit}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    // A reused build may already be done; only advance fresh ones.
    if env
        .store
        .get(build)
        .await
        .unwrap()
        .is_none_or(|b| b.status == BuildStatus::Queued)
    {
        env.succeed_build(build).await;
    }
    let view = env
        .wait_run(
            project,
            &run,
            &["waiting_for_security", "waiting_for_approval"],
        )
        .await;
    let beta = view["beta_publication_id"].as_str().unwrap().to_owned();
    env.analysis(&beta, "clean", None);
    env.wait_run(project, &run, &["waiting_for_approval"]).await;
    let (_, approvals) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/approvals?status=requested"),
            Some(&env.token),
            None,
        )
        .await;
    let approval = approvals
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["run_id"] == run.as_str())
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Candidate {
        run,
        build,
        beta,
        approval,
    }
}

pub async fn oidc_exchange(env: &Env, project: ProjectId, jwt: &str) -> (StatusCode, Value) {
    let response = env
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/integrations/github/oidc/exchange")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {jwt}"))
                .body(Body::from(json!({"project_id":project}).to_string()))
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
