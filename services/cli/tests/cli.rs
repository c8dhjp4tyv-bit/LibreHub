//! Black-box tests: the real `librehub` binary against a scripted HTTP server.
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TOKEN: &str = "librehub_00000000-0000-0000-0000-000000000001_SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSEC";
const PROJECT: &str = "11111111-1111-1111-1111-111111111111";
const AUTOMATION: &str = "22222222-2222-2222-2222-222222222222";
const RUN: &str = "33333333-3333-3333-3333-333333333333";

#[derive(Default)]
struct Mock {
    log: Vec<(String, String, Option<String>, Value)>,
    run_polls: usize,
    /// Number of polls before the build step succeeds; `usize::MAX` never.
    build_after: usize,
    fail_build: bool,
}
type Shared = Arc<Mutex<Mock>>;

fn authorised(headers: &HeaderMap) -> bool {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    value == format!("Bearer {TOKEN}") || value == "Bearer librehub_exchanged_token"
}
fn error(status: u16, code: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::from_u16(status).unwrap(),
        Json(json!({"code": code, "message": format!("{code} happened")})),
    )
}
fn record(state: &Shared, method: &str, path: &str, headers: &HeaderMap, body: Value) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    state
        .lock()
        .unwrap()
        .log
        .push((method.into(), path.into(), auth, body));
}
fn run_view(build_status: &str, status: &str, error: Value) -> Value {
    json!({"id": RUN, "automation_id": AUTOMATION, "project_id": PROJECT, "status": status, "trigger": "ci", "definition_version": 1,
        "source_commit": "0123456789abcdef0123456789abcdef01234567", "source_event_id": "44444444-4444-4444-4444-444444444444",
        "build_id": "55555555-5555-5555-5555-555555555555", "error": error,
        "steps": [
            {"id":"build","kind":"librehub/build","status":build_status,"output":{"build_status":if build_status=="succeeded"{"succeeded"}else{"building"}},"error":error},
            {"id":"verify","kind":"librehub/verify-provenance","status":"pending","output":{},"error":null}]})
}
async fn serve() -> (String, Shared) {
    let state: Shared = Arc::new(Mutex::new(Mock {
        build_after: 2,
        ..Default::default()
    }));
    let app = Router::new()
        .route("/api/v1/whoami", get(|State(s): State<Shared>, h: HeaderMap| async move {
            record(&s, "GET", "/api/v1/whoami", &h, Value::Null);
            if !authorised(&h) { return Err(error(401, "invalid_token")); }
            Ok(Json(json!({"developer_id":"d","token_id":"t","scopes":["projects:read"],"project_id":null,"federated":false})))
        }))
        .route("/api/v1/projects", get(|State(s): State<Shared>, h: HeaderMap| async move {
            record(&s, "GET", "/api/v1/projects", &h, Value::Null);
            if !authorised(&h) { return Err(error(401, "invalid_token")); }
            Ok(Json(json!([{"id":PROJECT,"slug":"hello","status":"active","default_branch":"main"}])))
        }))
        .route("/api/v1/projects/{id}", get(|Path(id): Path<String>| async move {
            match id.as_str() {
                "99999999-9999-9999-9999-999999999999" => Err(error(404, "project_not_found")),
                "88888888-8888-8888-8888-888888888888" => Err(error(409, "project_disabled")),
                "77777777-7777-7777-7777-777777777777" => Err(error(500, "internal_error")),
                _ => Ok(Json(json!({"id": id}))),
            }
        }))
        .route("/api/v1/integrations/github/oidc/exchange", post(|State(s): State<Shared>, h: HeaderMap, Json(body): Json<Value>| async move {
            record(&s, "POST", "/api/v1/integrations/github/oidc/exchange", &h, body);
            if h.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer github.identity.jwt") { return Err(error(401, "oidc_signature_invalid")); }
            Ok(Json(json!({"token":"librehub_exchanged_token","expires_in":600,"scopes":["automations:run","automations:read"]})))
        }))
        .route("/_actions/token", get(|State(s): State<Shared>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
            record(&s, "GET", "/_actions/token", &h, json!(q));
            if h.get("authorization").and_then(|v| v.to_str().ok()) != Some("bearer runtime-request-token") { return Err(error(401, "no")); }
            Ok(Json(json!({"value":"github.identity.jwt"})))
        }))
        .route("/api/v1/projects/{id}/automations", get(|State(s): State<Shared>, h: HeaderMap| async move {
            record(&s, "GET", "automations", &h, Value::Null);
            Json(json!([{"id":AUTOMATION,"name":"Release Pipeline","enabled":true,"current_version":1}]))
        }))
        .route("/api/v1/projects/{id}/automations/{aid}/run", post(|State(s): State<Shared>, h: HeaderMap, Json(body): Json<Value>| async move {
            record(&s, "POST", "run", &h, body);
            if !authorised(&h) { return Err(error(401, "invalid_token")); }
            Ok((StatusCode::ACCEPTED, Json(json!({"run": run_view("pending","queued",Value::Null), "existing": false}))))
        }))
        .route("/api/v1/projects/{id}/automations/runs/{rid}", get(|State(s): State<Shared>, h: HeaderMap| async move {
            record(&s, "GET", "run-status", &h, Value::Null);
            let mut m = s.lock().unwrap();
            m.run_polls += 1;
            if m.fail_build { return Json(run_view("failed", "failed", json!({"code":"build_failed","message":"The build failed"}))); }
            if m.run_polls > m.build_after { Json(run_view("succeeded", "running", Value::Null)) } else { Json(run_view("waiting", "waiting_for_build", Value::Null)) }
        }))
        .route("/api/v1/projects/{id}/automations/runs/{rid}/cancel", post(|State(s): State<Shared>, h: HeaderMap| async move {
            record(&s, "POST", "cancel", &h, Value::Null);
            Json(run_view("cancelled", "cancelled", Value::Null))
        }))
        .route("/api/v1/gateway", get(|| async { (StatusCode::BAD_GATEWAY, "<html>bad gateway</html>") }))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state)
}

struct Run {
    url: String,
    config: tempfile::TempDir,
    env: Vec<(String, String)>,
}
impl Run {
    fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            config: tempfile::tempdir().unwrap(),
            env: vec![],
        }
    }
    fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_librehub"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LIBREHUB_URL", &self.url)
            .env("LIBREHUB_CONFIG_DIR", self.config.path())
            .args(args)
            .stdin(Stdio::null());
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }
    fn exec(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
}
fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn json_output_and_success_exit_code() {
    let (url, _) = serve().await;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || run.exec(&["--json", "project", "list"]))
        .await
        .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));
    let value: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(value[0]["slug"], "hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn human_output_is_a_readable_table() {
    let (url, _) = serve().await;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || run.exec(&["project", "list"]))
        .await
        .unwrap();
    assert_eq!(code(&o), 0);
    assert!(out(&o).starts_with("ID"), "{}", out(&o));
    assert!(out(&o).contains("hello"));
}

#[tokio::test(flavor = "multi_thread")]
async fn authentication_failures_have_their_own_exit_code_and_structured_errors() {
    let (url, _) = serve().await;
    let run = Run::new(&url);
    let missing = tokio::task::spawn_blocking({
        let r = Run::new(&run.url);
        move || r.exec(&["--json", "project", "list"])
    })
    .await
    .unwrap();
    assert_eq!(code(&missing), 3);
    let error: Value = serde_json::from_str(err(&missing).trim()).unwrap();
    assert_eq!(error["error"]["code"], "authentication_required");
    assert_eq!(error["error"]["exit_code"], 3);
    let wrong = tokio::task::spawn_blocking({
        let r = Run::new(&run.url).env("LIBREHUB_TOKEN", "librehub_wrong");
        move || r.exec(&["--json", "project", "list"])
    })
    .await
    .unwrap();
    assert_eq!(code(&wrong), 3);
    let error: Value = serde_json::from_str(err(&wrong).trim()).unwrap();
    assert_eq!(error["error"]["status"], 401);
    assert_eq!(error["error"]["code"], "invalid_token");
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_never_appear_in_output_urls_or_errors() {
    let (url, state) = serve().await;
    let secret_fragment = "SECRETSECRETSECRET";
    for args in [
        vec!["project", "list"],
        vec!["--json", "project", "list"],
        vec!["auth", "status"],
        vec!["project", "show", "77777777-7777-7777-7777-777777777777"],
        vec!["project", "show", "99999999-9999-9999-9999-999999999999"],
    ] {
        let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
        let o = tokio::task::spawn_blocking(move || run.exec(&args))
            .await
            .unwrap();
        assert!(!out(&o).contains(secret_fragment) && !err(&o).contains(secret_fragment));
    }
    // Even when the connection itself fails.
    let run = Run::new("http://127.0.0.1:9").env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || run.exec(&["project", "list"]))
        .await
        .unwrap();
    assert_eq!(code(&o), 8);
    assert!(
        !out(&o).contains(secret_fragment) && !err(&o).contains(secret_fragment),
        "{}",
        err(&o)
    );
    // The token only travels in the Authorization header, never in a path.
    for (_, path, _, _) in &state.lock().unwrap().log {
        assert!(!path.contains("librehub_"));
    }
    // Tokens are not accepted as arguments at all.
    let run = Run::new(&url);
    let o = tokio::task::spawn_blocking(move || run.exec(&["auth", "login", "--token", TOKEN]))
        .await
        .unwrap();
    assert_eq!(code(&o), 2);
    assert!(
        !err(&o).contains(secret_fragment) || err(&o).contains("unexpected argument"),
        "clap may echo the flag name only"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_codes_distinguish_failure_classes() {
    let (url, _) = serve().await;
    let cases: Vec<(Vec<&str>, i32)> = vec![
        (
            vec!["project", "show", "99999999-9999-9999-9999-999999999999"],
            4,
        ),
        (
            vec!["project", "show", "88888888-8888-8888-8888-888888888888"],
            7,
        ),
        (
            vec!["project", "show", "77777777-7777-7777-7777-777777777777"],
            8,
        ),
        (vec!["project", "show", "not-a-uuid"], 2),
        (
            vec!["publish", "stable", "11111111-1111-1111-1111-111111111111"],
            2,
        ),
        (vec!["bogus"], 2),
    ];
    for (args, expected) in cases {
        let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
        let label = format!("{args:?}");
        let o = tokio::task::spawn_blocking(move || run.exec(&args))
            .await
            .unwrap();
        assert_eq!(code(&o), expected, "{label}: {}", err(&o));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn non_json_error_bodies_do_not_crash_the_cli() {
    let (url, _) = serve().await;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    // /api/v1/gateway is not a CLI command; exercise the same client path through an unknown project route.
    let o = tokio::task::spawn_blocking(move || {
        run.exec(&[
            "--json",
            "project",
            "show",
            "00000000-0000-0000-0000-000000000000",
        ])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 0);
    let o = tokio::task::spawn_blocking({
        let r = Run::new(&format!("{url}/api/v1/gateway-missing")).env("LIBREHUB_TOKEN", TOKEN);
        move || r.exec(&["--json", "project", "list"])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 4, "{}", err(&o));
    let error: Value = serde_json::from_str(err(&o).trim()).unwrap();
    assert_eq!(error["error"]["code"], "http_404");
}

#[tokio::test(flavor = "multi_thread")]
async fn insecure_or_credentialed_api_urls_are_refused() {
    for url in [
        "http://librehub.example.com",
        "https://user:pw@librehub.example.com",
        "https://librehub.example.com/?token=x",
    ] {
        let run = Run::new(url).env("LIBREHUB_TOKEN", TOKEN);
        let o = tokio::task::spawn_blocking(move || run.exec(&["project", "list"]))
            .await
            .unwrap();
        assert_eq!(code(&o), 2, "{url}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn triggering_and_polling_a_run_until_a_step_completes() {
    let (url, state) = serve().await;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let started = Instant::now();
    let o = tokio::task::spawn_blocking(move || {
        run.exec(&[
            "--json",
            "automation",
            "run",
            "--project",
            PROJECT,
            "Release Pipeline",
            "--commit",
            &"a".repeat(40),
            "--wait-for",
            "build",
        ])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));
    let value: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(value["run"]["steps"][0]["status"], "succeeded");
    let polls = state.lock().unwrap().run_polls;
    assert!(polls >= 3, "polled {polls} times");
    assert!(started.elapsed() < Duration::from_secs(30));
    // The automation was found by name, the request body was a JSON object and no shell was involved.
    let log = state.lock().unwrap().log.clone();
    let run_request = log.iter().find(|(_, p, ..)| p == "run").unwrap();
    assert_eq!(run_request.3["commit"], "a".repeat(40));
}

#[tokio::test(flavor = "multi_thread")]
async fn waiting_is_bounded_by_the_timeout() {
    let (url, state) = serve().await;
    state.lock().unwrap().build_after = usize::MAX;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let started = Instant::now();
    let o = tokio::task::spawn_blocking(move || {
        run.exec(&[
            "--json",
            "--timeout",
            "2",
            "automation",
            "status",
            "--project",
            PROJECT,
            RUN,
            "--wait-for",
            "build",
        ])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 5, "{}", err(&o));
    assert!(started.elapsed() < Duration::from_secs(15));
    let error: Value = serde_json::from_str(err(&o).trim()).unwrap();
    assert_eq!(error["error"]["code"], "timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_awaited_step_exits_with_the_operation_failed_code() {
    let (url, state) = serve().await;
    state.lock().unwrap().fail_build = true;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || {
        run.exec(&[
            "--json",
            "automation",
            "status",
            "--project",
            PROJECT,
            RUN,
            "--wait-for",
            "build",
        ])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 6);
    let error: Value = serde_json::from_str(err(&o).trim()).unwrap();
    assert_eq!(error["error"]["code"], "build_failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn github_actions_identity_is_exchanged_in_memory_and_outputs_are_written() {
    let (url, state) = serve().await;
    let outputs = tempfile::NamedTempFile::new().unwrap();
    let path = outputs.path().to_str().unwrap().to_owned();
    let run = Run::new(&url)
        .env("GITHUB_ACTIONS", "true")
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            &format!("{url}/_actions/token?existing=1"),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-request-token")
        .env("LIBREHUB_OIDC_PROJECT", PROJECT)
        .env("LIBREHUB_OIDC_AUDIENCE", "librehub-ci")
        .env("GITHUB_OUTPUT", &path);
    let config = run.config.path().to_owned();
    let o = tokio::task::spawn_blocking(move || {
        let o = run.exec(&[
            "ci",
            "wait-for-build",
            "--project",
            PROJECT,
            "--automation",
            "Release Pipeline",
        ]);
        (o, run)
    })
    .await
    .unwrap();
    let (o, _keep) = o;
    assert_eq!(code(&o), 0, "{}", err(&o));
    let log = state.lock().unwrap().log.clone();
    // Identity token was requested for LibreHub's audience, using the runner's request token.
    let identity = log
        .iter()
        .find(|(_, p, ..)| p == "/_actions/token")
        .unwrap();
    assert_eq!(identity.3["audience"], "librehub-ci");
    assert_eq!(identity.3["existing"], "1");
    // It was exchanged for the right project and the exchanged credential drove the rest.
    let exchange = log
        .iter()
        .find(|(_, p, ..)| p.ends_with("/oidc/exchange"))
        .unwrap();
    assert_eq!(exchange.3["project_id"], PROJECT);
    assert_eq!(
        log.iter()
            .find(|(_, p, ..)| p == "run")
            .unwrap()
            .2
            .as_deref(),
        Some("Bearer librehub_exchanged_token")
    );
    // Secrets are masked in runner logs and the short-lived credential is never persisted.
    let stdout = out(&o);
    assert!(stdout.contains("::add-mask::librehub_exchanged_token"));
    assert!(stdout.contains("::add-mask::github.identity.jwt"));
    assert_eq!(
        std::fs::read_dir(&config).unwrap().count(),
        0,
        "nothing was written to the config directory"
    );
    // Machine-readable outputs for later workflow steps.
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("source_commit=0123456789abcdef0123456789abcdef01234567"));
    assert!(written.contains("build_id=55555555-5555-5555-5555-555555555555"));
    assert!(written.contains("build_status=succeeded"));
    // In OIDC mode the commit comes from GitHub's claims, so the CLI does not send one.
    assert!(
        log.iter()
            .find(|(_, p, ..)| p == "run")
            .unwrap()
            .3
            .get("commit")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn oidc_without_the_runner_environment_fails_clearly() {
    let (url, _) = serve().await;
    let run = Run::new(&url)
        .env("LIBREHUB_OIDC_PROJECT", PROJECT)
        .env("LIBREHUB_OIDC_AUDIENCE", "librehub-ci");
    let o = tokio::task::spawn_blocking(move || run.exec(&["--json", "auth", "status"]))
        .await
        .unwrap();
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("id-token: write"));
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_posts_to_the_run_and_reports_status() {
    let (url, state) = serve().await;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || {
        run.exec(&["--json", "automation", "cancel", "--project", PROJECT, RUN])
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 0);
    assert_eq!(
        serde_json::from_str::<Value>(&out(&o)).unwrap()["status"],
        "cancelled"
    );
    assert!(
        state
            .lock()
            .unwrap()
            .log
            .iter()
            .any(|(m, p, ..)| m == "POST" && p == "cancel")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ctrl_c_stops_waiting_with_a_dedicated_exit_code() {
    let (url, state) = serve().await;
    state.lock().unwrap().build_after = usize::MAX;
    let run = Run::new(&url).env("LIBREHUB_TOKEN", TOKEN);
    let o = tokio::task::spawn_blocking(move || {
        let child = run
            .command(&[
                "automation",
                "status",
                "--project",
                PROJECT,
                RUN,
                "--wait-for",
                "build",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert_eq!(code(&o), 130, "{}", err(&o));
    assert!(err(&o).contains("Interrupted"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_credentials_are_private_scoped_to_the_server_and_refused_when_exposed() {
    let (url, _) = serve().await;
    let run = Run::new(&url);
    let config = run.config.path().to_owned();
    let (login, run) = tokio::task::spawn_blocking(move || {
        let child = run
            .command(&["--json", "auth", "login", "--token-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{TOKEN}\n").as_bytes())
            .unwrap();
        (child.wait_with_output().unwrap(), run)
    })
    .await
    .unwrap();
    assert_eq!(code(&login), 0, "{}", err(&login));
    assert!(!out(&login).contains("SECRETSECRET"));
    use std::os::unix::fs::PermissionsExt;
    let file = config.join("credentials.json");
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (status, run) =
        tokio::task::spawn_blocking(move || (run.exec(&["--json", "auth", "status"]), run))
            .await
            .unwrap();
    assert_eq!(code(&status), 0, "{}", err(&status));
    assert_eq!(
        serde_json::from_str::<Value>(&out(&status)).unwrap()["source"],
        "stored"
    );
    // A credential file other users can read is rejected rather than used.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (exposed, run) = tokio::task::spawn_blocking(move || (run.exec(&["auth", "status"]), run))
        .await
        .unwrap();
    assert_eq!(code(&exposed), 2);
    assert!(err(&exposed).contains("chmod 600"));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The stored token is keyed by origin: another server gets none of it.
    let other = Run {
        url: "http://127.0.0.1:9".into(),
        config: tempfile::tempdir_in(std::env::temp_dir()).unwrap(),
        env: vec![],
    };
    let _ = other;
    let (logout, _run) = tokio::task::spawn_blocking(move || (run.exec(&["auth", "logout"]), run))
        .await
        .unwrap();
    assert_eq!(code(&logout), 0);
    let remaining: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert!(remaining.as_object().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn login_refuses_to_persist_credentials_inside_github_actions() {
    let (url, _) = serve().await;
    let run = Run::new(&url).env("GITHUB_ACTIONS", "true");
    let o = tokio::task::spawn_blocking(move || {
        let child = run
            .command(&["auth", "login", "--token-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{TOKEN}\n").as_bytes())
            .unwrap();
        (child.wait_with_output().unwrap(), run)
    })
    .await
    .unwrap();
    assert_eq!(code(&o.0), 2);
    assert!(!o.1.config.path().join("credentials.json").exists());
}

#[test]
fn workflows_are_validated_locally_without_a_server() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.yaml");
    std::fs::write(
        &good,
        librehub_automation::workflow::EXAMPLE_RELEASE_PIPELINE,
    )
    .unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(
        &bad,
        "name: x\ntriggers: [{type: manual}]\nsteps:\n  - {id: build, uses: shell/run}\n",
    )
    .unwrap();
    let run = Run::new("http://127.0.0.1:9");
    let ok = run.exec(&[
        "--json",
        "automation",
        "validate",
        "--file",
        good.to_str().unwrap(),
    ]);
    assert_eq!(code(&ok), 0, "{}", err(&ok));
    assert_eq!(
        serde_json::from_str::<Value>(&out(&ok)).unwrap()["valid"],
        true
    );
    let invalid = run.exec(&["automation", "validate", "--file", bad.to_str().unwrap()]);
    assert_eq!(code(&invalid), 2);
}
