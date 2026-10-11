mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use librehub_common::*;
use serde_json::{Value, json};
use sha2::Sha256;
use std::sync::atomic::Ordering;
use tower::ServiceExt;

fn signature(secret: &str, bytes: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(bytes);
    format!("sha256={:x}", mac.finalize().into_bytes())
}
async fn deliver(
    env: &Env,
    project: ProjectId,
    secret: &str,
    delivery: uuid::Uuid,
    kind: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let body = payload.to_string();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/webhooks/github/{project}"))
        .header("x-github-delivery", delivery.to_string())
        .header("x-github-event", kind)
        .header("x-hub-signature-256", signature(secret, body.as_bytes()))
        .body(Body::from(body))
        .unwrap();
    let response = env.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap_or(Value::Null),
    )
}
fn push(branch: &str, sha: &str) -> Value {
    json!({"ref":format!("refs/heads/{branch}"),"after":sha,"deleted":false,"repository":{"clone_url":"https://github.com/example/hello.git"}})
}
async fn project_with_secret(env: &Env, auto_build: bool) -> (ProjectId, String) {
    let (status, value) = env
        .call("POST", "/api/v1/projects", Some(&env.token), Some(json!({"slug":"hello","display_name":"Hello","repository":{"provider":"github","url":"https://github.com/example/hello"},"auto_build":auto_build,"build_tags":true})))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    (
        value["project"]["id"].as_str().unwrap().parse().unwrap(),
        value["webhook_secret"].as_str().unwrap().to_owned(),
    )
}
fn count(env: &Env, sql: &str) -> i64 {
    env.db().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[tokio::test]
async fn a_verified_push_triggers_the_automation_and_shares_the_m3_build() {
    let mut env = Env::new().await;
    let (project, secret) = project_with_secret(&env, true).await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let sha = "c".repeat(40);
    let delivery = uuid::Uuid::new_v4();
    let (status, body) =
        deliver(&env, project, &secret, delivery, "push", push("main", &sha)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let run = body["automation_runs"][0].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    assert_eq!(view["trigger"], "push");
    assert_eq!(view["trigger_key"], format!("delivery:{delivery}"));
    assert_eq!(view["source_commit"], sha.as_str());
    // GitHub redelivers: no second run, no second source event, no second build.
    let (status, again) =
        deliver(&env, project, &secret, delivery, "push", push("main", &sha)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["code"], "webhook_duplicate");
    assert_eq!(again["automation_runs"][0], run.as_str());
    // The run converged on the build M3's own webhook handling created.
    assert_eq!(
        view["build_id"].as_str().unwrap(),
        body["build_id"].as_str().unwrap()
    );
    assert_eq!(Env::step(&view, "build")["output"]["reused"], true);
    env.succeed_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    env.wait_run(project, &run, &["waiting_for_security"]).await;
    assert_eq!(count(&env, "SELECT count(*) FROM source_events"), 1);
    assert_eq!(count(&env, "SELECT count(*) FROM automation_runs"), 1);
    assert_eq!(env.provider.fetches.load(Ordering::SeqCst), 1);
    let _ = automation;
    env.stop().await;
}

#[tokio::test]
async fn automations_run_without_m3_auto_build_and_ignore_unmatched_refs() {
    let mut env = Env::new().await;
    let (project, secret) = project_with_secret(&env, false).await;
    env.create_automation(project, release_pipeline()).await;
    let (status, body) = deliver(
        &env,
        project,
        &secret,
        uuid::Uuid::new_v4(),
        "push",
        push("feature", &"d".repeat(40)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["automation_runs"].as_array().unwrap().is_empty());
    let (status, body) = deliver(
        &env,
        project,
        &secret,
        uuid::Uuid::new_v4(),
        "push",
        push("main", &"e".repeat(40)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let run = body["automation_runs"][0].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    assert_eq!(Env::step(&view, "build")["output"]["created"], true);
    assert_eq!(
        count(&env, "SELECT count(*) FROM source_events"),
        1,
        "exactly one build is created for the commit"
    );
    // The automation owns publication decisions for the builds it creates.
    let state: String = env
        .db()
        .query_row("SELECT auto_publish_state FROM source_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "skipped");
    // Tag deliveries use tag patterns.
    let tag = json!({"ref":"refs/tags/v1.2.3","after":"f".repeat(40),"deleted":false,"repository":{"clone_url":"https://github.com/example/hello.git"}});
    let (_, body) = deliver(&env, project, &secret, uuid::Uuid::new_v4(), "push", tag).await;
    assert_eq!(body["automation_runs"].as_array().unwrap().len(), 1);
    env.stop().await;
}

#[tokio::test]
async fn invalid_signatures_trigger_nothing() {
    let mut env = Env::new().await;
    let (project, _) = project_with_secret(&env, true).await;
    env.create_automation(project, release_pipeline()).await;
    let (status, _) = deliver(
        &env,
        project,
        "wrong-secret",
        uuid::Uuid::new_v4(),
        "push",
        push("main", &"a".repeat(40)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(count(&env, "SELECT count(*) FROM automation_runs"), 0);
    env.stop().await;
}

#[tokio::test]
async fn state_changes_enter_the_outbox_in_the_same_transaction() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let c = to_approval(&env, project, automation, "events", &Provider::commit('1')).await;
    env.call(
        "POST",
        &format!("/api/v1/approvals/{}/approve", c.approval),
        Some(&env.token),
        None,
    )
    .await;
    env.wait_run(project, &c.run, &["completed"]).await;
    let types: Vec<String> = env
        .db()
        .prepare("SELECT event_type FROM event_outbox ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for expected in [
        "automation.started",
        "source_event.completed",
        "build.started",
        "build.succeeded",
        "publication.started",
        "publication.succeeded",
        "security.analysis_ready",
        "automation.approval_required",
        "automation.completed",
    ] {
        assert!(
            types.iter().any(|t| t == expected),
            "missing {expected}: {types:?}"
        );
    }
    assert_eq!(
        types
            .iter()
            .filter(|t| *t == "publication.succeeded")
            .count(),
        2,
        "beta and stable"
    );
    // Idempotent keys: the same transition can never enqueue twice.
    let keys: i64 = env
        .db()
        .query_row(
            "SELECT count(DISTINCT dedupe_key)-count(*) FROM event_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(keys, 0);
    // Atomicity: a rolled-back state change leaves no event behind.
    let before = count(&env, "SELECT count(*) FROM event_outbox");
    let db = env.db();
    db.execute_batch("BEGIN").unwrap();
    db.execute(
        "UPDATE publishes SET status='failed' WHERE id=?1",
        [&c.beta],
    )
    .unwrap();
    let inside: i64 = db
        .query_row("SELECT count(*) FROM event_outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(inside, before + 1);
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(count(&env, "SELECT count(*) FROM event_outbox"), before);
    env.stop().await;
}

#[tokio::test]
async fn archiving_a_project_cancels_its_active_runs_via_the_outbox() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let c = to_approval(&env, project, automation, "arch", &Provider::commit('2')).await;
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/api/v1/projects/{project}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let view = env
        .wait_run(project, &c.run, &["cancelled", "failed"])
        .await;
    // The pending approval can no longer be used to release anything.
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert!(
        status == StatusCode::CONFLICT || status == StatusCode::NOT_FOUND,
        "{status} {body}"
    );
    assert_eq!(
        *env.publisher.by_channel.lock().unwrap(),
        vec!["beta"],
        "history is untouched and nothing new is published: {view}"
    );
    env.stop().await;
}
