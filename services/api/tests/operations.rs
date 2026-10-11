//! M8 operations: metrics stay off the public router, expose bounded label sets only, and
//! requests carry a correlation identifier end to end.
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use http_body_util::BodyExt;
use librehub_api::ops::{self, OpsState, Telemetry};
use std::sync::Arc;
use tower::ServiceExt;

async fn text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn metrics_are_not_served_by_the_public_router() {
    let env = Env::new().await;
    let response = env
        .app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn telemetry_uses_route_templates_and_metrics_never_expose_identifiers() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let telemetry = Arc::new(Telemetry::new());
    env.app = env.app.clone().layer(axum::middleware::from_fn_with_state(
        telemetry.clone(),
        ops::observe,
    ));
    let (status, _) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let response = env
        .app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/projects/{project}"))
                .header("authorization", format!("Bearer {}", env.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("every response carries a request id");
    assert_eq!(
        request_id.to_str().unwrap().len(),
        36,
        "a fresh UUID per request"
    );
    let metrics = ops::metrics_router(OpsState {
        store: env.store.clone(),
        telemetry: telemetry.clone(),
        database_path: env.root.path().join("builds.sqlite3"),
        outbound: Some(env.outbound.clone()),
        automation: None,
        catalog: None,
        security: None,
    });
    let response = metrics
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = text(response).await;
    assert!(
        body.contains(
            r#"librehub_http_requests_total{route="/api/v1/projects/{id}",status_class="2xx"} 2"#
        ),
        "{body}"
    );
    assert!(
        body.contains(r#"librehub_worker_ready{worker="outbound"} 1"#),
        "{body}"
    );
    assert!(body.contains("librehub_disk_available_bytes "), "{body}");
    assert!(body.contains("librehub_build_info{version="), "{body}");
    assert!(
        !body.contains(&project.to_string()),
        "identifiers never become label values"
    );
    assert!(
        !body.contains(&env.token),
        "credentials never appear in metrics"
    );
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && l.contains('{'))
    {
        let labels = &line[line.find('{').unwrap()..line.find('}').unwrap()];
        assert!(
            !labels.contains(|c: char| c.is_ascii_hexdigit() && labels.matches(c).count() > 40),
            "{line}"
        );
    }
}

#[tokio::test]
async fn a_database_from_a_newer_release_is_refused_and_left_unmodified() {
    let mut env = Env::new().await;
    env.db()
        .execute("INSERT INTO schema_migrations(version) VALUES(999)", [])
        .unwrap();
    let versions = |db: &rusqlite::Connection| -> Vec<i64> {
        let mut query = db
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap();
        query
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let before = versions(&env.db());
    env.stop().await;
    // Keep the directory: dropping the environment's TempDir would delete the database itself.
    let root = std::mem::replace(&mut env.root, tempfile::tempdir().unwrap());
    // Release every store handle, including the one held by the workers, so the lock is free.
    drop(env);
    let error = librehub_api::store::Store::open(root.path())
        .err()
        .expect("a newer schema is refused");
    assert!(
        error
            .to_string()
            .contains("newer than this release supports"),
        "{error}"
    );
    assert_eq!(
        before,
        versions(&env_db(root.path())),
        "the refused database was not modified"
    );
    assert!(before.contains(&999));
}

fn env_db(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path.join("builds.sqlite3")).unwrap()
}

#[tokio::test]
async fn storage_admission_refuses_new_work_below_the_free_space_threshold() {
    let root = tempfile::tempdir().unwrap();
    let mut store = librehub_api::store::Store::open(root.path()).unwrap();
    assert!(
        store.storage_admissible(),
        "a zero threshold disables the guard"
    );
    store.min_free_bytes = u64::MAX;
    assert!(
        !store.storage_admissible(),
        "less free space than the threshold is refused"
    );
    store.min_free_bytes = 1;
    assert!(store.storage_admissible(), "enough free space admits work");
}
