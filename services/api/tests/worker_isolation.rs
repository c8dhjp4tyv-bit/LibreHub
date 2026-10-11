//! M8 regression: a failure inside one background worker never cancels the shared shutdown token,
//! never stops the other workers, and never makes the API unavailable.
mod common;
use axum::http::StatusCode;
use common::*;
use librehub_common::BuildId;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn a_malformed_outbox_event_is_quarantined_and_later_work_continues() {
    let mut env = Env::at(tempfile::tempdir().unwrap(), false).await;
    let project = env.project().await;
    env.resolver.set(
        "hooks.example.com",
        vec![vec!["93.184.216.34".parse().unwrap()]],
    );
    let (status, body) = env.call("POST",
        &format!("/api/v1/projects/{project}/integrations/webhooks"), Some(&env.token),
        Some(json!({"url":"https://hooks.example.com/events","event_types":["automation.started"]}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let automation = env.create_automation(project, json!({"name":"Build","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]})).await;
    let (status, started) = env
        .trigger(
            project,
            automation,
            json!({"commit":Provider::commit('e'),"idempotency_key":"poison-test"}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    // Admit a delivery before the poison row exists; it must still be claimed afterward.
    for event in env.store.outbox_batch("webhooks", 64).await.unwrap() {
        env.store
            .fan_out(event, env.store.automation_limits.max_chain_depth)
            .await
            .unwrap();
    }
    let pending: i64 = env
        .db()
        .query_row("SELECT count(*) FROM integration_deliveries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(pending, 1);
    // Both outbox consumers cannot parse this event identity.
    env.db()
        .execute(
            "INSERT INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,origin_kind,correlation_id,chain_depth,created_at) VALUES('not-a-uuid','poison',?1,'project.archived','s','{}','system','c',0,'2026-01-01T00:00:00Z')",
            [project.to_string()],
        )
        .unwrap();
    env.spawn_workers();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.succeed_build(build).await;
    env.wait_run(project, &run, &["completed"]).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let completed: i64 = env
                .db()
                .query_row(
                    "SELECT count(*) FROM integration_deliveries WHERE status='delivered'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if completed == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("already-admitted delivery must complete despite poison row");
    // Both independent cursors must move beyond the malformed event without
    // deleting or pretending to process it. Its raw row remains for inspection.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let quarantined: i64 = env
                .db()
                .query_row(
                    "SELECT count(*) FROM outbox_quarantine WHERE reason='invalid_event_encoding'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if quarantined == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both consumers must quarantine the poison row");
    assert!(env.store.outbox_batch("automation", 64).await.is_ok());
    assert!(env.store.outbox_batch("webhooks", 64).await.is_ok());

    // A later event must still be delivered and its automation must complete.
    let (status, later) = env
        .trigger(
            project,
            automation,
            json!({"commit": Provider::commit('f'), "idempotency_key": "after-poison"}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{later}");
    let later_id = later["run"]["id"].as_str().unwrap().to_owned();
    let view = env
        .wait_run(project, &later_id, &["waiting_for_build"])
        .await;
    let later_build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.succeed_build(later_build).await;
    env.wait_run(project, &later_id, &["completed"]).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let completed: i64 = env
                .db()
                .query_row(
                    "SELECT count(*) FROM integration_deliveries WHERE status='delivered'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if completed == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("later webhook must be delivered after quarantine");
    let consumer_count: i64 = env
        .db()
        .query_row(
            "SELECT count(DISTINCT consumer) FROM outbox_quarantine",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(consumer_count, 2);
    assert!(
        !env.shutdown.is_cancelled(),
        "a worker failure must not cancel the shared shutdown"
    );
    assert!(
        env.automation.ready(),
        "the automation supervisor keeps running and retries"
    );
    assert!(env.outbound.ready(), "the outbound worker is unaffected");
    let (status, body) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let remaining: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM event_outbox WHERE event_id='not-a-uuid'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 1,
        "the original event must remain for investigation"
    );
    env.stop().await;
}
