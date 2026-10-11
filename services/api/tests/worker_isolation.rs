//! M8 regression: a failure inside one background worker never cancels the shared shutdown token,
//! never stops the other workers, and never makes the API unavailable.
mod common;
use axum::http::StatusCode;
use common::*;
use std::time::Duration;

#[tokio::test]
async fn a_malformed_outbox_event_suspends_its_consumer_without_stopping_the_process() {
    let mut env = Env::new().await;
    let project = env.project().await;
    // A row the automation consumer cannot parse: its event identity is not a UUID.
    env.db()
        .execute(
            "INSERT INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,origin_kind,correlation_id,chain_depth,created_at) VALUES('not-a-uuid','poison',?1,'project.archived','s','{}','system','c',0,'2026-01-01T00:00:00Z')",
            [project.to_string()],
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
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
    assert_eq!(remaining, 1, "the event is kept, never silently dropped");
    env.stop().await;
}
