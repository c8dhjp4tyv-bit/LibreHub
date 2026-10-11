mod common;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use common::*;
use librehub_common::*;
use serde_json::json;

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}
fn scheduled(trigger: serde_json::Value) -> serde_json::Value {
    json!({"name":"Nightly","triggers":[trigger],"steps":[{"id":"build","uses":"librehub/build"}]})
}
async fn setup(trigger: serde_json::Value) -> (Env, ProjectId, AutomationId) {
    let env = Env::at(tempfile::tempdir().unwrap(), false).await;
    let project = env.project().await;
    let automation = env.create_automation(project, scheduled(trigger)).await;
    (env, project, automation)
}
fn set_cursor(env: &Env, next: &str) {
    env.db()
        .execute("UPDATE automation_triggers SET next_run_at=?1", [next])
        .unwrap();
}
fn cursor(env: &Env) -> String {
    env.db()
        .query_row("SELECT next_run_at FROM automation_triggers", [], |r| {
            r.get(0)
        })
        .unwrap()
}
fn run_count(env: &Env) -> i64 {
    env.db()
        .query_row("SELECT count(*) FROM automation_runs", [], |r| r.get(0))
        .unwrap()
}
const DAILY: &str = r#"{"type":"schedule","every":"daily","at":"03:30"}"#;

#[tokio::test]
async fn a_daily_schedule_runs_once_per_occurrence() {
    let (env, project, _) = setup(serde_json::from_str(DAILY).unwrap()).await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    let started = env
        .store
        .fire_due_schedules(at("2026-01-01T03:31:00Z"))
        .await
        .unwrap();
    assert_eq!(started.len(), 1);
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-01T03:31:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-01T03:45:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(run_count(&env), 1);
    assert!(cursor(&env).starts_with("2026-01-02T03:30:00"));
    let (_, runs) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/runs"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(runs[0]["trigger"], "schedule");
    assert_eq!(
        runs[0]["trigger_detail"]["occurrence"],
        "2026-01-01T03:30:00+00:00"
    );
    // The next day's occurrence runs, again exactly once.
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-02T03:30:30Z"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(run_count(&env), 2);
}

#[tokio::test]
async fn a_weekly_schedule_runs_once_on_its_utc_weekday() {
    let (env, _, _) =
        setup(json!({"type":"schedule","every":"weekly","weekday":"mon","at":"00:00"})).await;
    // 2026-01-05 is a Monday.
    set_cursor(&env, "2026-01-05T00:00:00+00:00");
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-05T00:02:00Z"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-06T12:00:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert!(cursor(&env).starts_with("2026-01-12T00:00:00"));
    assert_eq!(run_count(&env), 1);
}

#[tokio::test]
async fn missed_occurrences_follow_the_declared_policy() {
    let (env, _, _) = setup(serde_json::from_str(DAILY).unwrap()).await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    // Down for three days: the default policy skips, records the skip and resumes the schedule.
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-04T10:00:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(run_count(&env), 0);
    assert!(cursor(&env).starts_with("2026-01-05T03:30:00"));
    let skipped: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE action='automation.schedule_skipped'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(skipped, 1);

    let (env, _, _) =
        setup(json!({"type":"schedule","every":"daily","at":"03:30","catch_up":"run_once"})).await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-04T10:00:00Z"))
            .await
            .unwrap()
            .len(),
        1,
        "one catch-up run, not three"
    );
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-04T10:00:01Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(run_count(&env), 1);
}

#[tokio::test]
async fn a_restart_or_lost_cursor_cannot_duplicate_an_occurrence() {
    let root = tempfile::tempdir().unwrap();
    let store = librehub_api::store::Store::open(root.path()).unwrap();
    let env = Env::build(root, store, false, None).await;
    let project = env.project().await;
    env.create_automation(project, scheduled(serde_json::from_str(DAILY).unwrap()))
        .await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-01T03:31:00Z"))
            .await
            .unwrap()
            .len(),
        1
    );
    // Worst case: the cursor write is lost. The unique occurrence identity still blocks a second run.
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-01T03:32:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(run_count(&env), 1);
    // After a process restart the persisted cursor is honoured as well.
    let path = env.root.path().to_owned();
    let Env {
        store,
        supervisor,
        app,
        source,
        publishing,
        automation,
        outbound,
        root,
        ..
    } = env;
    drop((
        store, supervisor, app, source, publishing, automation, outbound,
    ));
    let reopened = librehub_api::store::Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .fire_due_schedules(at("2026-01-01T03:33:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    drop(root);
}

#[tokio::test]
async fn disabled_schedules_and_a_disabled_scheduler_do_not_trigger() {
    let (env, project, automation) = setup(serde_json::from_str(DAILY).unwrap()).await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    let (status, _) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/automations/{automation}"),
            Some(&env.token),
            Some(json!({"schedules_enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        env.store
            .fire_due_schedules(at("2026-01-01T03:31:00Z"))
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(run_count(&env), 0);
    // Operator switch: the worker never even evaluates schedules.
    env.call(
        "PATCH",
        &format!("/api/v1/projects/{project}/automations/{automation}"),
        Some(&env.token),
        Some(json!({"schedules_enabled": true})),
    )
    .await;
    set_cursor(&env, "2020-01-01T03:30:00+00:00");
    let mut worker = env.automation.clone();
    worker.scheduler_enabled = false;
    worker.tick_once(1).await.unwrap();
    assert_eq!(run_count(&env), 0);
    // And a disabled automation or archived project never fires.
    env.call(
        "PATCH",
        &format!("/api/v1/projects/{project}/automations/{automation}"),
        Some(&env.token),
        Some(json!({"enabled": false})),
    )
    .await;
    set_cursor(&env, "2020-01-01T03:30:00+00:00");
    assert_eq!(
        env.store
            .fire_due_schedules(Utc::now())
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn the_same_occurrence_is_admitted_only_once_under_concurrency() {
    let (env, _, _) = setup(serde_json::from_str(DAILY).unwrap()).await;
    set_cursor(&env, "2026-01-01T03:30:00+00:00");
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = env.store.clone();
            tokio::spawn(async move {
                store
                    .fire_due_schedules(at("2026-01-01T03:31:00Z"))
                    .await
                    .unwrap()
                    .len()
            })
        })
        .collect();
    let mut total = 0;
    for h in handles {
        total += h.await.unwrap();
    }
    assert_eq!(total, 1);
    assert_eq!(run_count(&env), 1);
}

#[tokio::test]
async fn a_scheduled_run_resolves_its_branch_to_an_immutable_commit() {
    let mut env = Env::new().await;
    let project = env.project().await;
    env.provider
        .commits
        .lock()
        .unwrap()
        .insert("main".into(), Provider::commit('9'));
    // An occurrence two minutes ago, so the running supervisor admits it on its own.
    let occurrence = (Utc::now() - chrono::Duration::minutes(2)).with_timezone(&Utc);
    let occurrence = occurrence
        - chrono::Duration::seconds(chrono::Timelike::second(&occurrence) as i64)
        - chrono::Duration::nanoseconds(chrono::Timelike::nanosecond(&occurrence) as i64);
    let time = occurrence.format("%H:%M").to_string();
    env.create_automation(
        project,
        scheduled(json!({"type":"schedule","every":"daily","at":time})),
    )
    .await;
    set_cursor(&env, &occurrence.to_rfc3339());
    for _ in 0..100 {
        let (_, runs) = env
            .call(
                "GET",
                &format!("/api/v1/projects/{project}/runs"),
                Some(&env.token),
                None,
            )
            .await;
        if let Some(run) = runs.as_array().and_then(|r| r.first())
            && run["source_commit"].is_string()
        {
            assert_eq!(run["source_commit"], Provider::commit('9'));
            assert_eq!(run["trigger"], "schedule");
            env.stop().await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("scheduled run did not start");
}
