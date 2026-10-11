mod common;
use axum::http::StatusCode;
use common::*;
use librehub_common::*;
use serde_json::json;
use std::sync::atomic::Ordering;

fn build_only() -> serde_json::Value {
    json!({"name":"Build Only","triggers":[{"type":"manual"},{"type":"push","branches":["main"]},{"type":"tag","patterns":["v*"]}],
           "steps":[{"id":"build","uses":"librehub/build"}]})
}

#[tokio::test]
async fn valid_workflow_is_accepted_and_versioned() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let id = env.create_automation(project, release_pipeline()).await;
    let (status, shown) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/automations/{id}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(shown["current_version"], 1);
    assert_eq!(shown["min_valid_version"], 1);
    // Names are unique per project.
    assert_eq!(
        env.automation_with(project, release_pipeline()).await.0,
        StatusCode::CONFLICT
    );
    env.stop().await;
}

#[tokio::test]
async fn invalid_workflows_are_rejected_with_stable_codes() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let cycle = json!({"name":"c","triggers":[{"type":"manual"}],"steps":[
        {"id":"build","uses":"librehub/build"},
        {"id":"a","uses":"librehub/verify-provenance","needs":["build","b"]},
        {"id":"b","uses":"librehub/verify-provenance","needs":["a"]}]});
    let (status, body) = env.automation_with(project, cycle).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("workflow_cycle"))
    );
    let unsupported = json!({"name":"u","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"},{"id":"x","uses":"shell/run","needs":["build"],"with":{"command":"id"}}]});
    assert_eq!(
        env.automation_with(project, unsupported).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut steps = vec![json!({"id":"build","uses":"librehub/build"})];
    for i in 0..20 {
        steps.push(
            json!({"id":format!("v{i}"),"uses":"librehub/verify-provenance","needs":["build"]}),
        );
    }
    let (status, body) = env
        .automation_with(
            project,
            json!({"name":"big","triggers":[{"type":"manual"}],"steps":steps}),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("workflow_too_complex"))
    );
    let huge = json!({"name":"x".repeat(100_000),"triggers":[],"steps":[]});
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations"),
            Some(&env.token),
            Some(json!({"spec": huge})),
        )
        .await;
    assert!(status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST);
    // YAML with anchors is refused instead of expanded.
    let yaml =
        "name: a\ntriggers: [{type: manual}]\nsteps: &s\n  - {id: build, uses: librehub/build}\n";
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations"),
            Some(&env.token),
            Some(json!({"yaml": yaml})),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("workflow_yaml_unsupported"))
    );
    env.stop().await;
}

#[tokio::test]
async fn full_release_flow_with_pinned_source_beta_security_approval_and_stable() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    env.provider
        .commits
        .lock()
        .unwrap()
        .insert("main".into(), Provider::commit('d'));
    let (status, started) = env
        .trigger(
            project,
            automation,
            json!({"ref":"main","idempotency_key":"first"}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    // Build step: the commit is resolved and pinned *before* any source work is queued.
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    assert_eq!(view["source_commit"], Provider::commit('d'));
    let build: BuildId = loop {
        let v = env.run_view(project, &run).await;
        if let Some(b) = v["build_id"].as_str() {
            break b.parse().unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    env.succeed_build(build).await;
    // No attestor in this harness: provenance verification is honestly skipped, not faked.
    let view = env.wait_run(project, &run, &["waiting_for_security"]).await;
    assert_eq!(Env::step(&view, "verify")["status"], "skipped");
    assert_eq!(
        Env::step(&view, "verify")["output"]["attestation"],
        "not_configured"
    );
    assert_eq!(Env::step(&view, "publish-beta")["status"], "succeeded");
    let beta = view["beta_publication_id"].as_str().unwrap().to_owned();
    // Provenance of the build carries exactly the pinned commit.
    let record = env.store.get(build).await.unwrap().unwrap();
    assert_eq!(
        record.provenance.unwrap().revision.commit,
        Provider::commit('d')
    );
    assert_eq!(env.provider.fetches.load(Ordering::SeqCst), 1);
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    // A vulnerability provider outage must not look like a clean result.
    env.analysis(&beta, "unavailable", None);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let view = env.run_view(project, &run).await;
    assert_eq!(view["status"], "waiting_for_security", "{view}");
    env.analysis(&beta, "clean", None);
    let view = env.wait_run(project, &run, &["waiting_for_approval"]).await;
    assert_eq!(Env::step(&view, "security")["status"], "succeeded");
    // Stable has not been published and cannot be before approval.
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    let (status, approvals) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/approvals?status=requested"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let approval = approvals[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        approvals[0]["candidate"]["source_commit"],
        Provider::commit('d')
    );
    // An unrelated developer has no standing at all.
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{approval}/approve"),
            Some(&env.other_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/approvals/{approval}"),
            Some(&env.other_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // The owner approves; the same decision cannot be repeated.
    let (status, decided) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{approval}/approve"),
            Some(&env.token),
            Some(json!({"reason":"ship it"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{decided}");
    assert_eq!(decided["decided_role"], "project_owner");
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/approvals/{approval}/approve"),
            Some(&env.token),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let view = env.wait_run(project, &run, &["completed"]).await;
    assert_eq!(Env::step(&view, "publish-stable")["status"], "succeeded");
    assert_eq!(
        *env.publisher.by_channel.lock().unwrap(),
        vec!["beta", "stable"]
    );
    assert_ne!(view["beta_publication_id"], view["stable_publication_id"]);
    // History and audit are durable.
    let (_, events) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/automations/runs/{run}/events"),
            Some(&env.token),
            None,
        )
        .await;
    assert!(events.as_array().unwrap().len() >= 5);
    let (_, audit) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/audit?limit=100"),
            Some(&env.token),
            None,
        )
        .await;
    let actions: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap().to_owned())
        .collect();
    for expected in [
        "automation.created",
        "automation.triggered",
        "release.approval_requested",
        "release.approved",
        "automation.completed",
    ] {
        assert!(
            actions.iter().any(|a| a == expected),
            "missing {expected}: {actions:?}"
        );
    }
    env.stop().await;
}

#[tokio::test]
async fn duplicate_triggers_return_the_original_run() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, build_only()).await;
    let (s1, first) = env
        .trigger(project, automation, json!({"idempotency_key":"k1"}))
        .await;
    let (s2, second) = env
        .trigger(project, automation, json!({"idempotency_key":"k1"}))
        .await;
    assert_eq!((s1, s2), (StatusCode::ACCEPTED, StatusCode::OK));
    assert_eq!(first["run"]["id"], second["run"]["id"]);
    assert_eq!(second["existing"], true);
    let (_, runs) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/runs"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(runs.as_array().unwrap().len(), 1);
    // Concurrent requests with one identity create exactly one run.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let app = env.app.clone();
            let token = env.token.clone();
            tokio::spawn(async move {
                call(
                    &app,
                    "POST",
                    &format!("/api/v1/projects/{project}/automations/{automation}/run"),
                    Some(&token),
                    Some(json!({"idempotency_key":"race"})),
                )
                .await
            })
        })
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    for h in handles {
        let (status, body) = h.await.unwrap();
        assert!(
            status == StatusCode::ACCEPTED || status == StatusCode::OK,
            "{status} {body}"
        );
        ids.insert(body["run"]["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(ids.len(), 1);
    env.stop().await;
}

#[tokio::test]
async fn an_existing_build_of_the_same_commit_is_reused_unless_a_fresh_build_is_requested() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, build_only()).await;
    let commit = Provider::commit('e');
    let (_, a) = env
        .trigger(
            project,
            automation,
            json!({"commit":commit,"idempotency_key":"a"}),
        )
        .await;
    let run_a = a["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run_a, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.succeed_build(build).await;
    env.wait_run(project, &run_a, &["completed"]).await;
    let (_, b) = env
        .trigger(
            project,
            automation,
            json!({"commit":commit,"idempotency_key":"b"}),
        )
        .await;
    let run_b = b["run"]["id"].as_str().unwrap().to_owned();
    let view_b = env.wait_run(project, &run_b, &["completed"]).await;
    assert_eq!(view_b["build_id"].as_str().unwrap(), build.to_string());
    assert_eq!(Env::step(&view_b, "build")["output"]["reused"], true);
    assert_eq!(
        env.provider.fetches.load(Ordering::SeqCst),
        1,
        "no second build of the same commit"
    );
    // An explicit request builds again.
    let (_, c) = env
        .trigger(
            project,
            automation,
            json!({"commit":commit,"idempotency_key":"c","fresh_build":true}),
        )
        .await;
    let run_c = c["run"]["id"].as_str().unwrap().to_owned();
    let view_c = env.wait_run(project, &run_c, &["waiting_for_build"]).await;
    assert_ne!(view_c["build_id"].as_str().unwrap(), build.to_string());
    env.stop().await;
}

#[tokio::test]
async fn a_failed_build_stops_dependent_steps_and_publishes_nothing() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"f"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    env.fail_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    let view = env.wait_run(project, &run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "build_failed");
    assert_eq!(Env::step(&view, "build")["status"], "failed");
    for step in [
        "verify",
        "publish-beta",
        "security",
        "approval",
        "publish-stable",
    ] {
        assert_eq!(Env::step(&view, step)["status"], "skipped", "{step}");
    }
    assert_eq!(env.publisher.calls.load(Ordering::SeqCst), 0);
    env.stop().await;
}

#[tokio::test]
async fn publication_is_never_duplicated_by_repeated_supervision() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"d"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.succeed_build(build).await;
    env.wait_run(project, &run, &["waiting_for_security"]).await;
    // Someone else publishes the same build to beta concurrently; the automation adopts it.
    for _ in 0..10 {
        env.automation.tick_once(2).await.unwrap();
        env.publishing.wake.notify_one();
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    let rows: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM publishes WHERE build_id=?1",
            [build.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
    env.stop().await;
}

#[tokio::test]
async fn cancellation_stops_pending_steps_and_keeps_history() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"x"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    env.wait_run(project, &run, &["waiting_for_build"]).await;
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/runs/{run}/cancel"),
            Some(&env.token),
            None,
        )
        .await;
    assert!(status == StatusCode::ACCEPTED || status == StatusCode::OK);
    let view = env.wait_run(project, &run, &["cancelled"]).await;
    for step in [
        "build",
        "verify",
        "publish-beta",
        "security",
        "approval",
        "publish-stable",
    ] {
        assert_eq!(Env::step(&view, step)["status"], "cancelled", "{step}");
    }
    assert_eq!(env.publisher.calls.load(Ordering::SeqCst), 0);
    // The M3 build the run itself created is cancelled through M1's own mechanism.
    if let Some(build) = view["build_id"].as_str() {
        let record = env.store.get(build.parse().unwrap()).await.unwrap();
        assert!(record.is_none() || record.unwrap().status == BuildStatus::Cancelled);
    }
    // A second cancel is idempotent and history remains.
    let (status, again) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/runs/{run}/cancel"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["status"], "cancelled");
    env.stop().await;
}

#[tokio::test]
async fn a_restart_resumes_a_waiting_run_without_new_side_effects() {
    let root = tempfile::tempdir().unwrap();
    let store = librehub_api::store::Store::open(root.path()).unwrap();
    let owner = store.create_developer("Owner".into()).await.unwrap().id;
    let other = store.create_developer("Other".into()).await.unwrap().id;
    let token = store
        .issue_token(owner, "o".into(), Scope::developer_defaults())
        .await
        .unwrap()
        .token
        .0;
    let other_token = store
        .issue_token(other, "x".into(), Scope::developer_defaults())
        .await
        .unwrap()
        .token
        .0;
    let mut env = Env::build(
        root,
        store,
        true,
        Some((owner, token.clone(), other, other_token.clone())),
    )
    .await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"r"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.stop().await;
    // "Crash": drop everything holding the data directory, then start again from disk.
    let path = env.root.path().to_owned();
    let Env {
        store,
        supervisor,
        app,
        source,
        publishing,
        automation: worker,
        outbound,
        root,
        ..
    } = env;
    drop((store, supervisor, app, source, publishing, worker, outbound));
    let reopened = librehub_api::store::Store::open(&path).unwrap();
    let mut env = Env::build(
        root,
        reopened,
        true,
        Some((owner, token, other, other_token)),
    )
    .await;
    env.succeed_build(build).await;
    let view = env.wait_run(project, &run, &["waiting_for_security"]).await;
    assert_eq!(view["build_id"].as_str().unwrap(), build.to_string());
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    let sources: i64 = env
        .db()
        .query_row("SELECT count(*) FROM source_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sources, 1);
    env.stop().await;
}

#[tokio::test]
async fn disabled_and_archived_projects_stop_automation() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"queued"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    env.wait_run(project, &run, &["waiting_for_build"]).await;
    // Archiving fails the queued run before any further step and blocks new admission.
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/api/v1/projects/{project}"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let view = env.wait_run(project, &run, &["failed", "cancelled"]).await;
    assert!(
        ["project_not_active"].contains(
            &view["error"]["code"]
                .as_str()
                .unwrap_or("project_not_active")
        ) || view["status"] == "cancelled"
    );
    let (status, body) = env
        .trigger(project, automation, json!({"idempotency_key":"later"}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "project_not_active");
    assert_eq!(env.publisher.calls.load(Ordering::SeqCst), 0);
    env.stop().await;
}

#[tokio::test]
async fn a_material_policy_change_blocks_publication_of_runs_admitted_earlier() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"s"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    // The owner tightens the workflow while this run waits for its build.
    let mut stricter = release_pipeline();
    stricter["policy"]["require_allowed_builder"] = json!(false);
    stricter["policy"]["require_no_blocking_moderation"] = json!(true);
    stricter["steps"][4]["with"]["expires_in_hours"] = json!(1);
    let (status, updated) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/automations/{automation}"),
            Some(&env.token),
            Some(json!({"spec": stricter})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["current_version"], 2);
    assert_eq!(updated["min_valid_version"], 2);
    env.succeed_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    let view = env.wait_run(project, &run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "stale_policy");
    assert_eq!(
        view["definition_version"], 1,
        "the run keeps the version it was admitted with"
    );
    assert_eq!(env.publisher.calls.load(Ordering::SeqCst), 0);
    // New runs use the new version.
    let (_, fresh) = env
        .trigger(project, automation, json!({"idempotency_key":"s2"}))
        .await;
    assert_eq!(fresh["run"]["definition_version"], 2);
    env.stop().await;
}

#[tokio::test]
async fn disabling_an_automation_blocks_inflight_publication_and_new_runs() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let (_, started) = env
        .trigger(project, automation, json!({"idempotency_key":"dis"}))
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let (status, _) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/automations/{automation}"),
            Some(&env.token),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    env.succeed_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    let view = env.wait_run(project, &run, &["failed"]).await;
    assert!(
        ["stale_policy", "automation_disabled"].contains(&view["error"]["code"].as_str().unwrap())
    );
    assert_eq!(
        env.trigger(project, automation, json!({"idempotency_key":"n"}))
            .await
            .1["code"],
        "automation_disabled"
    );
    env.stop().await;
}

#[tokio::test]
async fn transient_source_failures_retry_with_backoff_and_permanent_ones_do_not() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, build_only()).await;
    *env.provider.fail_resolution.lock().unwrap() = Some(librehub_source::SourceError::transient(
        "source_unavailable",
    ));
    let (_, started) = env
        .trigger(
            project,
            automation,
            json!({"ref":"main","idempotency_key":"t"}),
        )
        .await;
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    for _ in 0..100 {
        let view = env.run_view(project, &run).await;
        if Env::step(&view, "build")["attempts"].as_u64().unwrap() >= 1 {
            assert_eq!(
                view["status"].as_str().map(|s| s != "failed"),
                Some(true),
                "transient failures must not fail the run"
            );
            assert!(Env::step(&view, "build")["next_attempt_at"].is_string());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    *env.provider.fail_resolution.lock().unwrap() =
        Some(librehub_source::SourceError::new("repository_not_allowed"));
    let (_, permanent) = env
        .trigger(
            project,
            automation,
            json!({"ref":"main","idempotency_key":"p"}),
        )
        .await;
    let view = env
        .wait_run(
            project,
            permanent["run"]["id"].as_str().unwrap(),
            &["failed"],
        )
        .await;
    assert_eq!(view["error"]["code"], "source_ref_unresolvable");
    env.stop().await;
}
