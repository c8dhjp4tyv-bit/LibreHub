mod common;
use axum::http::StatusCode;
use common::*;
use librehub_common::*;
use serde_json::json;
use std::sync::atomic::Ordering;

async fn setup() -> (Env, ProjectId, AutomationId) {
    let env = Env::new().await;
    let project = env.project().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    (env, project, automation)
}

#[tokio::test]
async fn rejection_blocks_stable_promotion() {
    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "rej", &Provider::commit('1')).await;
    let (status, rejected) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/reject", c.approval),
            Some(&env.token),
            Some(json!({"reason":"not now"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rejected}");
    assert_eq!(rejected["status"], "rejected");
    let view = env.wait_run(project, &c.run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "approval_rejected");
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    // A rejected request cannot be approved afterwards.
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.token),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    env.stop().await;
}

#[tokio::test]
async fn expired_approvals_are_refused() {
    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "exp", &Provider::commit('2')).await;
    env.db()
        .execute(
            "UPDATE automation_approvals SET expires_at='2000-01-01T00:00:00Z' WHERE id=?1",
            [&c.approval],
        )
        .unwrap();
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("approval_expired")),
        "{body}"
    );
    let view = env.wait_run(project, &c.run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "approval_expired");
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    env.stop().await;
}

#[tokio::test]
async fn an_approval_applies_only_to_its_own_run_and_is_single_use() {
    let (mut env, project, automation) = setup().await;
    let first = to_approval(&env, project, automation, "one", &Provider::commit('3')).await;
    let second = to_approval(&env, project, automation, "two", &Provider::commit('4')).await;
    assert_ne!(first.approval, second.approval);
    // Approving one candidate leaves the other waiting.
    env.call(
        "POST",
        &format!("/api/v1/approvals/{}/approve", first.approval),
        Some(&env.token),
        None,
    )
    .await;
    env.wait_run(project, &first.run, &["completed"]).await;
    let other = env.run_view(project, &second.run).await;
    assert_eq!(other["status"], "waiting_for_approval");
    assert_eq!(
        *env.publisher.by_channel.lock().unwrap(),
        vec!["beta", "beta", "stable"]
    );
    // The consumed approval cannot be decided again nor reused.
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", first.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let consumed: Option<String> = env
        .db()
        .query_row(
            "SELECT consumed_at FROM automation_approvals WHERE id=?1",
            [&first.approval],
            |r| r.get(0),
        )
        .unwrap();
    assert!(consumed.is_some());
    env.stop().await;
}

#[tokio::test]
async fn a_changed_candidate_invalidates_the_approval() {
    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "chg", &Provider::commit('5')).await;
    env.call(
        "POST",
        &format!("/api/v1/approvals/{}/approve", c.approval),
        Some(&env.token),
        None,
    )
    .await;
    // The immutable source snapshot of the build is tampered with between approval and promotion.
    // (The worker may already be acting, so race-free tamper happens on a second candidate below.)
    env.wait_run(project, &c.run, &["completed", "failed"])
        .await;
    env.stop().await;

    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "chg2", &Provider::commit('6')).await;
    // Stop the supervisor so the change lands strictly between approval and promotion.
    env.stop().await;
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    env.db()
        .execute("UPDATE builds SET record=json_set(record,'$.provenance.snapshot.sha256',?2) WHERE id=?1", rusqlite::params![c.build.to_string(), "f".repeat(64)])
        .unwrap();
    env.shutdown = tokio_util::sync::CancellationToken::new();
    let mut revived = Env::build(
        env.root,
        env.store,
        true,
        Some((env.owner, env.token, env.other, env.other_token)),
    )
    .await;
    let view = revived.wait_run(project, &c.run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "approval_stale", "{view}");
    assert_eq!(
        *revived.publisher.by_channel.lock().unwrap(),
        Vec::<String>::new(),
        "nothing is published after the candidate changed"
    );
    revived.stop().await;
}

#[tokio::test]
async fn ci_tokens_and_unprivileged_developers_cannot_approve() {
    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "auth", &Provider::commit('7')).await;
    // A developer token without releases:approve.
    let limited = env
        .store
        .issue_token(
            env.owner,
            "limited".into(),
            vec![
                Scope::AutomationsRead,
                Scope::BuildsWrite,
                Scope::AutomationsRun,
            ],
        )
        .await
        .unwrap()
        .token
        .0;
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&limited),
            None,
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("insufficient_scope"))
    );
    // A federated CI credential (minted through OIDC) is confined to its project and has no approve scope.
    install_signing_key(&env);
    let (status, created) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            Some(json!({"name":"gha","policy":github_policy()})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, exchanged) =
        oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    assert_eq!(status, StatusCode::OK, "{exchanged}");
    let ci = exchanged["token"].as_str().unwrap();
    for path in [
        format!("/api/v1/approvals/{}/approve", c.approval),
        format!("/api/v1/approvals/{}/reject", c.approval),
    ] {
        let (status, _) = env.call("POST", &path, Some(ci), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/approvals/{}", c.approval),
            Some(ci),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Still undecided, and nothing was promoted.
    let (_, approval) = env
        .call(
            "GET",
            &format!("/api/v1/approvals/{}", c.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(approval["status"], "requested");
    assert_eq!(env.publisher.calls.load(Ordering::SeqCst), 1);
    env.stop().await;
}

#[tokio::test]
async fn a_listed_release_approver_may_decide_but_an_outsider_may_not() {
    let mut env = Env::new().await;
    let project = env.project().await;
    let mut spec = release_pipeline();
    spec["policy"]["release_approvers"] = json!([env.other.to_string()]);
    let automation = env.create_automation(project, spec).await;
    let c = to_approval(&env, project, automation, "role", &Provider::commit('8')).await;
    let outsider = env
        .store
        .create_developer("Outsider".into())
        .await
        .unwrap()
        .id;
    let outsider_token = env
        .store
        .issue_token(outsider, "o".into(), Scope::developer_defaults())
        .await
        .unwrap()
        .token
        .0;
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&outsider_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, listed) = env
        .call(
            "GET",
            "/api/v1/approvals?status=requested",
            Some(&env.other_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let (status, decided) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.other_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{decided}");
    assert_eq!(decided["decided_role"], "authorized_release_approver");
    env.wait_run(project, &c.run, &["completed"]).await;
    env.stop().await;
}

#[tokio::test]
async fn stable_promotion_requires_a_successful_beta_publication_of_the_same_build() {
    let (mut env, project, automation) = setup().await;
    let c = to_approval(&env, project, automation, "beta", &Provider::commit('9')).await;
    env.stop().await;
    // Corrupt the link between the run and its beta publication, then approve.
    env.db().execute("UPDATE publishes SET status='failed',record=json_set(record,'$.status','failed') WHERE id=?1", [&c.beta]).unwrap();
    let (status, _) = env
        .call(
            "POST",
            &format!("/api/v1/approvals/{}/approve", c.approval),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    env.shutdown = tokio_util::sync::CancellationToken::new();
    let mut revived = Env::build(
        env.root,
        env.store,
        true,
        Some((env.owner, env.token, env.other, env.other_token)),
    )
    .await;
    let view = revived.wait_run(project, &c.run, &["failed"]).await;
    assert!(
        ["approval_stale", "beta_not_published"].contains(&view["error"]["code"].as_str().unwrap()),
        "{view}"
    );
    revived.stop().await;
}
