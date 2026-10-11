mod common;
use axum::http::StatusCode;
use common::*;
use librehub_automation::oidc::testing;
use librehub_common::*;
use serde_json::{Value, json};

async fn setup() -> (Env, ProjectId) {
    let env = Env::new().await;
    install_signing_key(&env);
    let project = env.project().await;
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            Some(json!({"name":"gha","policy":github_policy()})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (env, project)
}
fn with(f: impl FnOnce(&mut Value)) -> String {
    let mut c = github_claims();
    f(&mut c);
    sign_github_token(c)
}
async fn denied_reason(env: &Env, project: ProjectId) -> String {
    let (_, audit) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/audit"),
            Some(&env.token),
            None,
        )
        .await;
    audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "oidc.exchange_denied")
        .map(|e| e["result"].as_str().unwrap().to_owned())
        .unwrap_or_default()
}

#[tokio::test]
async fn valid_identity_receives_a_short_lived_project_bound_credential() {
    let (mut env, project) = setup().await;
    let (status, body) = oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body.get("refresh_token").is_none());
    assert!(body["expires_in"].as_i64().unwrap() <= 600);
    let scopes: Vec<String> = body["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    assert!(scopes.contains(&"automations:run".to_owned()));
    for forbidden in [
        "publishes:write",
        "releases:approve",
        "automations:write",
        "integrations:write",
        "tokens:write",
        "operator",
        "webhooks:write",
        "projects:write",
    ] {
        assert!(!scopes.contains(&forbidden.to_owned()), "{forbidden}");
    }
    let ci = body["token"].as_str().unwrap();
    // The credential works inside its project...
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{project}/automations"),
            Some(ci),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    // ...and nowhere else.
    let other = env
        .store
        .issue_token(env.other, "x".into(), Scope::developer_defaults())
        .await
        .unwrap();
    let _ = other;
    let stranger = ProjectId::new();
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{stranger}/automations"),
            Some(ci),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for path in [
        "/api/v1/projects",
        "/api/v1/tokens",
        "/api/v1/audit",
        "/api/v1/approvals",
    ] {
        let (status, _) = env.call("GET", path, Some(ci), None).await;
        assert!(status == StatusCode::FORBIDDEN, "{path} -> {status}");
    }
    // It cannot mint credentials, edit definitions or manage integrations.
    assert_eq!(
        env.call(
            "POST",
            "/api/v1/tokens",
            Some(ci),
            Some(json!({"name":"x","scopes":["projects:read"]}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/projects/{project}/automations"),
            Some(ci),
            Some(json!({"spec":release_pipeline()}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(ci),
            Some(json!({"name":"x","policy":github_policy()}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/webhooks"),
            Some(ci),
            Some(json!({"url":"https://hooks.example.com/x","event_types":["build.started"]}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Credentials are not persisted in clear text.
    let stored: String = env
        .db()
        .query_row("SELECT group_concat(record) FROM api_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!stored.contains(ci));
    env.stop().await;
}

#[tokio::test]
async fn forged_or_misdirected_tokens_are_rejected() {
    let (mut env, project) = setup().await;
    let other_key = testing::key_pair(testing::OTHER_KEY);
    let forged = testing::sign(&other_key, testing::header("k1"), github_claims());
    let cases: Vec<(&str, String)> = vec![
        ("oidc_signature_invalid", forged),
        (
            "oidc_issuer_not_trusted",
            with(|c| c["iss"] = json!("https://evil.example")),
        ),
        (
            "oidc_audience_mismatch",
            with(|c| c["aud"] = json!("https://github.com/octo")),
        ),
        (
            "oidc_token_expired",
            with(|c| c["exp"] = json!(now() - 3600)),
        ),
        (
            "oidc_token_not_yet_valid",
            with(|c| c["nbf"] = json!(now() + 3600)),
        ),
        ("oidc_key_unknown", sign_with_kid("nope")),
    ];
    for (code, token) in cases {
        let (status, body) = oidc_exchange(&env, project, &token).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::UNAUTHORIZED, Some(code)),
            "{code}: {body}"
        );
    }
    let (status, body) = env
        .call(
            "POST",
            "/api/v1/integrations/github/oidc/exchange",
            None,
            Some(json!({"project_id":project})),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("oidc_token_missing"))
    );
    // Nothing was minted.
    let federated: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM api_tokens WHERE json_extract(record,'$.project_id') IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(federated, 0);
    env.stop().await;
}
fn sign_with_kid(kid: &str) -> String {
    testing::sign(
        &testing::key_pair(testing::SIGNING_KEY),
        testing::header(kid),
        github_claims(),
    )
}

#[tokio::test]
async fn identity_policy_denies_other_repositories_owners_refs_workflows_and_environments() {
    let (mut env, project) = setup().await;
    let denials: Vec<(&str, String)> = vec![
        (
            "no_trusted_identity",
            with(|c| c["repository_id"] = json!("999")),
        ),
        (
            "oidc_owner_not_trusted",
            with(|c| c["repository_owner_id"] = json!("999")),
        ),
        (
            "oidc_ref_not_allowed",
            with(|c| {
                c["ref"] = json!("refs/heads/evil");
                c["sub"] = json!("repo:octo/hello:ref:refs/heads/evil");
            }),
        ),
        (
            "oidc_workflow_not_allowed",
            with(|c| {
                c["workflow_ref"] = json!("octo/hello/.github/workflows/evil.yml@refs/heads/main")
            }),
        ),
        (
            "oidc_environment_not_allowed",
            with(|c| {
                c["environment"] = json!("production");
            }),
        ),
        (
            "oidc_event_not_allowed",
            with(|c| c["event_name"] = json!("schedule")),
        ),
    ];
    for (reason, token) in denials {
        let (status, body) = oidc_exchange(&env, project, &token).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("oidc_exchange_denied")),
            "{reason}: {body}"
        );
        // The generic response does not reveal which rule failed; the owner's audit trail does.
        assert!(!body.to_string().contains(reason));
        let (_, audit) = env
            .call(
                "GET",
                &format!("/api/v1/projects/{project}/integrations/audit?limit=100"),
                Some(&env.token),
                None,
            )
            .await;
        assert!(
            audit
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["result"] == reason),
            "{reason} not audited: {audit}"
        );
    }
    // A project nobody trusts this repository for is indistinguishable from a missing one.
    let (status, body) =
        oidc_exchange(&env, ProjectId::new(), &sign_github_token(github_claims())).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("oidc_exchange_denied"))
    );
    assert!(!denied_reason(&env, project).await.is_empty());
    env.stop().await;
}

#[tokio::test]
async fn untrusted_pull_requests_never_get_write_or_run_permissions() {
    let (mut env, project) = setup().await;
    let mut policy = github_policy();
    policy.allowed_event_types.push("pull_request".into());
    policy.allowed_refs.push("refs/pull/*".into());
    let (_, listed) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            None,
        )
        .await;
    let connection = listed[0]["id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/integrations/oidc/{connection}"),
            Some(&env.token),
            Some(json!({"policy":policy})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = with(|c| {
        c["event_name"] = json!("pull_request");
        c["ref"] = json!("refs/pull/7/merge");
        c["sub"] = json!("repo:octo/hello:pull_request");
    });
    let (status, body) = oidc_exchange(&env, project, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let scopes: Vec<&str> = body["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(
        !scopes.contains(&"automations:run") && !scopes.contains(&"builds:write"),
        "{scopes:?}"
    );
    let ci = body["token"].as_str().unwrap();
    let automation = env.create_automation(project, release_pipeline()).await;
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/{automation}/run"),
            Some(ci),
            Some(json!({})),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("insufficient_scope"))
    );
    env.stop().await;
}

#[tokio::test]
async fn policies_cannot_grant_privileged_scopes() {
    let (mut env, project) = setup().await;
    for scope in [
        "publishes:write",
        "releases:approve",
        "automations:write",
        "integrations:write",
        "tokens:write",
        "operator",
        "projects:write",
        "webhooks:write",
        "audit:read",
    ] {
        let mut policy = serde_json::to_value(github_policy()).unwrap();
        policy["repository_id"] = json!("4242");
        policy["allowed_permissions"] = json!([scope]);
        let (status, body) = env
            .call(
                "POST",
                &format!("/api/v1/projects/{project}/integrations/oidc"),
                Some(&env.token),
                Some(json!({"name":"x","policy":policy})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{scope}: {body}");
    }
    for mutate in [
        json!({"allowed_refs":[]}),
        json!({"repository_id":"octo/hello"}),
        json!({"token_ttl_seconds":86400}),
        json!({"allowed_workflows":[]}),
    ] {
        let mut policy = serde_json::to_value(github_policy()).unwrap();
        policy["repository_id"] = json!("4243");
        for (k, v) in mutate.as_object().unwrap() {
            policy[k] = v.clone();
        }
        assert_eq!(
            env.call(
                "POST",
                &format!("/api/v1/projects/{project}/integrations/oidc"),
                Some(&env.token),
                Some(json!({"name":"x","policy":policy}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST,
            "{mutate}"
        );
    }
    env.stop().await;
}

#[tokio::test]
async fn expiry_replay_and_revocation_are_enforced() {
    let (mut env, project) = setup().await;
    let token = sign_github_token(github_claims());
    let (status, first) = oidc_exchange(&env, project, &token).await;
    assert_eq!(status, StatusCode::OK);
    // The same identity token cannot be exchanged twice.
    let (status, again) = oidc_exchange(&env, project, &token).await;
    assert_eq!(
        (status, again["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("oidc_exchange_denied"))
    );
    assert_eq!(denied_reason(&env, project).await, "token_replayed");
    let ci = first["token"].as_str().unwrap();
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{project}/automations"),
            Some(ci),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    // Expiry is evaluated on every request.
    env.db().execute("UPDATE api_tokens SET record=json_set(record,'$.expires_at','2001-01-01T00:00:00Z') WHERE json_extract(record,'$.project_id') IS NOT NULL", []).unwrap();
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{project}/automations"),
            Some(ci),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // Revoking the connection kills credentials minted through it.
    let (_, second) = oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    let ci2 = second["token"].as_str().unwrap().to_owned();
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{project}/automations"),
            Some(&ci2),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, listed) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            None,
        )
        .await;
    let connection = listed[0]["id"].as_str().unwrap();
    assert_eq!(
        env.call(
            "DELETE",
            &format!("/api/v1/projects/{project}/integrations/oidc/{connection}"),
            Some(&env.token),
            None
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        env.call(
            "GET",
            &format!("/api/v1/projects/{project}/automations"),
            Some(&ci2),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    env.stop().await;
}

#[tokio::test]
async fn a_ci_run_is_bound_to_the_commit_github_attests_and_deduplicated() {
    let (mut env, project) = setup().await;
    let automation = env.create_automation(project, release_pipeline()).await;
    let claims = github_claims();
    let sha = claims["sha"].as_str().unwrap().to_owned();
    let (_, ex) = oidc_exchange(&env, project, &sign_github_token(claims.clone())).await;
    let ci = ex["token"].as_str().unwrap().to_owned();
    let url = format!("/api/v1/projects/{project}/automations/{automation}/run");
    // The CI identity cannot choose a different commit or ref.
    let (status, body) = env
        .call(
            "POST",
            &url,
            Some(&ci),
            Some(json!({"commit":"f".repeat(40)})),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("ci_commit_mismatch"))
    );
    let (status, started) = env.call("POST", &url, Some(&ci), Some(json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    assert_eq!(started["run"]["source_commit"], sha.as_str());
    assert_eq!(started["run"]["trigger"], "ci");
    assert_eq!(started["run"]["trigger_detail"]["repository_id"], "1296269");
    // Retrying the same workflow run returns the same automation run.
    let (status, retry) = env.call("POST", &url, Some(&ci), Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retry["run"]["id"], started["run"]["id"]);
    assert_eq!(retry["existing"], true);
    // A re-run of the workflow (new attempt) reuses the build instead of building again.
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    let build: BuildId = view["build_id"].as_str().unwrap().parse().unwrap();
    env.succeed_build(build).await;
    env.wait_run(project, &run, &["waiting_for_security"]).await;
    let mut second = claims.clone();
    second["run_attempt"] = json!("2");
    second["jti"] = json!(uuid::Uuid::new_v4().to_string());
    let (_, ex2) = oidc_exchange(&env, project, &sign_github_token(second)).await;
    let (status, rerun) = env
        .call(
            "POST",
            &url,
            Some(ex2["token"].as_str().unwrap()),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let rerun_id = rerun["run"]["id"].as_str().unwrap().to_owned();
    assert_ne!(rerun_id, run);
    let view = env
        .wait_run(
            project,
            &rerun_id,
            &["waiting_for_security", "waiting_for_publication"],
        )
        .await;
    assert_eq!(view["build_id"].as_str().unwrap(), build.to_string());
    let builds: i64 = env
        .db()
        .query_row("SELECT count(*) FROM builds", [], |r| r.get(0))
        .unwrap();
    assert_eq!(builds, 1);
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    env.stop().await;
}

#[tokio::test]
async fn a_ci_triggered_run_never_reaches_stable_without_an_approved_release() {
    let (mut env, project) = setup().await;
    // The owner deliberately removes the approval requirement from the workflow...
    let spec = json!({
        "name": "Unattended", "triggers": [{"type":"ci"},{"type":"manual"}],
        "steps": [
            {"id":"build","uses":"librehub/build"},
            {"id":"beta","uses":"librehub/publish","needs":["build"],"with":{"channel":"beta"}},
            {"id":"stable","uses":"librehub/promote","needs":["beta"],"with":{"channel":"stable"}}
        ],
        "policy": {"require_manual_approval": false}
    });
    let automation = env.create_automation(project, spec).await;
    // ...yet an untrusted external CI event still cannot promote on its own authority.
    let (_, ex) = oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    let (status, started) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/{automation}/run"),
            Some(ex["token"].as_str().unwrap()),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run = started["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    env.succeed_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    let view = env.wait_run(project, &run, &["failed"]).await;
    assert_eq!(view["error"]["code"], "approval_required");
    assert_eq!(*env.publisher.by_channel.lock().unwrap(), vec!["beta"]);
    // The same workflow run by the owner (manual trigger) is allowed to promote.
    let (_, manual) = env
        .trigger(
            project,
            automation,
            json!({"idempotency_key":"m","commit":"0".repeat(40).replace('0', "7")}),
        )
        .await;
    let run = manual["run"]["id"].as_str().unwrap().to_owned();
    let view = env.wait_run(project, &run, &["waiting_for_build"]).await;
    env.succeed_build(view["build_id"].as_str().unwrap().parse().unwrap())
        .await;
    env.wait_run(project, &run, &["completed"]).await;
    assert_eq!(
        *env.publisher.by_channel.lock().unwrap(),
        vec!["beta", "beta", "stable"]
    );
    env.stop().await;
}
