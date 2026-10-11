//! M7 regression (OIDC policy revocation). Any real change to an integration's trusted GitHub
//! identity policy revokes every credential minted through that connection, atomically with the
//! policy change. Unchanged policies have no side effects, and other integrations' credentials
//! are untouched. Revoked credentials are rejected on every route, not only at exchange time.
mod common;
use axum::http::StatusCode;
use common::*;
use librehub_automation::oidc::GithubIdentityPolicy;
use librehub_common::*;
use serde_json::{Value, json};

/// Creates one OIDC integration in a new project and returns the integration's id.
async fn project_with_policy(policy: &GithubIdentityPolicy) -> (Env, ProjectId, String) {
    let env = Env::new().await;
    install_signing_key(&env);
    let project = env.project().await;
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            Some(json!({"name":"gha","policy":policy})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let connection = connection_id(&env, project);
    (env, project, connection)
}
/// The live connection of a project (the newest one when a test creates several).
fn connection_id(env: &Env, project: ProjectId) -> String {
    env.db()
        .query_row(
            "SELECT id FROM integration_connections WHERE project_id=?1 AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [project.to_string()],
            |r| r.get(0),
        )
        .unwrap()
}
/// Exchanges a valid GitHub identity for a credential and returns the bearer token.
async fn credential(env: &Env, project: ProjectId, claims: Value) -> String {
    let (status, body) = oidc_exchange(env, project, &sign_github_token(claims)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_owned()
}
fn claims_with(edit: fn(&mut Value)) -> Value {
    let mut claims = github_claims();
    edit(&mut claims);
    claims
}
/// Whether a credential can read its own project, which needs a live credential.
async fn accepted(env: &Env, project: ProjectId, token: &str) -> bool {
    env.call(
        "GET",
        &format!("/api/v1/projects/{project}"),
        Some(token),
        None,
    )
    .await
    .0 == StatusCode::OK
}
async fn update(env: &Env, project: ProjectId, connection: &str, body: Value) -> StatusCode {
    let (status, response) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/integrations/oidc/{connection}"),
            Some(&env.token),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    status
}
fn revoked_audit_entries(env: &Env, project: ProjectId) -> usize {
    env.db()
        .query_row(
            "SELECT count(*) FROM integration_audit_events WHERE project_id=?1 AND action='integration.credentials_revoked'",
            [project.to_string()],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
}

/// One real change per trusted dimension. `setup` is the policy the integration starts with,
/// `narrow` is applied on top of it, and `claims` shapes the identity used to mint the credential.
struct Case {
    name: &'static str,
    setup: fn(&mut GithubIdentityPolicy),
    claims: fn(&mut Value),
    narrow: fn(&mut GithubIdentityPolicy),
}

#[tokio::test]
async fn every_narrowing_of_the_trusted_identity_revokes_existing_credentials() {
    let cases = [
        Case {
            name: "allowed branch removed",
            setup: |_| {},
            claims: |_| {},
            narrow: |p| p.allowed_refs.retain(|r| r != "refs/heads/main"),
        },
        Case {
            name: "allowed workflow removed",
            setup: |p| {
                p.allowed_workflows
                    .push("octo/hello/.github/workflows/other.yml@*".into())
            },
            claims: |_| {},
            narrow: |p| p.allowed_workflows.retain(|w| !w.contains("release.yml")),
        },
        Case {
            name: "environments restricted",
            setup: |p| p.allowed_environments = vec!["production".into()],
            claims: |c| c["environment"] = json!("production"),
            narrow: |p| p.allowed_environments = vec!["staging".into()],
        },
        Case {
            name: "event types restricted",
            setup: |_| {},
            claims: |_| {},
            narrow: |p| p.allowed_event_types = vec!["workflow_dispatch".into()],
        },
        Case {
            name: "allowed permissions changed",
            setup: |_| {},
            claims: |_| {},
            narrow: |p| p.allowed_permissions = vec![Scope::ProjectsRead],
        },
        Case {
            name: "repository owner restriction changed",
            setup: |_| {},
            claims: |_| {},
            narrow: |p| p.repository_owner_id = "424242".into(),
        },
        Case {
            name: "credential lifetime changed",
            setup: |_| {},
            claims: |_| {},
            narrow: |p| p.token_ttl_seconds = 300,
        },
    ];
    for case in cases {
        let mut initial = github_policy();
        (case.setup)(&mut initial);
        let (env, project, connection) = project_with_policy(&initial).await;
        let token = credential(&env, project, claims_with(case.claims)).await;
        assert!(
            accepted(&env, project, &token).await,
            "{}: works before the change",
            case.name
        );
        let mut narrowed = initial.clone();
        (case.narrow)(&mut narrowed);
        update(&env, project, &connection, json!({"policy": narrowed})).await;
        assert!(
            !accepted(&env, project, &token).await,
            "{}: the old credential is revoked",
            case.name
        );
        assert_eq!(
            revoked_audit_entries(&env, project),
            1,
            "{}: the revocation is audited",
            case.name
        );
    }
}

#[tokio::test]
async fn disabling_or_deleting_the_connection_revokes_existing_credentials() {
    for action in ["disable", "delete"] {
        let (env, project, connection) = project_with_policy(&github_policy()).await;
        let token = credential(&env, project, github_claims()).await;
        let path = format!("/api/v1/projects/{project}/integrations/oidc/{connection}");
        let (status, body) = match action {
            "disable" => {
                env.call(
                    "PATCH",
                    &path,
                    Some(&env.token),
                    Some(json!({"enabled": false})),
                )
                .await
            }
            _ => env.call("DELETE", &path, Some(&env.token), None).await,
        };
        assert!(status.is_success(), "{action}: {body}");
        assert!(
            !accepted(&env, project, &token).await,
            "{action}: the credential is revoked"
        );
    }
}

#[tokio::test]
async fn re_enabling_never_resurrects_a_revoked_credential_but_allows_new_exchanges() {
    let (env, project, connection) = project_with_policy(&github_policy()).await;
    let old = credential(&env, project, github_claims()).await;
    update(&env, project, &connection, json!({"enabled": false})).await;
    update(&env, project, &connection, json!({"enabled": true})).await;
    assert!(
        !accepted(&env, project, &old).await,
        "the revoked credential stays revoked"
    );
    let fresh = credential(&env, project, github_claims()).await;
    assert!(
        accepted(&env, project, &fresh).await,
        "a new exchange under the enabled policy works"
    );
}

#[tokio::test]
async fn unchanged_or_reordered_policies_have_no_side_effects() {
    let mut policy = github_policy();
    policy.allowed_refs = vec!["refs/heads/main".into(), "refs/tags/v*".into()];
    let (env, project, connection) = project_with_policy(&policy).await;
    let token = credential(&env, project, github_claims()).await;
    update(
        &env,
        project,
        &connection,
        json!({"policy": github_policy_with_refs(&["refs/tags/v*", "refs/heads/main"])}),
    )
    .await;
    update(&env, project, &connection, json!({"policy": policy})).await;
    assert!(
        accepted(&env, project, &token).await,
        "reordering or re-saving is not a policy change"
    );
    assert_eq!(
        revoked_audit_entries(&env, project),
        0,
        "no revocation was recorded"
    );
}

#[tokio::test]
async fn repository_display_name_changes_are_saved_without_revoking_credentials() {
    let mut policy = github_policy();
    let (mut env, project, connection) = project_with_policy(&policy).await;
    let token = credential(&env, project, github_claims()).await;
    for name in [Some("octo/renamed".to_owned()), None] {
        policy.repository = name.clone();
        update(&env, project, &connection, json!({"policy": policy})).await;
        let stored: String = env
            .db()
            .query_row(
                "SELECT policy FROM integration_connections WHERE id=?1",
                [&connection],
                |r| r.get(0),
            )
            .unwrap();
        let stored: GithubIdentityPolicy = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored.repository, name);
        assert!(accepted(&env, project, &token).await);
        assert_eq!(revoked_audit_entries(&env, project), 0);
    }
    env.stop().await;
}

fn github_policy_with_refs(refs: &[&str]) -> GithubIdentityPolicy {
    let mut policy = github_policy();
    policy.allowed_refs = refs.iter().map(|r| (*r).to_owned()).collect();
    policy
}

#[tokio::test]
async fn other_integrations_credentials_remain_valid() {
    let (env, project, connection) = project_with_policy(&github_policy()).await;
    let mut other = github_policy();
    other.repository_id = "2000001".into();
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/oidc"),
            Some(&env.token),
            Some(json!({"name":"other","policy":other})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let first = credential(&env, project, github_claims()).await;
    let second = credential(
        &env,
        project,
        claims_with(|c| {
            c["repository_id"] = json!("2000001");
            c["repository"] = json!("octo/other");
            c["sub"] = json!("repo:octo/other:ref:refs/heads/main");
        }),
    )
    .await;
    let mut narrowed = github_policy();
    narrowed.allowed_refs = vec!["refs/tags/v*".into()];
    update(&env, project, &connection, json!({"policy": narrowed})).await;
    assert!(
        !accepted(&env, project, &first).await,
        "the narrowed integration's credential is revoked"
    );
    assert!(
        accepted(&env, project, &second).await,
        "another integration's credential is untouched"
    );
}

#[tokio::test]
async fn revoked_credentials_cannot_build_automate_publish_or_promote() {
    let (env, project, connection) = project_with_policy(&github_policy()).await;
    let automation = env
        .create_automation(
            project,
            json!({"name":"release","triggers":[{"type":"ci"},{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]}),
        )
        .await;
    let token = credential(&env, project, github_claims()).await;
    let (status, body) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/automations/{automation}/run"),
            Some(&token),
            Some(json!({"idempotency_key":"before-revocation"})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "the credential is authorized before the change: {body}"
    );
    let mut narrowed = github_policy();
    narrowed.allowed_refs = vec!["refs/tags/v*".into()];
    update(&env, project, &connection, json!({"policy": narrowed})).await;
    let fake = uuid::Uuid::new_v4();
    let attempts = [
        (
            "POST",
            format!("/api/v1/projects/{project}/automations/{automation}/run"),
            json!({"idempotency_key":"after"}),
        ),
        (
            "POST",
            format!("/api/v1/projects/{project}/builds"),
            json!({}),
        ),
        ("POST", format!("/api/v1/builds/{fake}/publish"), json!({})),
    ];
    for (method, path, body) in attempts {
        let (status, response) = env.call(method, &path, Some(&token), Some(body)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: {response}"
        );
    }
}

#[tokio::test]
async fn concurrent_exchanges_and_a_policy_update_leave_no_stale_access() {
    let (env, project, connection) = project_with_policy(&github_policy()).await;
    let mut narrowed = github_policy();
    narrowed.allowed_refs = vec!["refs/tags/v*".into()];
    let path = format!("/api/v1/projects/{project}/integrations/oidc/{connection}");
    let body = json!({"policy": narrowed});
    let jwts: Vec<String> = (0..4).map(|_| sign_github_token(github_claims())).collect();
    let (update_result, a, b, c, d) = tokio::join!(
        env.call("PATCH", &path, Some(&env.token), Some(body)),
        oidc_exchange(&env, project, &jwts[0]),
        oidc_exchange(&env, project, &jwts[1]),
        oidc_exchange(&env, project, &jwts[2]),
        oidc_exchange(&env, project, &jwts[3]),
    );
    assert_eq!(update_result.0, StatusCode::OK, "{}", update_result.1);
    // Each exchange either committed before the policy update (and was revoked by it) or saw the
    // new policy and was denied. Once the update has returned, no live credential can exist.
    let live: i64 = env
        .db()
        .query_row(
            "SELECT count(*) FROM api_tokens WHERE json_extract(record,'$.integration_id')=?1 AND json_extract(record,'$.revoked_at') IS NULL",
            [connection.clone()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        live, 0,
        "no credential minted under the old policy survives the update"
    );
    for (status, body) in [a, b, c, d] {
        if status == StatusCode::OK {
            let token = body["token"].as_str().unwrap();
            assert!(
                !accepted(&env, project, token).await,
                "an early credential is revoked"
            );
        }
    }
    let (status, body) = oidc_exchange(&env, project, &sign_github_token(github_claims())).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a fresh exchange on the old branch is denied: {body}"
    );
}

#[tokio::test]
async fn credentials_stay_bound_to_their_project() {
    let (env, project, _connection) = project_with_policy(&github_policy()).await;
    let token = credential(&env, project, github_claims()).await;
    let (status, body) = env
        .call(
            "POST",
            "/api/v1/projects",
            Some(&env.token),
            Some(json!({"slug":"other","display_name":"Other","repository":{"provider":"github","url":"https://github.com/example/other"},"auto_build":true,"build_tags":true})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let other_project: ProjectId = body["project"]["id"].as_str().unwrap().parse().unwrap();
    assert_ne!(other_project, project);
    let (status, _) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{other_project}"),
            Some(&token),
            None,
        )
        .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a project credential cannot read another project"
    );
}
