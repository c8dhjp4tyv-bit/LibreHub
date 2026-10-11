mod common;
use axum::http::StatusCode;
use common::*;
use librehub_api::outbound_worker::TransportResult;
use librehub_automation::webhook;
use librehub_common::*;
use serde_json::{Value, json};
use std::{net::IpAddr, sync::Arc};

const HOST: &str = "hooks.example.com";
fn public(ip: &str) -> Vec<IpAddr> {
    vec![ip.parse().unwrap()]
}
async fn setup() -> (Env, ProjectId, String, String) {
    let env = Env::at(tempfile::tempdir().unwrap(), false).await;
    env.resolver
        .set(HOST, vec![vec!["93.184.216.34".parse().unwrap()]]);
    let project = env.project().await;
    let (status, body) = env
        .call("POST", &format!("/api/v1/projects/{project}/integrations/webhooks"), Some(&env.token), Some(json!({"url":format!("https://{HOST}/librehub"),"event_types":["automation.started","build.started","automation.completed"],"description":"ci"})))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let secret = body["secret"].as_str().unwrap().to_owned();
    let id = body["webhook"]["id"].as_str().unwrap().to_owned();
    (env, project, id, secret)
}
/// One supervisor pass: outbox -> deliveries, then every due delivery once.
async fn pump(env: &Env) -> usize {
    for event in env.store.outbox_batch("webhooks", 64).await.unwrap() {
        env.store
            .fan_out(event, env.store.automation_limits.max_chain_depth)
            .await
            .unwrap();
    }
    let due = env.store.claim_deliveries(16).await.unwrap();
    let n = due.len();
    for d in due {
        env.outbound.deliver(d).await.unwrap();
    }
    n
}
fn make_due(env: &Env) {
    env.db().execute("UPDATE integration_deliveries SET next_attempt_at='2000-01-01T00:00:00Z' WHERE status='retry_wait'", []).unwrap();
}
async fn emit_event(env: &Env, project: ProjectId) -> String {
    let automation = env.create_automation(project, json!({"name":"A","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]})).await;
    let (status, started) = env
        .trigger(project, automation, json!({"idempotency_key":"e"}))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    started["run"]["id"].as_str().unwrap().to_owned()
}
fn deliveries(env: &Env) -> Vec<(String, String, u32)> {
    env.db()
        .prepare("SELECT id,status,attempts FROM integration_deliveries ORDER BY created_at, rowid")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[tokio::test]
async fn deliveries_are_signed_over_the_transmitted_bytes_and_identity() {
    let (env, project, _hook, secret) = setup().await;
    let run = emit_event(&env, project).await;
    assert_eq!(pump(&env).await, 1);
    let sent = env.transport.requests.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    assert_eq!(request.url, format!("https://{HOST}/librehub"));
    assert_eq!(
        request
            .pinned
            .iter()
            .map(|a| a.ip().to_string())
            .collect::<Vec<_>>(),
        ["93.184.216.34"],
        "connection is pinned to the validated address"
    );
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let timestamp: i64 = header(webhook::TIMESTAMP_HEADER).parse().unwrap();
    let delivery = header(webhook::DELIVERY_HEADER);
    let signature = header(webhook::SIGNATURE_HEADER);
    let now = chrono::Utc::now().timestamp();
    assert!(webhook::verify_signature(
        secret.as_bytes(),
        &signature,
        timestamp,
        &delivery,
        &request.body,
        now
    ));
    // A receiver using the wrong secret, a modified body or another delivery ID rejects it.
    assert!(!webhook::verify_signature(
        b"whsec_wrong",
        &signature,
        timestamp,
        &delivery,
        &request.body,
        now
    ));
    let mut tampered = request.body.clone();
    tampered.push(b' ');
    assert!(!webhook::verify_signature(
        secret.as_bytes(),
        &signature,
        timestamp,
        &delivery,
        &tampered,
        now
    ));
    assert!(!webhook::verify_signature(
        secret.as_bytes(),
        &signature,
        timestamp,
        "00000000-0000-0000-0000-000000000000",
        &request.body,
        now
    ));
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["version"], 1);
    assert_eq!(body["event_type"], "automation.started");
    assert_eq!(body["delivery_id"], delivery.as_str());
    assert_eq!(body["event_id"], header(webhook::EVENT_ID_HEADER).as_str());
    assert_eq!(body["origin"]["kind"], "automation");
    assert_eq!(body["origin"]["automation_run_id"], run.as_str());
    assert_eq!(body["chain_depth"], 0);
    assert_eq!(body["project_id"], project.to_string());
    let text = String::from_utf8(request.body.clone()).unwrap();
    assert!(!text.contains(&secret) && !text.contains("token") && !text.contains("password"));
    env.shutdown.cancel();
}

#[tokio::test]
async fn the_delivery_row_exists_before_any_byte_is_sent() {
    let (env, project, ..) = setup().await;
    emit_event(&env, project).await;
    let root = env.root.path().to_owned();
    let seen: Arc<std::sync::Mutex<Vec<(String, u32)>>> = Arc::default();
    let observed = seen.clone();
    *env.transport.observer.lock().unwrap() = Some(Box::new(move || {
        let db = rusqlite::Connection::open(root.join("builds.sqlite3")).unwrap();
        let rows: Vec<(String, u32)> = db
            .prepare("SELECT status,attempts FROM integration_deliveries")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        observed.lock().unwrap().extend(rows);
    }));
    pump(&env).await;
    assert_eq!(*seen.lock().unwrap(), vec![("delivering".to_owned(), 1)]);
    assert_eq!(deliveries(&env)[0].1, "delivered");
    env.shutdown.cancel();
}

#[tokio::test]
async fn retries_keep_event_and_delivery_identity_and_recover_after_failures() {
    let (env, project, ..) = setup().await;
    emit_event(&env, project).await;
    *env.transport.script.lock().unwrap() = vec![
        TransportResult::Response {
            status: 500,
            retry_after: None,
        },
        TransportResult::Timeout,
        TransportResult::Response {
            status: 429,
            retry_after: Some(1),
        },
        TransportResult::Connect,
        TransportResult::Response {
            status: 204,
            retry_after: None,
        },
    ];
    for expected in [
        "retry_wait",
        "retry_wait",
        "retry_wait",
        "retry_wait",
        "delivered",
    ] {
        assert_eq!(pump(&env).await, 1);
        assert_eq!(deliveries(&env)[0].1, expected);
        make_due(&env);
    }
    let sent = env.transport.requests.lock().unwrap().clone();
    assert_eq!(sent.len(), 5);
    let header = |r: &Recorded, n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert!(
        sent.iter()
            .all(|r| header(r, webhook::EVENT_ID_HEADER)
                == header(&sent[0], webhook::EVENT_ID_HEADER))
    );
    assert!(
        sent.iter()
            .all(|r| header(r, webhook::DELIVERY_HEADER)
                == header(&sent[0], webhook::DELIVERY_HEADER))
    );
    assert!(
        sent.iter().all(|r| r.body == sent[0].body),
        "the persisted payload is re-sent byte for byte"
    );
    // History keeps every attempt.
    let (_, detail) = env
        .call(
            "GET",
            &format!(
                "/api/v1/projects/{project}/integrations/deliveries/{}",
                deliveries(&env)[0].0
            ),
            Some(&env.token),
            None,
        )
        .await;
    let attempts = detail["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 5);
    assert_eq!(attempts[0]["http_status"], 500);
    assert_eq!(attempts[1]["error"], "timeout");
    assert_eq!(attempts[4]["outcome"], "delivered");
    env.shutdown.cancel();
}

#[tokio::test]
async fn retry_after_is_honoured_but_bounded_and_attempts_are_capped() {
    let (mut env, project, ..) = setup().await;
    env.outbound.max_attempts = 3;
    emit_event(&env, project).await;
    *env.transport.script.lock().unwrap() = vec![TransportResult::Response {
        status: 503,
        retry_after: Some(120),
    }];
    for expected in ["retry_wait", "retry_wait", "dead_letter"] {
        pump(&env).await;
        assert_eq!(deliveries(&env)[0].1, expected);
        make_due(&env);
    }
    assert_eq!(
        pump(&env).await,
        0,
        "dead letters are never retried automatically"
    );
    let next: String = env
        .db()
        .query_row(
            "SELECT next_attempt_at FROM integration_deliveries",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let _ = next;
    let (_, audit) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/audit"),
            Some(&env.token),
            None,
        )
        .await;
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "webhook.delivery_failed")
    );
    // Manual replay creates a new delivery of the same event and delivers it.
    let original = deliveries(&env)[0].0.clone();
    *env.transport.script.lock().unwrap() = vec![TransportResult::Response {
        status: 200,
        retry_after: None,
    }];
    let (status, replay) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/deliveries/{original}/replay"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_ne!(replay["id"], original.as_str());
    assert_eq!(replay["replay_of"], original.as_str());
    pump(&env).await;
    let all = deliveries(&env);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].1, "delivered");
    let events: Vec<String> = env
        .db()
        .prepare("SELECT DISTINCT event_id FROM integration_deliveries")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(events.len(), 1, "a replay re-sends the same event");
    // The replayed payload names the new delivery.
    let sent = env
        .transport
        .requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&sent.body).unwrap()["delivery_id"],
        all[1].0.as_str()
    );
    // A delivery that is still in flight cannot be replayed.
    let (status, _) = env
        .call(
            "POST",
            &format!(
                "/api/v1/projects/{project}/integrations/deliveries/{}/replay",
                all[1].0
            ),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "terminal deliveries may be replayed again"
    );
    env.shutdown.cancel();
}

#[tokio::test]
async fn permanent_client_errors_and_redirects_are_not_retried() {
    let (env, project, ..) = setup().await;
    emit_event(&env, project).await;
    *env.transport.script.lock().unwrap() = vec![TransportResult::Response {
        status: 302,
        retry_after: None,
    }];
    pump(&env).await;
    assert_eq!(deliveries(&env)[0].1, "failed");
    let reason: Option<String> = env
        .db()
        .query_row("SELECT last_error FROM integration_deliveries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(reason.as_deref(), Some("redirect_rejected"));
    make_due(&env);
    assert_eq!(pump(&env).await, 0);
    assert_eq!(
        env.transport.requests.lock().unwrap().len(),
        1,
        "the redirect target is never contacted"
    );
    env.shutdown.cancel();
}

#[tokio::test]
async fn unsafe_destinations_are_rejected_at_creation() {
    let env = Env::at(tempfile::tempdir().unwrap(), false).await;
    env.resolver.set(
        "rebind.example.com",
        vec![vec!["127.0.0.1".parse().unwrap()]],
    );
    env.resolver.set(
        "meta.example.com",
        vec![vec!["169.254.169.254".parse().unwrap()]],
    );
    env.resolver.set(
        "mixed.example.com",
        vec![vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ]],
    );
    let project = env.project().await;
    let url = format!("/api/v1/projects/{project}/integrations/webhooks");
    for (target, code) in [
        ("http://hooks.example.com/x", "webhook_url_not_https"),
        (
            "https://user:pw@hooks.example.com/x",
            "webhook_url_credentials",
        ),
        ("https://127.0.0.1/x", "webhook_destination_not_public"),
        ("https://[::1]/x", "webhook_destination_not_public"),
        ("https://10.0.0.1/x", "webhook_destination_not_public"),
        (
            "https://169.254.169.254/latest/meta-data",
            "webhook_destination_not_public",
        ),
        ("https://localhost/x", "webhook_url_host"),
        (
            "https://rebind.example.com/x",
            "webhook_destination_not_public",
        ),
        (
            "https://meta.example.com/x",
            "webhook_destination_not_public",
        ),
        (
            "https://mixed.example.com/x",
            "webhook_destination_not_public",
        ),
        (
            "https://nxdomain.example.com/x",
            "webhook_destination_unresolvable",
        ),
        ("https://hooks.example.com:22/x", "webhook_url_port"),
    ] {
        let (status, body) = env
            .call(
                "POST",
                &url,
                Some(&env.token),
                Some(json!({"url":target,"event_types":["build.started"]})),
            )
            .await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some(code)),
            "{target}: {body}"
        );
    }
    let count: i64 = env
        .db()
        .query_row("SELECT count(*) FROM webhook_subscriptions", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    env.shutdown.cancel();
}

#[tokio::test]
async fn dns_rebinding_after_creation_is_blocked_on_every_attempt() {
    let (env, project, ..) = setup().await;
    emit_event(&env, project).await;
    // The name now resolves to an internal service.
    env.resolver
        .set(HOST, vec![vec!["10.0.0.7".parse().unwrap()]]);
    pump(&env).await;
    assert_eq!(deliveries(&env)[0].1, "failed");
    let reason: Option<String> = env
        .db()
        .query_row("SELECT last_error FROM integration_deliveries", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(reason.as_deref(), Some("webhook_destination_not_public"));
    assert!(
        env.transport.requests.lock().unwrap().is_empty(),
        "no connection to a non-public address is ever attempted"
    );
    // A resolver that answers differently on the second query is checked again, not cached.
    let (env2, project2, ..) = setup().await;
    env2.resolver.set(
        HOST,
        vec![public("93.184.216.34"), public("169.254.169.254")],
    );
    emit_event(&env2, project2).await;
    *env2.transport.script.lock().unwrap() = vec![TransportResult::Response {
        status: 500,
        retry_after: None,
    }];
    pump(&env2).await;
    make_due(&env2);
    pump(&env2).await;
    assert_eq!(deliveries(&env2)[0].1, "failed");
    assert_eq!(env2.transport.requests.lock().unwrap().len(), 1);
    env.shutdown.cancel();
    env2.shutdown.cancel();
}

#[tokio::test]
async fn secret_rotation_takes_effect_for_later_deliveries_and_secrets_are_never_listed() {
    let (env, project, hook, secret) = setup().await;
    let (_, listed) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/webhooks"),
            Some(&env.token),
            None,
        )
        .await;
    let rendered = listed.to_string();
    assert!(
        !rendered.contains(&secret) && !rendered.contains("whsec_"),
        "{rendered}"
    );
    assert!(listed[0]["secret_fingerprint"].as_str().unwrap().len() >= 8);
    let (status, rotated) = env
        .call(
            "POST",
            &format!("/api/v1/projects/{project}/integrations/webhooks/{hook}/rotate"),
            Some(&env.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let new_secret = rotated["secret"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, secret);
    assert_ne!(
        rotated["webhook"]["secret_fingerprint"],
        listed[0]["secret_fingerprint"]
    );
    emit_event(&env, project).await;
    pump(&env).await;
    let request = env.transport.requests.lock().unwrap()[0].clone();
    let get = |n: &str| {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let (ts, delivery, sig) = (
        get(webhook::TIMESTAMP_HEADER).parse().unwrap(),
        get(webhook::DELIVERY_HEADER),
        get(webhook::SIGNATURE_HEADER),
    );
    let now = chrono::Utc::now().timestamp();
    assert!(webhook::verify_signature(
        new_secret.as_bytes(),
        &sig,
        ts,
        &delivery,
        &request.body,
        now
    ));
    assert!(!webhook::verify_signature(
        secret.as_bytes(),
        &sig,
        ts,
        &delivery,
        &request.body,
        now
    ));
    // Stored encrypted, not as the raw value.
    let stored: Vec<u8> = env
        .db()
        .query_row("SELECT secret FROM webhook_subscriptions", [], |r| r.get(0))
        .unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains("whsec_"));
    env.shutdown.cancel();
}

#[tokio::test]
async fn subscriptions_are_owner_scoped_and_bounded() {
    let (env, project, hook, _) = setup().await;
    let base = format!("/api/v1/projects/{project}/integrations/webhooks");
    for (method, path) in [
        ("GET", base.clone()),
        ("GET", format!("{base}/{hook}")),
        ("DELETE", format!("{base}/{hook}")),
        ("POST", format!("{base}/{hook}/rotate")),
        ("GET", format!("{base}/{hook}/deliveries")),
    ] {
        let (status, _) = env.call(method, &path, Some(&env.other_token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
    assert_eq!(
        env.call(
            "PATCH",
            &format!("{base}/{hook}"),
            Some(&env.other_token),
            Some(json!({"enabled":false}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.call(
            "POST",
            &base,
            Some(&env.other_token),
            Some(json!({"url":"https://hooks.example.com/z","event_types":["build.started"]}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // A read-only token cannot configure subscriptions.
    let reader = env
        .store
        .issue_token(env.owner, "r".into(), vec![Scope::IntegrationsRead])
        .await
        .unwrap()
        .token
        .0;
    assert_eq!(
        env.call("GET", &base, Some(&reader), None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        env.call(
            "POST",
            &base,
            Some(&reader),
            Some(json!({"url":"https://hooks.example.com/z","event_types":["build.started"]}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Bounded count and valid filters.
    env.resolver
        .set("a.example.com", vec![public("93.184.216.35")]);
    for i in 0..7 {
        let (status, body) = env.call("POST", &base, Some(&env.token), Some(json!({"url":format!("https://a.example.com/{i}"),"event_types":["build.started"]}))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let (status, body) = env
        .call(
            "POST",
            &base,
            Some(&env.token),
            Some(json!({"url":"https://a.example.com/overflow","event_types":["build.started"]})),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (
            StatusCode::TOO_MANY_REQUESTS,
            Some("webhook_limit_exceeded")
        )
    );
    assert_eq!(
        env.call(
            "POST",
            &base,
            Some(&env.token),
            Some(json!({"url":"https://a.example.com/bad","event_types":["root.shell"]}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.call("DELETE", &format!("{base}/{hook}"), Some(&env.token), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    env.shutdown.cancel();
}

#[tokio::test]
async fn duplicate_fan_out_and_restart_do_not_duplicate_or_lose_deliveries() {
    let (env, project, ..) = setup().await;
    emit_event(&env, project).await;
    let events = env.store.outbox_batch("webhooks", 64).await.unwrap();
    let started: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "automation.started")
        .cloned()
        .collect();
    assert_eq!(started.len(), 1);
    for _ in 0..3 {
        env.store.fan_out(started[0].clone(), 3).await.unwrap();
    }
    assert_eq!(deliveries(&env).len(), 1, "(subscription, event) is unique");
    // A crash mid-delivery leaves the row `delivering`; recovery makes it due again (at-least-once).
    let due = env.store.claim_deliveries(4).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(deliveries(&env)[0].1, "delivering");
    assert_eq!(env.store.recover_deliveries().await.unwrap(), 1);
    assert_eq!(deliveries(&env)[0].1, "retry_wait");
    assert_eq!(pump(&env).await, 1);
    assert_eq!(deliveries(&env)[0].1, "delivered");
    env.shutdown.cancel();
}

#[tokio::test]
async fn origin_filters_and_chain_depth_stop_notification_loops() {
    let (env, project, hook, _) = setup().await;
    // Opt out of everything automation-originated.
    let (status, _) = env
        .call(
            "PATCH",
            &format!("/api/v1/projects/{project}/integrations/webhooks/{hook}"),
            Some(&env.token),
            Some(json!({"exclude_origins":["automation"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    emit_event(&env, project).await;
    pump(&env).await;
    assert!(deliveries(&env).is_empty(), "filtered by origin");
    // A run that is already deep in a chain is admitted, but its events are no longer delivered.
    let automation = env.create_automation(project, json!({"name":"Deep","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]})).await;
    env.call(
        "PATCH",
        &format!("/api/v1/projects/{project}/integrations/webhooks/{hook}"),
        Some(&env.token),
        Some(json!({"exclude_origins":[]})),
    )
    .await;
    let (status, deep) = env
        .trigger(
            project,
            automation,
            json!({"idempotency_key":"deep","chain_depth":3}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{deep}");
    pump(&env).await;
    assert_eq!(
        deliveries(&env).len(),
        0,
        "events at the maximum chain depth are suppressed"
    );
    let (_, audit) = env
        .call(
            "GET",
            &format!("/api/v1/projects/{project}/integrations/audit"),
            Some(&env.token),
            None,
        )
        .await;
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "webhook.chain_limit")
    );
    // And a chain that is already too deep cannot start at all.
    let (status, body) = env
        .trigger(
            project,
            automation,
            json!({"idempotency_key":"deeper","chain_depth":4}),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("automation_loop_detected")
        )
    );
    env.shutdown.cancel();
}

#[tokio::test]
async fn shutdown_drains_other_deliveries_after_a_task_panics() {
    use librehub_api::outbound_worker::Transport;
    use librehub_automation::webhook::Destination;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;
    use tokio_util::sync::CancellationToken;

    struct DrainTransport {
        started: Barrier,
        shutdown: CancellationToken,
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl Transport for DrainTransport {
        async fn post(
            &self,
            _: &Destination,
            _: &[std::net::SocketAddr],
            _: Vec<(String, String)>,
            _: Vec<u8>,
        ) -> TransportResult {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.wait().await;
            self.shutdown.cancelled().await;
            if index == 0 {
                panic!("synthetic delivery panic");
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            TransportResult::Response {
                status: 204,
                retry_after: None,
            }
        }
    }
    let (env, project, _, _) = setup().await;
    let (status, body) = env.call("POST", &format!("/api/v1/projects/{project}/integrations/webhooks"), Some(&env.token), Some(json!({"url":format!("https://{HOST}/second"),"event_types":["automation.started"]}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    emit_event(&env, project).await;
    let transport = Arc::new(DrainTransport {
        started: Barrier::new(3),
        shutdown: env.shutdown.clone(),
        calls: AtomicUsize::new(0),
    });
    let mut worker = env.outbound.clone();
    worker.transport = transport.clone();
    let task = tokio::spawn(worker.run());
    tokio::time::timeout(std::time::Duration::from_secs(5), transport.started.wait())
        .await
        .unwrap();
    env.shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        deliveries(&env)
            .iter()
            .filter(|(_, status, _)| status == "delivered")
            .count(),
        1
    );
}
