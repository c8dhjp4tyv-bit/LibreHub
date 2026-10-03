use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
};
use librehub_publisher::{PublishError, flat_manager::FlatManagerClient};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct Mock {
    mode: &'static str,
    calls: Arc<AtomicUsize>,
}
async fn handler(
    State(mock): State<Mock>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    let call = mock.calls.fetch_add(1, Ordering::SeqCst);
    assert!(body.len() < 8192);
    match mock.mode {
        "scope-safe-ready" => { assert_eq!(uri.path(), "/api/v1/build/2147483647"); (StatusCode::NOT_FOUND, "not found".to_owned()) },
        "partial" if uri.path().ends_with("/missing_objects") => { let request: serde_json::Value = serde_json::from_slice(&body).unwrap(); (StatusCode::OK, serde_json::json!({"missing":request["wanted"]}).to_string()) },
        "partial" => (StatusCode::OK, "[]".to_owned()),
        "unauthorized" => (StatusCode::UNAUTHORIZED, "token-must-never-appear".to_owned()),
        "malformed" => (StatusCode::OK, "not json".to_owned()),
        "timeout" => { tokio::time::sleep(Duration::from_millis(100)).await; (StatusCode::OK, "[]".to_owned()) },
        "5xx" => (StatusCode::INTERNAL_SERVER_ERROR, "upstream-secret".to_owned()),
        "retry" if call == 0 => (StatusCode::SERVICE_UNAVAILABLE, "temporary".to_owned()),
        "commit-failure" | "publish-failure" => (StatusCode::BAD_REQUEST, "rejected-secret".to_owned()),
        "published" => (StatusCode::OK, r#"{"id":7,"repo":"stable","app_id":"org.librehub.Hello","repo_state":2,"published_state":2,"build_log_url":"marker"}"#.to_owned()),
        _ => { assert_eq!(method, Method::GET); (StatusCode::OK, "[]".to_owned()) },
    }
}
async fn server(
    mode: &'static str,
) -> (
    FlatManagerClient,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(any(handler)).with_state(Mock {
        mode,
        calls: calls.clone(),
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        FlatManagerClient::new(
            &url,
            "token-must-never-appear".into(),
            Duration::from_millis(20),
            if mode == "timeout" {
                Duration::from_millis(20)
            } else {
                Duration::from_secs(1)
            },
        )
        .unwrap(),
        calls,
        task,
    )
}
#[tokio::test]
async fn success_and_bounded_safe_retry() {
    for (mode, expected) in [("success", 1), ("retry", 2), ("5xx", 3)] {
        let (client, calls, task) = server(mode).await;
        let result = client.list("org.librehub.Hello").await;
        assert_eq!(result.is_ok(), mode != "5xx");
        assert_eq!(calls.load(Ordering::SeqCst), expected);
        task.abort();
    }
}
#[tokio::test]
async fn unauthorized_malformed_and_timeout_are_structured_and_redacted() {
    for (mode, code, expected) in [
        ("unauthorized", "flat_manager_unauthorized", 1),
        ("malformed", "flat_manager_malformed_response", 1),
        ("timeout", "publish_timeout", 3),
    ] {
        let (client, calls, task) = server(mode).await;
        let error = client.list("org.librehub.Hello").await.unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(calls.load(Ordering::SeqCst), expected);
        assert!(!format!("{error:?} {error}").contains("token-must-never-appear"));
        task.abort();
    }
}
#[tokio::test]
async fn mutations_do_not_retry_and_published_state_is_recognized() {
    for mode in ["commit-failure", "publish-failure", "5xx"] {
        let (client, calls, task) = server(mode).await;
        let result = if mode == "commit-failure" {
            client.commit(7).await
        } else {
            client.publish(7).await
        };
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.abort();
    }
    let (client, _, task) = server("published").await;
    assert_eq!(client.get(7).await.unwrap().published_state, 2);
    task.abort();
}
#[test]
fn credentials_in_urls_and_empty_tokens_are_rejected() {
    for url in [
        "http://user:secret@example.com",
        "file:///etc",
        "http://example.com/?token=secret",
    ] {
        assert!(matches!(
            FlatManagerClient::new(
                url,
                "secret".into(),
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(PublishError::Malformed)
        ));
    }
}

#[tokio::test]
async fn readiness_does_not_require_an_unrelated_application_prefix() {
    let (client, calls, task) = server("scope-safe-ready").await;
    assert!(client.ready().await);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    task.abort();
    let (client, _, task) = server("unauthorized").await;
    assert!(!client.ready().await);
    task.abort();
}

#[tokio::test]
async fn partial_upload_cannot_advance_to_commit() {
    let dir = tempfile::tempdir().unwrap();
    let objects = dir.path().join("objects/aa");
    std::fs::create_dir_all(&objects).unwrap();
    std::fs::write(
        objects.join(format!("{}.dirtree", "a".repeat(62))),
        b"object",
    )
    .unwrap();
    let (client, calls, task) = server("partial").await;
    assert!(matches!(
        client.upload(7, dir.path()).await,
        Err(PublishError::PartialUpload)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}
