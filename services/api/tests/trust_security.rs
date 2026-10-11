use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use librehub_api::{
    security_http::{SecurityHttp, admin_router, developer_router, public_router},
    store::Store,
};
use librehub_catalog::{CatalogPermissions, CatalogQuery, CatalogStorage};
use librehub_common::*;
use librehub_security::{
    FixtureDnsResolver, FixtureVulnerabilityProvider, SbomInput, diff_permissions,
    generate_spdx_document, parse_permission_snapshot, validate_domain_syntax, write_sbom_artifact,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tower::ServiceExt;

fn sample_metadata_v1() -> &'static str {
    r#"[Application]
name=org.librehub.TestApp
runtime=org.freedesktop.Platform/x86_64/23.08
sdk=org.freedesktop.Sdk/x86_64/23.08

[Context]
shared=network;
sockets=wayland;fallback-x11;
filesystems=xdg-download:ro;
"#
}

fn sample_metadata_v2_expanded() -> &'static str {
    r#"[Application]
name=org.librehub.TestApp
runtime=org.freedesktop.Platform/x86_64/23.08
sdk=org.freedesktop.Sdk/x86_64/23.08

[Context]
shared=network;
sockets=wayland;fallback-x11;session-bus;
filesystems=xdg-download:ro;home;host;
devices=all;dri;
"#
}

async fn publish_app(
    store: &Store,
    id: &str,
    channel: RepositoryChannel,
    name: &str,
) -> PublishRecord {
    let mut manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    manifest.app_id = id.into();
    let build = store.insert(manifest, Architecture::X86_64).await.unwrap();
    store
        .transition(build.id, BuildStatus::Validating, None, None)
        .await
        .unwrap();
    store
        .transition(build.id, BuildStatus::Building, None, None)
        .await
        .unwrap();
    store
        .transition(
            build.id,
            BuildStatus::Succeeded,
            Some(BuildResult {
                environment: None,
                exit_code: Some(0),
                artifacts: vec![Artifact {
                    path: format!("builds/{}/artifacts/application.flatpak", build.id),
                    size_bytes: 1,
                    sha256: "a".repeat(64),
                }],
            }),
            None,
        )
        .await
        .unwrap();
    let mut p = store.enqueue_publish(build.id, channel).await.unwrap();
    p = store.claim_publication(p.id).await.unwrap().unwrap();
    for status in [
        PublishStatus::Uploading,
        PublishStatus::Committing,
        PublishStatus::Publishing,
    ] {
        p.status = status;
        store.save_publication(p.clone()).await.unwrap();
    }
    p.status = PublishStatus::Succeeded;
    p.result = Some(PublishResult {
        published_ref: PublishedRef {
            ref_name: RepositoryRef::new(id, Architecture::X86_64, "master").unwrap(),
            commit: "b".repeat(64),
            source_commit: "a".repeat(64),
            repository_url: "https://repo.example.com/repo/stable/".into(),
        },
        signing: SigningMetadata {
            fingerprint: "F".repeat(40),
            public_key_url: "https://repo.example.com/repository.gpg".into(),
        },
    });
    store.save_publication(p.clone()).await.unwrap();
    p = store.publish_record(p.id).await.unwrap().unwrap();
    let mut metadata = librehub_catalog::metadata::fallback(id);
    metadata.name = name.into();
    metadata.summary = "A test application".into();
    metadata.description = "Test application description".into();
    metadata.categories = vec!["Utility".into()];
    metadata.version = Some("1.0".into());
    store
        .catalog_commit(
            p.clone(),
            librehub_catalog::extract::Extracted {
                metadata,
                permissions: CatalogPermissions {
                    network: true,
                    ..Default::default()
                },
                icon_png: None,
            },
        )
        .await
        .unwrap();
    p
}

async fn call_http(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(
            "192.0.2.10:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }

    let req_body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };

    let response = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let val: Value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)}))
    };
    (status, val)
}

#[tokio::test]
async fn test_domain_syntax_validation() {
    assert!(validate_domain_syntax("example.org").is_ok());
    assert!(validate_domain_syntax("sub.domain.co.uk").is_ok());
    assert_eq!(
        validate_domain_syntax("  EXAMPLE.ORG.  ").unwrap(),
        "example.org"
    );

    // Rejections
    assert!(validate_domain_syntax("").is_err());
    assert!(validate_domain_syntax("localhost").is_err());
    assert!(validate_domain_syntax("192.168.1.1").is_err());
    assert!(validate_domain_syntax("https://example.org").is_err());
    assert!(validate_domain_syntax("example.org:8080").is_err());
    assert!(validate_domain_syntax("user@example.org").is_err());
    assert!(validate_domain_syntax("test.local").is_err());
    assert!(validate_domain_syntax("-invalid.org").is_err());
}

#[tokio::test]
async fn test_publisher_domain_verification_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let dev1 = store
        .create_developer("Developer 1".into())
        .await
        .unwrap()
        .id;
    let dev2 = store
        .create_developer("Developer 2".into())
        .await
        .unwrap()
        .id;

    // 1. Request verification for example.org
    let v1 = store
        .request_domain_verification(&dev1, "example.org", VerificationMethod::DnsTxt)
        .await
        .unwrap();
    assert_eq!(v1.domain, "example.org");
    assert_eq!(v1.status, PublisherVerificationStatus::Pending);
    assert!(v1.challenge_token.is_some());

    // 2. Resolver without matching TXT record -> verification check fails
    let resolver_empty = FixtureDnsResolver::new();
    let err = store
        .check_domain_verification(&dev1, &v1.id, &resolver_empty)
        .await;
    assert!(err.is_err());

    // 3. Resolver with valid TXT record -> verification check succeeds
    let resolver_valid = FixtureDnsResolver::new().with_record(
        "example.org",
        &format!("librehub-verification={}", v1.challenge_token.unwrap()),
    );
    let v1_verified = store
        .check_domain_verification(&dev1, &v1.id, &resolver_valid)
        .await
        .unwrap();
    assert_eq!(v1_verified.status, PublisherVerificationStatus::Verified);
    assert!(v1_verified.verified_at.is_some());

    // 4. Another developer cannot request verification for already-verified domain
    let conflict_err = store
        .request_domain_verification(&dev2, "example.org", VerificationMethod::DnsTxt)
        .await;
    assert!(conflict_err.is_err());

    // 5. Developer can revoke verification
    store
        .revoke_domain_verification(&dev1, &v1.id)
        .await
        .unwrap();
    let verifications = store.list_domain_verifications(&dev1).await.unwrap();
    assert_eq!(
        verifications[0].status,
        PublisherVerificationStatus::Revoked
    );

    // 6. After revocation, another developer can request it
    let v2 = store
        .request_domain_verification(&dev2, "example.org", VerificationMethod::DnsTxt)
        .await
        .unwrap();
    assert_eq!(v2.status, PublisherVerificationStatus::Pending);
}

#[tokio::test]
async fn test_permission_extraction_and_diffing() {
    let perm1 = parse_permission_snapshot(sample_metadata_v1()).unwrap();
    assert!(perm1.network);
    assert_eq!(perm1.sockets, vec!["fallback-x11", "wayland"]);
    assert_eq!(perm1.filesystem, vec!["xdg-download:ro"]);
    assert!(perm1.devices.is_empty());

    let perm2 = parse_permission_snapshot(sample_metadata_v2_expanded()).unwrap();
    assert!(perm2.network);
    assert_eq!(
        perm2.sockets,
        vec!["fallback-x11", "session-bus", "wayland"]
    );
    assert_eq!(perm2.filesystem, vec!["home", "host", "xdg-download:ro"]);
    assert_eq!(perm2.devices, vec!["all", "dri"]);

    let pub1 = PublishId::new();
    let pub2 = PublishId::new();

    let diff = diff_permissions(
        Some(pub1.to_string()),
        pub2.to_string(),
        Some(&perm1),
        &perm2,
        chrono::Utc::now(),
    );
    assert_eq!(diff.severity, PermissionSeverity::Significant);
    assert_eq!(diff.added.filesystem, vec!["home", "host"]);
    assert_eq!(diff.added.devices, vec!["all", "dri"]);
    assert_eq!(diff.added.sockets, vec!["session-bus"]);
    assert!(diff.removed.filesystem.is_empty());
    assert!(diff.summary_notes.iter().any(|n| n.contains("home")));
    assert!(diff.summary_notes.iter().any(|n| n.contains("all")));
    let json = serde_json::to_value(diff).unwrap();
    assert!(json["summary_notes"].is_array());
    assert!(json.get("changed_network").is_some());
    for side in ["added", "removed"] {
        for category in [
            "filesystem",
            "devices",
            "sockets",
            "dbus",
            "shared",
            "other",
        ] {
            assert!(
                json[side][category].is_array(),
                "{side}.{category} must always be an array"
            );
        }
    }
}

#[tokio::test]
async fn test_spdx_sbom_generation_and_storage() {
    let dir = tempfile::tempdir().unwrap();
    let pub_id = PublishId::new();
    let app_id = "org.librehub.Sample";

    let input = SbomInput {
        publication_id: &pub_id,
        app_id,
        version: "1.0.0",
        ostree_checksum: "abcdef1234567890",
        source_commit: Some("commit123"),
        license: Some("MIT"),
        metadata_text: Some(sample_metadata_v1()),
        additional_modules: Vec::new(),
    };

    let doc = generate_spdx_document(input);
    assert_eq!(doc.spdx_version, "SPDX-2.3");
    assert_eq!(doc.name, format!("{app_id}-1.0.0"));
    assert!(doc.packages.len() >= 2); // root package + runtime platform

    let (rel_path, sha256, count) = write_sbom_artifact(dir.path(), &pub_id, &doc)
        .await
        .unwrap();
    assert_eq!(count, doc.packages.len() as u32);
    assert_eq!(sha256.len(), 64);
    assert!(dir.path().join(&rel_path).exists());

    // Read back and verify valid JSON
    let content = tokio::fs::read_to_string(dir.path().join(&rel_path))
        .await
        .unwrap();
    let loaded: SbomDocument = serde_json::from_str(&content).unwrap();
    assert_eq!(loaded.name, format!("{app_id}-1.0.0"));
}

#[tokio::test]
async fn test_vulnerability_matching_and_outage_handling() {
    use librehub_security::VulnerabilityProvider;

    let packages = vec![
        SbomPackage {
            spdx_id: String::new(),
            download_location: "NOASSERTION".into(),
            files_analyzed: false,
            name: "openssl".to_string(),
            version: Some("1.1.1".to_string()),
            package_type: "library".to_string(),
            purl: Some("pkg:generic/openssl@1.1.1".to_string()),
            license: None,
            source: None,
            hashes: BTreeMap::new(),
            scope: "runtime".to_string(),
        },
        SbomPackage {
            spdx_id: String::new(),
            download_location: "NOASSERTION".into(),
            files_analyzed: false,
            name: "zlib".to_string(),
            version: Some("1.2.11".to_string()),
            package_type: "library".to_string(),
            purl: None,
            license: None,
            source: None,
            hashes: BTreeMap::new(),
            scope: "runtime".to_string(),
        },
    ];

    // Case 1: Match findings
    let finding = VulnerabilityFinding {
        vulnerability_id: "CVE-2026-0001".to_string(),
        component_name: "openssl".to_string(),
        component_version: "1.1.1".to_string(),
        severity: VulnerabilitySeverity::Critical,
        summary: "Critical OpenSSL vulnerability".to_string(),
        reference_url: Some("https://osv.dev/vulnerability/CVE-2026-0001".to_string()),
        source_provider: "osv".to_string(),
        checked_at: chrono::Utc::now(),
    };

    let provider = FixtureVulnerabilityProvider::new(vec![finding]);
    let results = provider.check_packages(&packages).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].vulnerability_id, "CVE-2026-0001");
    assert_eq!(results[0].severity, VulnerabilitySeverity::Critical);

    // Case 2: Outage handling
    let outage_provider = FixtureVulnerabilityProvider::with_outage();
    let outage_err = outage_provider.check_packages(&packages).await;
    assert!(outage_err.is_err());
    assert!(outage_err.unwrap_err().to_string().contains("unavailable"));
}

#[tokio::test]
async fn test_moderation_actions_and_catalog_gating() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let app_id = "org.librehub.ModeratedApp";

    let pub_record = publish_app(&store, app_id, RepositoryChannel::Stable, "Moderated App").await;
    let pub_id = pub_record.id;

    // 1. Initial moderation state is normal
    let trust1 = store
        .compute_trust_summary(app_id, "stable", None, Some(&pub_id.to_string()))
        .await
        .unwrap();
    assert_eq!(trust1.moderation_state, ModerationState::Normal);

    // 2. Moderate to restricted
    store
        .apply_moderation(
            app_id,
            ModerationAction::Restrict,
            ModerationReason::PolicyViolation,
            Some("Excessive permissions".to_string()),
            Some("Investigating".to_string()),
            "operator1",
        )
        .await
        .unwrap();

    let trust2 = store
        .compute_trust_summary(app_id, "stable", None, Some(&pub_id.to_string()))
        .await
        .unwrap();
    assert_eq!(trust2.moderation_state, ModerationState::Restricted);
    assert_eq!(trust2.trust_state, TrustState::Restricted);
    assert_eq!(
        trust2.moderation_notice.as_deref(),
        Some("Excessive permissions")
    );

    // Check catalog filtering: restricted app is excluded from apps() and search()
    let apps_page = store
        .apps(CatalogQuery {
            channel: RepositoryChannel::Stable,
            limit: 20,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!apps_page.items.iter().any(|c| c.app_id == app_id));

    let search_page = store
        .apps(CatalogQuery {
            channel: RepositoryChannel::Stable,
            q: "Moderated".to_string(),
            limit: 20,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!search_page.items.iter().any(|c| c.app_id == app_id));

    // Direct app lookup still works, showing restricted status
    let direct_app = store
        .app(app_id.to_string(), RepositoryChannel::Stable)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        direct_app.card.trust.as_ref().unwrap().moderation_state,
        ModerationState::Restricted
    );

    // 3. Moderate to removed
    store
        .apply_moderation(
            app_id,
            ModerationAction::Remove,
            ModerationReason::MalwareReport,
            Some("Removed for user safety".to_string()),
            None,
            "operator1",
        )
        .await
        .unwrap();

    let trust3 = store
        .compute_trust_summary(app_id, "stable", None, Some(&pub_id.to_string()))
        .await
        .unwrap();
    assert_eq!(trust3.moderation_state, ModerationState::Removed);
    assert_eq!(trust3.trust_state, TrustState::Removed);

    // Direct app lookup now returns None (404)
    let removed_app = store
        .app(app_id.to_string(), RepositoryChannel::Stable)
        .await
        .unwrap();
    assert!(removed_app.is_none());

    // 4. Audit events exist
    let events = store.get_moderation_history(app_id).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].action, ModerationAction::Remove);
    assert_eq!(events[1].action, ModerationAction::Restrict);

    // 5. Restore
    store
        .apply_moderation(
            app_id,
            ModerationAction::Restore,
            ModerationReason::DeveloperRequest,
            Some("Reinstated after review".to_string()),
            None,
            "operator1",
        )
        .await
        .unwrap();

    let trust4 = store
        .compute_trust_summary(app_id, "stable", None, Some(&pub_id.to_string()))
        .await
        .unwrap();
    assert_eq!(trust4.moderation_state, ModerationState::Normal);

    // Reinstated app reappears in direct lookup
    let reinstated_app = store
        .app(app_id.to_string(), RepositoryChannel::Stable)
        .await
        .unwrap();
    assert!(reinstated_app.is_some());
}

#[tokio::test]
async fn test_user_reports_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let app_id = "org.librehub.ReportedApp";

    // 1. Submit report
    let report = store
        .submit_report(
            app_id,
            ReportReason::Malware,
            Some("App performs suspicious network activity".to_string()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(report.app_id, app_id);
    assert_eq!(report.reason, ReportReason::Malware);
    assert_eq!(report.status, ReportStatus::Open);

    // 2. List reports
    let pending_reports = store
        .list_reports(Some(ReportStatus::Open), None, 10, 0)
        .await
        .unwrap();
    assert_eq!(pending_reports.len(), 1);
    assert_eq!(pending_reports[0].id, report.id);

    // 3. Resolve report
    let resolved = store
        .resolve_report(
            &report.id,
            ReportStatus::Resolved,
            Some("Reviewed by security team, false positive".to_string()),
            "operator1",
        )
        .await
        .unwrap();
    assert_eq!(resolved.status, ReportStatus::Resolved);
    assert_eq!(resolved.resolved_by.as_deref(), Some("operator1"));

    // 4. Open list is now empty
    let empty_reports = store
        .list_reports(Some(ReportStatus::Open), None, 10, 0)
        .await
        .unwrap();
    assert!(empty_reports.is_empty());
}

#[tokio::test]
async fn test_security_http_routes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let data_dir = dir.path().to_path_buf();

    let sec_state = SecurityHttp::new(store.clone(), data_dir, "http://localhost:8080".to_string());

    let app = librehub_api::catalog_http::router(librehub_api::catalog_http::CatalogHttp {
        store: store.clone(),
        api_public_url: "http://localhost:8080".into(),
        repository: None,
        page_size: 20,
    })
    .merge(public_router(sec_state.clone()))
    .merge(developer_router(sec_state.clone()))
    .merge(admin_router(sec_state));

    let app_id = "org.librehub.HttpTest";
    let _pub_record = publish_app(&store, app_id, RepositoryChannel::Stable, "HTTP Test App").await;

    // Public trust endpoint
    let (status, details) = call_http(
        &app,
        "GET",
        &format!("/api/v1/catalog/apps/{app_id}/trust"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(details["trust_summary"]["trust_state"], "unverified");

    // Public report submission
    let (status, report) = call_http(
        &app,
        "POST",
        &format!("/api/v1/catalog/apps/{app_id}/reports"),
        Some(json!({
            "reason": "privacy_violation",
            "message": "App reads documents directory"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(report["app_id"], app_id);
    assert_eq!(report["reason"], "privacy_violation");
}

#[tokio::test]
async fn reports_are_limited_even_without_a_reporter_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    for reporter in [None, Some("192.0.2.10")] {
        let app = if reporter.is_some() {
            "org.example.Known"
        } else {
            "org.example.Unknown"
        };
        for _ in 0..3 {
            store
                .submit_report(app, ReportReason::Other, None, reporter)
                .await
                .unwrap();
        }
        assert!(
            store
                .submit_report(app, ReportReason::Other, None, reporter)
                .await
                .is_err()
        );
        if reporter.is_none() {
            assert!(
                store
                    .submit_report(app, ReportReason::Other, None, Some(""))
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn missing_signed_metadata_records_unavailable_without_ready_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let publication = publish_app(
        &store,
        "org.example.NoArtifact",
        RepositoryChannel::Stable,
        "Missing artifact",
    )
    .await;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let worker = librehub_api::security_worker::SecurityWorker::new(
        store.clone(),
        Some(librehub_publisher::repository::RepositoryConfig {
            public_base_url: "http://127.0.0.1:1".into(),
            public_key: b"fixture".to_vec(),
            fingerprint: "A".repeat(40),
            runtime_repo_url: "https://example.org/runtime.flatpakrepo".into(),
        }),
        shutdown.clone(),
    );
    let task = tokio::spawn(worker.run());
    let details = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(details) = store
                .get_release_security_details(&publication.id)
                .await
                .unwrap()
            {
                break details;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    shutdown.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(details.status, ReleaseSecurityState::Unavailable);
    assert!(details.sbom_path.is_none());
    assert!(details.permission_diff.is_none());
    assert!(
        store
            .get_current_permissions(&publication.app_id, "stable")
            .await
            .unwrap()
            .is_none()
    );
}
