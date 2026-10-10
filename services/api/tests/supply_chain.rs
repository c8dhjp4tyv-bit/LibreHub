//! Trusted-store/key/publication-policy regression tests; real publication acceptance is separate.
use librehub_api::{store::Store, supply_chain_http};
use librehub_common::*;
use librehub_supply_chain::{Attestor, provision};
use rusqlite::Connection;
use std::sync::Arc;
fn manifest() -> FlatpakManifest {
    librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap()
}
async fn successful(store: &Store) -> BuildId {
    let build = store
        .insert(manifest(), Architecture::X86_64)
        .await
        .unwrap();
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
    build.id
}
async fn published(store: &Store) -> PublishRecord {
    let id = successful(store).await;
    let mut p = store
        .enqueue_publish(id, RepositoryChannel::Stable)
        .await
        .unwrap();
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
            ref_name: RepositoryRef::new("org.librehub.Hello", Architecture::X86_64, "master")
                .unwrap(),
            commit: "b".repeat(64),
            source_commit: "a".repeat(64),
            repository_url: "https://repo.example.org/stable/".into(),
        },
        signing: SigningMetadata {
            fingerprint: "F".repeat(40),
            public_key_url: "https://repo.example.org/key.gpg".into(),
        },
    });
    store.save_publication(p.clone()).await.unwrap();
    let p = store.publish_record(p.id).await.unwrap().unwrap();
    store
        .catalog_commit(
            p.clone(),
            librehub_catalog::extract::Extracted {
                metadata: librehub_catalog::metadata::fallback(&p.app_id),
                permissions: Default::default(),
                icon_png: None,
            },
        )
        .await
        .unwrap();
    p
}
#[tokio::test]
async fn enforce_denies_missing_provenance_before_publication_admission() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    let id = successful(&store).await;
    store.supply_policy = SupplyChainPolicy::Enforce;
    assert!(
        store
            .enqueue_publish(id, RepositoryChannel::Stable)
            .await
            .unwrap_err()
            .to_string()
            .contains("Supply-chain policy")
    );
    assert!(store.publications(id).await.unwrap().is_empty());
    let decision = store.last_supply_policy(id).await.unwrap().unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.violations[0].code, "provenance_invalid_or_missing");
}
#[tokio::test]
async fn audit_records_violation_without_changing_legacy_publication_semantics() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    let id = successful(&store).await;
    store.supply_policy = SupplyChainPolicy::AuditOnly;
    let decision = store.check_supply_policy(id).await.unwrap();
    assert!(decision.allowed);
    assert!(!decision.violations.is_empty());
    assert!(
        store
            .enqueue_publish(id, RepositoryChannel::Stable)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn legacy_public_evidence_is_explicit_and_cross_app_substitution_is_hidden() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::open(t.path()).unwrap();
    let p = published(&store).await;
    let evidence = supply_chain_http::evidence(&store, p.app_id.clone(), p.id)
        .await
        .unwrap_or_else(|_| panic!("Expected public legacy evidence"));
    assert_eq!(evidence.status, AttestationStatus::LegacyUnattested);
    assert!(!evidence.verification.verified);
    assert!(evidence.bundle.is_none());
    assert!(
        supply_chain_http::evidence(&store, "org.wrong.App".into(), p.id)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn release_signing_failure_preserves_real_durable_publication_result() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::open(t.path()).unwrap();
    let p = published(&store).await;
    assert!(store.attest_release(p.id).await.is_err());
    let after = store.publish_record(p.id).await.unwrap().unwrap();
    assert_eq!(after.status, PublishStatus::Succeeded);
    assert_eq!(after.result.unwrap().published_ref.commit, "b".repeat(64));
}
#[tokio::test]
async fn key_rotation_retirement_and_revocation_are_durable_and_audited() {
    let t = tempfile::tempdir().unwrap();
    let seed = t.path().join("seed");
    let keys = t.path().join("keys");
    let mut bundle = provision(&seed, &keys).unwrap();
    let mut store = Store::open(&t.path().join("data")).unwrap();
    store.attestor = Some(Arc::new(Attestor::new(seed, keys.clone()).unwrap()));
    store.sync_attestor_keys().await.unwrap();
    bundle.keys[0].state = KeyState::Retired;
    std::fs::write(&keys, serde_json::to_vec(&bundle).unwrap()).unwrap();
    store.sync_attestor_keys().await.unwrap();
    assert!(!store.attestor.as_ref().unwrap().ready());
    bundle.keys[0].state = KeyState::Revoked;
    std::fs::write(&keys, serde_json::to_vec(&bundle).unwrap()).unwrap();
    store.sync_attestor_keys().await.unwrap();
    bundle.keys[0].state = KeyState::Active;
    std::fs::write(&keys, serde_json::to_vec(&bundle).unwrap()).unwrap();
    assert!(store.sync_attestor_keys().await.is_err());
    let public = store.public_keys().await.unwrap();
    assert_eq!(public.keys[0].state, KeyState::Revoked);
    let db = Connection::open(t.path().join("data/builds.sqlite3")).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM supply_chain_audit WHERE action='attestor.key_rotated'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}
#[tokio::test]
async fn migration_preserves_previous_records_and_has_separate_attestation_state() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::open(t.path()).unwrap();
    let p = published(&store).await;
    drop(store);
    let store = Store::open(t.path()).unwrap();
    assert_eq!(
        store.publish_record(p.id).await.unwrap().unwrap().status,
        PublishStatus::Succeeded
    );
    assert!(
        store
            .envelope("release", p.id.to_string())
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn reproducibility_history_retains_inconclusive_and_mismatch() {
    let t = tempfile::tempdir().unwrap();
    let store = Store::open(t.path()).unwrap();
    let id = successful(&store).await;
    for state in [
        ReproducibilityState::Inconclusive,
        ReproducibilityState::NonReproducible,
    ] {
        store
            .save_reproducibility(ReproducibilityResult {
                original_build_id: id,
                rebuild_id: None,
                state,
                reason: "test comparison".into(),
                original_content: Some("a".repeat(64)),
                rebuild_content: Some("b".repeat(64)),
                checked_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .latest_reproducibility(id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ReproducibilityState::NonReproducible
    );
    let db = Connection::open(t.path().join("builds.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM reproducibility_attempts", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        2
    );
}
