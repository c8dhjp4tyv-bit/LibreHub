//! M8 backup and restore: an online, application-consistent archive that verifies, rejects
//! tampering, never carries keys, and restores into a clean directory with identities intact.
mod common;
use axum::http::StatusCode;
use common::*;
use librehub_api::backup;
use rusqlite::Connection;
use serde_json::json;
use std::{fs, path::Path};

fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[tokio::test]
async fn an_online_archive_verifies_rejects_tampering_and_restores_identically() {
    let mut env = Env::new().await;
    let root = env.root.path().to_path_buf();
    env.resolver.set(
        "hooks.example.com",
        vec![vec!["93.184.216.34".parse().unwrap()]],
    );
    let project = env.project().await;
    let (status, body) = env
        .call("POST", &format!("/api/v1/projects/{project}/integrations/webhooks"), Some(&env.token), Some(json!({"url":"https://hooks.example.com/librehub","event_types":["automation.started"]})))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let automation = env
        .create_automation(project, json!({"name":"A","triggers":[{"type":"manual"}],"steps":[{"id":"build","uses":"librehub/build"}]}))
        .await;
    let (status, body) = env
        .trigger(
            project,
            automation,
            json!({"idempotency_key":"backup-proof"}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    // Evidence the control plane references, plus material that must never be archived.
    write(&root.join("sources/snapshot.tar"), b"source snapshot");
    write(&root.join("builds/logs/1.txt"), b"build log");
    write(&root.join("artifacts/app.flatpak"), b"bundle bytes");
    write(
        &root.join("publishes/ledger.json"),
        br#"{"publication":"stable"}"#,
    );
    write(
        &root.join("security/sbom.spdx.json"),
        br#"{"spdxVersion":"SPDX-2.3"}"#,
    );
    write(&root.join("repo/objects/ab/cd.commit"), b"ostree commit");
    write(&root.join("keys/attestor-private.pem"), b"PRIVATE");
    write(&root.join("webhook.key"), b"ENCRYPTION KEY");
    write(&root.join("tmp/scratch"), b"temporary");
    let db = env.db();
    let (projects, runs, deliveries) = (
        count(&db, "SELECT count(*) FROM projects"),
        count(&db, "SELECT count(*) FROM automation_runs"),
        count(&db, "SELECT count(*) FROM integration_deliveries"),
    );
    let archive = tempfile::tempdir().unwrap();
    let archive_path = archive.path().join("archive");
    // Taken while the API and its workers keep running.
    let manifest = backup::create(&root, &root.join("builds.sqlite3"), &archive_path).unwrap();
    env.stop().await;
    let listed: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    assert!(listed.contains(&"data/sources/snapshot.tar"));
    assert!(listed.contains(&"data/repo/objects/ab/cd.commit"));
    assert!(
        !listed
            .iter()
            .any(|p| p.contains("keys") || p.contains("webhook.key") || p.contains("tmp"))
    );
    assert!(manifest.excluded.iter().any(|e| e == "keys"));
    assert!(manifest.excluded.iter().any(|e| e == "webhook.key"));
    assert!(!archive_path.join("data/keys").exists());
    assert!(!archive_path.join("data/webhook.key").exists());
    backup::verify(&archive_path).expect("a fresh archive verifies");

    // Tampering with evidence is detected before anything is restored.
    let log = archive_path.join("data/builds/logs/1.txt");
    fs::write(&log, b"altered").unwrap();
    assert!(
        backup::verify(&archive_path).is_err(),
        "modified evidence is rejected"
    );
    fs::write(&log, b"build log").unwrap();
    // Unlisted material is rejected too.
    write(&archive_path.join("data/smuggled.key"), b"KEY");
    assert!(
        backup::verify(&archive_path).is_err(),
        "unlisted files are rejected"
    );
    fs::remove_file(archive_path.join("data/smuggled.key")).unwrap();
    backup::verify(&archive_path).expect("the restored original verifies again");

    // A manifest that names a path outside the archive is rejected.
    let escape = archive.path().join("escape");
    fs::create_dir_all(&escape).unwrap();
    for entry in fs::read_dir(&archive_path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), escape.join(entry.file_name())).unwrap();
        }
    }
    let mut tampered: backup::Manifest =
        serde_json::from_slice(&fs::read(escape.join(backup::MANIFEST)).unwrap()).unwrap();
    tampered.files[0].path = "../outside".into();
    fs::write(
        escape.join(backup::MANIFEST),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    assert!(
        backup::verify(&escape).is_err(),
        "path traversal is rejected"
    );

    // A restore needs an empty target, and produces the same identities and bytes.
    let target = archive.path().join("restored");
    write(&target.join("occupied"), b"x");
    assert!(backup::restore(&archive_path, &target, &target.join("builds.sqlite3")).is_err());
    let target = archive.path().join("clean");
    backup::restore(&archive_path, &target, &target.join("builds.sqlite3")).unwrap();
    let restored = Connection::open(target.join("builds.sqlite3")).unwrap();
    let check: String = restored
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(check, "ok");
    assert_eq!(count(&restored, "SELECT count(*) FROM projects"), projects);
    assert_eq!(
        count(&restored, "SELECT count(*) FROM automation_runs"),
        runs
    );
    assert_eq!(
        count(&restored, "SELECT count(*) FROM integration_deliveries"),
        deliveries
    );
    let project_id: String = restored
        .query_row("SELECT id FROM projects LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(project_id, project.to_string());
    assert_eq!(
        fs::read(target.join("sources/snapshot.tar")).unwrap(),
        b"source snapshot"
    );
    assert_eq!(
        fs::read(target.join("repo/objects/ab/cd.commit")).unwrap(),
        b"ostree commit"
    );
    assert!(
        !target.join("keys").exists(),
        "keys are provisioned, never restored"
    );
    assert!(!target.join("webhook.key").exists());
    drop(restored);
    // The restored directory opens as a store with its records intact.
    let store = librehub_api::store::Store::open(&target).expect("the restored store opens");
    drop(store);
}

#[tokio::test]
async fn writes_during_an_online_backup_still_produce_a_consistent_snapshot() {
    let env = Env::new().await;
    let root = env.root.path().to_path_buf();
    let project = env.project().await.to_string();
    let writer_root = root.clone();
    let writer = std::thread::spawn(move || {
        let db = Connection::open(writer_root.join("builds.sqlite3")).unwrap();
        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        for index in 0..300 {
            db.execute(
                "INSERT INTO event_outbox(event_id,dedupe_key,project_id,event_type,subject_id,data,origin_kind,correlation_id,chain_depth,created_at) VALUES(?1,?2,?3,'load.test','s','{}','system',?1,0,'2026-01-01T00:00:00Z')",
                rusqlite::params![format!("evt-{index}"), format!("dedupe-{index}"), project],
            )
            .unwrap();
        }
    });
    let archive = tempfile::tempdir().unwrap();
    let archive_path = archive.path().join("archive");
    backup::create(&root, &root.join("builds.sqlite3"), &archive_path).unwrap();
    writer.join().unwrap();
    backup::verify(&archive_path).expect("the snapshot is internally consistent");
    let snapshot = Connection::open(archive_path.join("database.sqlite3")).unwrap();
    let rows = count(&snapshot, "SELECT count(*) FROM event_outbox");
    assert!(rows <= 300, "the snapshot is a point-in-time state");
}
