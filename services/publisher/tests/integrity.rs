use librehub_common::*;
use librehub_publisher::{
    PublishError,
    artifact::{source_ref, verify_bundle},
    repository::RepositoryConfig,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn record(id: BuildId) -> BuildRecord {
    serde_json::from_value(json!({"id":id,"status":"succeeded","architecture":Architecture::native(),"created_at":"2026-10-03T00:00:00Z","updated_at":"2026-10-03T00:00:00Z","started_at":null,"finished_at":null,"manifest":{"app_id":"org.librehub.Hello","runtime":"org.freedesktop.Platform","runtime_version":"25.08","sdk":"org.freedesktop.Sdk"},"result":{"exit_code":0,"artifacts":[{"path":format!("builds/{id}/artifacts/application.flatpak"),"size_bytes":5,"sha256":format!("{:x}",Sha256::digest(b"hello"))}]},"error":null,"cancellation_requested":false,"logs_truncated":false})).unwrap()
}
fn fixture() -> (tempfile::TempDir, BuildRecord, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let build = record(BuildId::new());
    let path = dir
        .path()
        .join(&build.result.as_ref().unwrap().artifacts[0].path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"hello").unwrap();
    (dir, build, path)
}
#[test]
fn artifact_hash_size_and_persisted_path_are_revalidated() {
    let (dir, mut build, path) = fixture();
    verify_bundle(dir.path(), &build, None).unwrap();
    std::fs::write(&path, b"jello").unwrap();
    assert!(matches!(
        verify_bundle(dir.path(), &build, None),
        Err(PublishError::Integrity)
    ));
    std::fs::write(&path, b"too long").unwrap();
    assert!(verify_bundle(dir.path(), &build, None).is_err());
    build.result.as_mut().unwrap().artifacts[0].path = "../../etc/passwd".into();
    assert!(matches!(
        verify_bundle(dir.path(), &build, None),
        Err(PublishError::Integrity)
    ));
}
#[cfg(unix)]
#[test]
fn symlink_files_and_parent_directories_are_rejected() {
    use std::os::unix::fs::symlink;
    let (dir, build, path) = fixture();
    std::fs::remove_file(&path).unwrap();
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"hello").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(matches!(
        verify_bundle(dir.path(), &build, None),
        Err(PublishError::Storage)
    ));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
    let target = dir.path().join("pivot");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("application.flatpak"), b"hello").unwrap();
    symlink(target, path.parent().unwrap()).unwrap();
    assert!(matches!(
        verify_bundle(dir.path(), &build, None),
        Err(PublishError::Storage)
    ));
}
#[test]
fn source_build_metadata_architecture_and_state_cannot_be_forged() {
    let (_, mut build, _) = fixture();
    let mut manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    source_ref(&build, &manifest, Architecture::native()).unwrap();
    for state in [BuildStatus::Failed, BuildStatus::Cancelled] {
        build.status = state;
        assert!(matches!(
            source_ref(&build, &manifest, Architecture::native()),
            Err(PublishError::Ineligible)
        ));
    }
    build.status = BuildStatus::Succeeded;
    let unsupported = if Architecture::native() == Architecture::X86_64 {
        Architecture::Aarch64
    } else {
        Architecture::X86_64
    };
    assert!(matches!(
        source_ref(&build, &manifest, unsupported),
        Err(PublishError::Architecture)
    ));
    manifest.app_id = "org.attacker.Other".into();
    assert!(matches!(
        source_ref(&build, &manifest, Architecture::native()),
        Err(PublishError::Metadata)
    ));
}
#[test]
fn public_trust_descriptor_has_no_secret_and_rejects_ini_injection() {
    let mut config = RepositoryConfig {
        public_base_url: "http://localhost:8090".into(),
        public_key: b"public-key".to_vec(),
        fingerprint: "A".repeat(40),
        runtime_repo_url: "https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
    };
    config.validate().unwrap();
    let repo = config.flatpakrepo(RepositoryChannel::Beta);
    assert!(repo.contains("Url=http://localhost:8090/repo/beta/\n"));
    assert!(repo.contains("GPGKey="));
    assert!(!repo.contains("PRIVATE"));
    config.public_base_url.push_str("\nGPGKey=attacker");
    assert!(config.validate().is_err());
}
