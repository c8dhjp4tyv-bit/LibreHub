//! Real smart-HTTPS Git, dynamic CA and commit, no network account.
use librehub_common::*;
use librehub_source::{GitSource, SourceProvider, TestOrigin};
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};
struct Fixture {
    child: std::process::Child,
    _root: tempfile::TempDir,
    provider: GitSource,
    commit: String,
    repo: String,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/source_fixture.py"
            ))
            .args(["--root", root.path().to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(&line).unwrap();
        let provider = GitSource {
            test_origin: Some(TestOrigin {
                repository: config["env"]["LIBREHUB_TEST_SOURCE_REPOSITORY"]
                    .as_str()
                    .unwrap()
                    .into(),
                address: std::net::Ipv4Addr::LOCALHOST,
                port: config["env"]["LIBREHUB_TEST_SOURCE_PORT"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                ca_file: config["env"]["LIBREHUB_TEST_SOURCE_CA_FILE"]
                    .as_str()
                    .unwrap()
                    .into(),
            }),
        };
        Self {
            child,
            _root: root,
            provider,
            commit: config["commit"].as_str().unwrap().into(),
            repo: config["repo"].as_str().unwrap().into(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn source() -> ProjectSource {
    ProjectSource {
        provider: RepositoryProvider::Git,
        url: "https://git.librehub.test/fixture.git".into(),
    }
}
#[tokio::test]
async fn real_https_revision_discovery_snapshot_local_inputs_and_immutable_fetch() {
    let fixture = Fixture::new();
    let commit = fixture
        .provider
        .resolve_revision(&source(), "main")
        .await
        .unwrap();
    assert_eq!(commit, fixture.commit);
    let stage = tempfile::tempdir().unwrap();
    let fetched = fixture
        .provider
        .fetch_source(&source(), &commit, stage.path())
        .await
        .unwrap();
    let prepared = fixture.provider.discover_manifest(&fetched, None).unwrap();
    assert_eq!(prepared.manifest_path, "org.librehub.ProjectHello.json");
    assert_eq!(prepared.snapshot.sha256.len(), 64);
    assert_eq!(prepared.snapshot.file_count, 2);
    assert_eq!(
        prepared.manifest.modules[0].sources[0].options["path"],
        "source/hello.sh"
    );
    let again = fixture.provider.discover_manifest(&fetched, None).unwrap();
    assert_eq!(prepared.snapshot.sha256, again.snapshot.sha256);
    std::fs::write(
        std::path::Path::new(&fixture.repo).join("hello.sh"),
        "changed",
    )
    .unwrap();
    for args in [
        ["add", "."].as_slice(),
        ["commit", "-m", "second"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&fixture.repo)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let old = fixture
        .provider
        .fetch_source(&source(), &commit, stage.path())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .provider
            .discover_manifest(&old, None)
            .unwrap()
            .snapshot
            .sha256,
        prepared.snapshot.sha256
    );
    assert_ne!(
        fixture
            .provider
            .resolve_revision(&source(), "main")
            .await
            .unwrap(),
        commit
    );
}
#[tokio::test]
async fn git_repository_symlink_is_rejected() {
    let fixture = Fixture::new();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/etc/passwd",
        std::path::Path::new(&fixture.repo).join("escape"),
    )
    .unwrap();
    for args in [
        ["add", "."].as_slice(),
        ["commit", "-m", "symlink"].as_slice(),
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&fixture.repo)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let commit = fixture
        .provider
        .resolve_revision(&source(), "main")
        .await
        .unwrap();
    let stage = tempfile::tempdir().unwrap();
    let error = fixture
        .provider
        .fetch_source(&source(), &commit, stage.path())
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "source_special_file");
}
